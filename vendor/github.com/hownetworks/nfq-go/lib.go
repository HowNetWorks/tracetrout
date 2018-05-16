package nfq

/*
#cgo pkg-config: libnetfilter_queue
#include <netinet/in.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

extern void queueCallback(struct nfq_q_handle *, struct nfgenmsg *, struct nfq_data *, void *);

static inline u_int32_t get_id(struct nfqnl_msg_packet_hdr *ph) {
  return ntohl(ph->packet_id);
}
*/
import "C"
import (
	"errors"
	"sync"
	"syscall"
	"unsafe"
)

const (
	maxPacketSize = 0xffff
)

var (
	registry map[*C.struct_nfq_q_handle]*NFQ
	lock     sync.RWMutex
)

func init() {
	registry = make(map[*C.struct_nfq_q_handle]*NFQ)
}

func register(qh *C.struct_nfq_q_handle, nfq *NFQ) {
	lock.Lock()
	registry[qh] = nfq
	lock.Unlock()
}

func unregister(qh *C.struct_nfq_q_handle) {
	lock.Lock()
	delete(registry, qh)
	lock.Unlock()
}

func get(qh *C.struct_nfq_q_handle) *NFQ {
	lock.RLock()
	nfq := registry[qh]
	lock.RUnlock()
	return nfq
}

// Packet ...
type Packet struct {
	shared *packetShared
	data   []byte
	mark   uint32
}

type packetShared struct {
	nfq *NFQ
	id  uint32
	mx  sync.Mutex
	err error
}

func newPacket(nfq *NFQ, id uint32, mark uint32, data []byte) Packet {
	shared := &packetShared{nfq: nfq, id: id}
	return Packet{shared, data, mark}
}

// Mark ...
func (p Packet) Mark() uint32 {
	return p.mark
}

// Data ...
func (p Packet) Data() []byte {
	return p.data
}

// WithMark ...
func (p Packet) WithMark(mark uint32) Packet {
	p.mark = mark
	return p
}

// WithData ...
func (p Packet) WithData(data []byte) Packet {
	p.data = data
	return p
}

// Accept ...
func (p Packet) Accept() error {
	return p.setVerdict(C.NF_ACCEPT)
}

// Drop ...
func (p Packet) Drop() error {
	return p.setVerdict(C.NF_DROP)
}

// Repeat ...
func (p Packet) Repeat() error {
	return p.setVerdict(C.NF_REPEAT)
}

// Queue ...
func (p Packet) Queue(num uint16) error {
	verdict := (uint32(num) << 16) | C.NF_QUEUE
	return p.setVerdict(verdict)
}

func (p Packet) setVerdict(verdict uint32) error {
	shared := p.shared
	shared.mx.Lock()
	defer shared.mx.Unlock()
	if shared.err != nil {
		return shared.err
	}

	nfq := shared.nfq
	nfq.mx.RLock()
	defer nfq.mx.RUnlock()
	if nfq.closed {
		shared.err = errors.New("queue already closed")
		return shared.err
	}

	var ptr *C.uchar
	if p.data != nil {
		ptr = (*C.uchar)(&p.data[0])
	}
	if C.nfq_set_verdict2(nfq.qh, C.u_int32_t(shared.id), C.u_int32_t(verdict), C.u_int32_t(p.mark), C.u_int32_t(len(p.data)), ptr) < 0 {
		shared.err = errors.New("nfq_set_verdict2() failed")
		return shared.err
	}
	shared.err = errors.New("verdict already set")
	return nil
}

// NFQ ...
type NFQ struct {
	h        *C.struct_nfq_handle
	qh       *C.struct_nfq_q_handle
	wfd      int
	callback func(Packet)

	closed bool
	mx     sync.RWMutex
	wg     sync.WaitGroup
}

// New ...
func New(num uint16, callback func(Packet)) (*NFQ, error) {
	h, err := open()
	if err != nil {
		return nil, err
	}

	qh, err := createQueue(h, num)
	if err != nil {
		C.nfq_close(h)
		return nil, err
	}

	rfd, wfd, err := pipe()
	if err != nil {
		C.nfq_destroy_queue(qh)
		C.nfq_close(h)
		return nil, err
	}

	nfq := &NFQ{h: h, qh: qh, wfd: wfd, callback: callback}
	register(qh, nfq)
	nfq.wg.Add(1)
	go func() {
		defer nfq.wg.Done()
		defer syscall.Close(rfd)
		poll(h, rfd)
	}()

	return nfq, nil
}

// Close ...
func (nfq *NFQ) Close() {
	nfq.mx.Lock()
	closed := nfq.closed
	nfq.closed = true
	nfq.mx.Unlock()

	if !closed {
		unregister(nfq.qh)
		syscall.Close(nfq.wfd)

		nfq.wg.Wait()

		C.nfq_destroy_queue(nfq.qh)
		C.nfq_close(nfq.h)
	}
}

func open() (*C.struct_nfq_handle, error) {
	h := C.nfq_open()
	if h == nil {
		return nil, errors.New("nfq_open() failed")
	}
	return h, nil
}

func createQueue(h *C.struct_nfq_handle, num uint16) (*C.struct_nfq_q_handle, error) {
	qh := C.nfq_create_queue(h, C.u_int16_t(num), (*C.nfq_callback)(C.queueCallback), nil)
	if qh == nil {
		return nil, errors.New("nfq_create_queue() failed")
	}

	if C.nfq_set_mode(qh, C.NFQNL_COPY_PACKET, maxPacketSize) < 0 {
		C.nfq_destroy_queue(qh)
		return nil, errors.New("nfq_set_mode() failed")
	}

	return qh, nil
}

//export queueCallback
func queueCallback(qh *C.struct_nfq_q_handle, _ *C.struct_nfgenmsg, nfad *C.struct_nfq_data, _ unsafe.Pointer) {
	nfq := get(qh)
	if nfq == nil {
		return
	}

	var payload *C.uchar

	size := C.nfq_get_payload(nfad, &payload)
	if size < 0 {
		panic("nfq_get_payload() failed")
	}

	ph := C.nfq_get_msg_packet_hdr(nfad)
	if ph == nil {
		panic("nfq_get_msg_packet_hdr() failed")
	}

	id := uint32(C.get_id(ph))
	mark := uint32(C.nfq_get_nfmark(nfad))
	data := C.GoBytes(unsafe.Pointer(payload), size)
	packet := newPacket(nfq, id, mark, data)
	nfq.callback(packet)
}

func pipe() (int, int, error) {
	pipe := make([]int, 2)
	if err := syscall.Pipe(pipe); err != nil {
		return 0, 0, err
	}
	return pipe[0], pipe[1], nil
}

func poll(h *C.struct_nfq_handle, rfd int) error {
	buf := make([]byte, maxPacketSize)
	fd := int(C.nfq_fd(h))

	epfd, err := syscall.EpollCreate1(0)
	if err != nil {
		return err
	}
	defer syscall.Close(epfd)

	err = syscall.EpollCtl(epfd, syscall.EPOLL_CTL_ADD, rfd, &syscall.EpollEvent{Events: syscall.EPOLLIN, Fd: int32(rfd)})
	if err != nil {
		return err
	}
	err = syscall.EpollCtl(epfd, syscall.EPOLL_CTL_ADD, fd, &syscall.EpollEvent{Events: syscall.EPOLLIN, Fd: int32(fd)})
	if err != nil {
		return err
	}

	events := make([]syscall.EpollEvent, 2)
	for {
		n, err := syscall.EpollWait(epfd, events, -1)
		if err != nil {
			return err
		}

		for _, ev := range events[:n] {
			if ev.Fd == int32(rfd) {
				return nil
			}

			if ev.Fd == int32(fd) {
				rv, _, err := syscall.Recvfrom(fd, buf, 0)
				if err != nil {
					return err
				}

				ptr := (*C.char)(unsafe.Pointer(&buf[0]))
				if C.nfq_handle_packet(h, ptr, C.int(rv)) != 0 {
					return errors.New("nfq_handle_packet() failed")
				}
			}
		}
	}
}
