package main

import (
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/tcpassembly"
	"github.com/gorilla/handlers"
	nfq "github.com/hownetworks/nfq-go"
	"github.com/kelseyhightower/envconfig"
	"github.com/rs/cors"
)

var (
	ErrCanceled     = errors.New("canceled")
	ErrStreamClosed = errors.New("stream closed")
)

func less(a, b tcpassembly.Sequence) bool {
	return b.Difference(a) < 0
}

func lessOrEqual(a, b tcpassembly.Sequence) bool {
	return b.Difference(a) <= 0
}

type StreamID struct {
	remoteIP   gopacket.Endpoint
	remotePort gopacket.Endpoint
}

func StreamIDFromHostPort(hostPort string) (StreamID, error) {
	ipStr, portStr, err := net.SplitHostPort(hostPort)
	if err != nil {
		return StreamID{}, err
	}

	ip := net.ParseIP(ipStr)
	if strings.ContainsRune(ipStr, ':') {
		ip = ip.To16()
	} else {
		ip = ip.To4()
	}
	if ip == nil {
		return StreamID{}, errors.New("could not parse the address")
	}

	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return StreamID{}, err
	}

	id := StreamID{layers.NewIPEndpoint(ip), layers.NewTCPPortEndpoint(layers.TCPPort(port))}
	return id, nil
}

func (id StreamID) String() string {
	return net.JoinHostPort(id.remoteIP.String(), id.remotePort.String())
}

type IPLayer interface {
	gopacket.NetworkLayer
	gopacket.SerializableLayer
}

type Stream struct {
	mx      sync.Mutex
	seq     tcpassembly.Sequence
	active  map[tcpassembly.Sequence]*Claim
	pending []*Claim
	closed  bool
}

func (s *Stream) close() {
	s.mx.Lock()
	defer s.mx.Unlock()

	for _, claim := range s.pending {
		claim.set(&Result{TTL: claim.ttl, Err: ErrStreamClosed}, true)
	}
	s.pending = nil

	for _, claim := range s.active {
		claim.set(&Result{TTL: claim.ttl, Err: ErrStreamClosed}, true)
	}
	s.active = nil

	s.closed = true
}

func (s *Stream) Trace(ttl byte, timeout time.Duration, action func() error) *Claim {
	claim := &Claim{
		ttl:     ttl,
		timeout: timeout,
		done:    make(chan struct{}),
		action:  action,
		stream:  s,
	}

	func() {
		s.mx.Lock()
		defer s.mx.Unlock()

		if s.closed {
			claim.set(&Result{TTL: claim.ttl, Err: ErrStreamClosed}, true)
			return
		}

		if len(s.pending) == 0 {
			if err := action(); err != nil {
				claim.set(&Result{TTL: ttl, Err: err}, true)
				return
			}
		}
		s.pending = append(s.pending, claim)
	}()

	return claim
}

func (s *Stream) icmpReceived(src net.IP, seq uint32) error {
	s.mx.Lock()
	defer s.mx.Unlock()

	claimSeq := tcpassembly.Sequence(seq)
	if claim := s.active[claimSeq]; claim != nil {
		claim.set(&Result{TTL: claim.ttl, IP: src}, false)
	}
	return nil
}

func (s *Stream) tcpReceived(src net.IP, tcp *layers.TCP) error {
	s.mx.Lock()
	defer s.mx.Unlock()

	if !tcp.ACK {
		return nil
	}

	ack := tcpassembly.Sequence(tcp.Ack)
	for claimSeq, claim := range s.active {
		if lessOrEqual(ack, claimSeq) {
			continue
		}
		delete(s.active, claimSeq)
		claim.set(&Result{TTL: claim.ttl, IP: src}, true)
	}
	return nil
}

func (s *Stream) tcpSent(pkt nfq.Packet, ip IPLayer, tcp *layers.TCP) error {
	s.mx.Lock()
	defer s.mx.Unlock()

	size := len(tcp.Payload)
	if size == 0 {
		return pkt.Accept()
	}

	current := s.seq
	start := tcpassembly.Sequence(tcp.Seq)
	end := start.Add(size)
	if less(current, end) {
		s.seq = end
	}

	// Does the [start, end[ range overlap any active claims that do not have a result?
	for claimSeq, claim := range s.active {
		if claim.result == nil && lessOrEqual(start, claimSeq) && less(claimSeq, end) {
			return pkt.Drop()
		}
	}

	// Only claim the first bytes of packets.
	if less(start, current) {
		return pkt.Accept()
	}
	if len(s.pending) == 0 {
		return pkt.Accept()
	}
	claim := s.pending[0]

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{ComputeChecksums: true}

	switch ip := ip.(type) {
	case *layers.IPv4:
		ip.TTL = claim.ttl
	case *layers.IPv6:
		ip.HopLimit = claim.ttl
	default:
		panic("not a IPv4/6 layer")
	}
	tcp.SetNetworkLayerForChecksum(ip)
	if err := gopacket.SerializeLayers(buf, opts, ip, tcp, gopacket.Payload(tcp.Payload)); err != nil {
		return err
	}
	if err := pkt.WithData(buf.Bytes()).Accept(); err != nil {
		return err
	}

	s.pending = s.pending[1:]
	for len(s.pending) > 0 {
		other := s.pending[0]
		err := other.action()
		if err == nil {
			break
		}
		other.set(&Result{TTL: claim.ttl, Err: err}, true)
		s.pending = s.pending[1:]
	}

	claim.seq = start
	s.active[start] = claim
	claim.start()
	return nil
}

type Claim struct {
	ttl     byte
	timeout time.Duration
	action  func() error
	done    chan struct{}

	seq    tcpassembly.Sequence
	timer  *time.Timer
	result *Result
	closed bool
	stream *Stream
}

func (c *Claim) Cancel() {
	s := c.stream

	s.mx.Lock()
	defer s.mx.Unlock()

	index := 0
	for _, other := range s.pending {
		if c != other {
			s.pending[index] = other
			index++
		}
	}
	s.pending = s.pending[:index]

	if other := s.active[c.seq]; other == c {
		delete(s.active, c.seq)
	}

	c.set(&Result{TTL: c.ttl, Err: ErrCanceled}, true)
}

func (c *Claim) Done() <-chan struct{} {
	return c.done
}

func (c *Claim) Result() *Result {
	select {
	case <-c.done:
		return c.result
	default:
		return nil
	}
}

func (c *Claim) start() {
	c.timer = time.AfterFunc(c.timeout, func() {
		s := c.stream

		s.mx.Lock()
		defer s.mx.Unlock()

		c.timer = nil
		c.set(&Result{TTL: c.ttl, Timeout: true}, false)
	})
}

func (c *Claim) set(result *Result, closed bool) {
	if c.timer != nil {
		c.timer.Stop()
		c.timer = nil
	}
	if c.result == nil {
		c.result = result
	}
	if closed && !c.closed {
		c.closed = true
		close(c.done)
	}
}

type Result struct {
	TTL     byte
	IP      net.IP
	Err     error
	Timeout bool
}

type StreamTracker struct {
	mx      sync.RWMutex
	streams map[StreamID]*Stream
}

func NewStreamTracker() *StreamTracker {
	streams := make(map[StreamID]*Stream)
	return &StreamTracker{streams: streams}
}

func (st *StreamTracker) HandlePacket(pkt nfq.Packet) error {
	data := pkt.Data()
	if len(data) == 0 {
		return pkt.Accept()
	}

	version := data[0] >> 4
	if version == 4 {
		p := gopacket.NewPacket(data, layers.LayerTypeIPv4, gopacket.Lazy)
		if ip, ok := p.NetworkLayer().(*layers.IPv4); ok {
			return st.handleIPv4(pkt, p, ip)
		}
	}
	if version == 6 {
		p := gopacket.NewPacket(data, layers.LayerTypeIPv6, gopacket.Lazy)
		if ip, ok := p.NetworkLayer().(*layers.IPv6); ok {
			return st.handleIPv6(pkt, p, ip)
		}
	}
	return pkt.Accept()
}

func (st *StreamTracker) handleIPv4(pkt nfq.Packet, p gopacket.Packet, ip *layers.IPv4) error {
	if icmp, ok := p.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4); ok {
		return st.handleICMPv4(pkt, ip.SrcIP, icmp)
	}
	if tcp, ok := p.TransportLayer().(*layers.TCP); ok {
		return st.handleTCP(pkt, ip, ip.SrcIP, tcp)
	}
	return pkt.Accept()
}

func (st *StreamTracker) handleIPv6(pkt nfq.Packet, p gopacket.Packet, ip *layers.IPv6) error {
	if icmp, ok := p.Layer(layers.LayerTypeICMPv6).(*layers.ICMPv6); ok {
		return st.handleICMPv6(pkt, ip.SrcIP, icmp)
	}
	if tcp, ok := p.TransportLayer().(*layers.TCP); ok {
		return st.handleTCP(pkt, ip, ip.SrcIP, tcp)
	}
	return pkt.Accept()
}

func (st *StreamTracker) handleICMPv4(pkt nfq.Packet, srcIP net.IP, icmp *layers.ICMPv4) error {
	defer pkt.Accept()

	if icmp.TypeCode.Type() != layers.ICMPv4TypeTimeExceeded {
		return nil
	}

	p := gopacket.NewPacket(icmp.Payload, layers.LayerTypeIPv4, gopacket.Lazy)
	ip, ok := p.NetworkLayer().(*layers.IPv4)
	if !ok || ip.Protocol != layers.IPProtocolTCP || len(ip.Payload) < 8 {
		return nil
	}

	dstPort := layers.TCPPort(binary.BigEndian.Uint16(ip.Payload[2:4]))
	seq := binary.BigEndian.Uint32(ip.Payload[4:8])
	id := StreamID{ip.NetworkFlow().Dst(), layers.NewTCPPortEndpoint(dstPort)}

	stream := st.Get(id)
	if stream != nil {
		return stream.icmpReceived(srcIP, seq)
	}
	return nil
}

func (st *StreamTracker) handleICMPv6(pkt nfq.Packet, srcIP net.IP, icmp *layers.ICMPv6) error {
	defer pkt.Accept()

	if icmp.TypeCode.Type() != layers.ICMPv6TypeTimeExceeded {
		return nil
	}

	p := gopacket.NewPacket(icmp.Payload, layers.LayerTypeIPv6, gopacket.Lazy)
	ip, ok := p.NetworkLayer().(*layers.IPv6)
	if !ok || ip.NextHeader != layers.IPProtocolTCP || len(ip.Payload) < 8 {
		return nil
	}

	dstPort := layers.TCPPort(binary.BigEndian.Uint16(ip.Payload[2:4]))
	seq := binary.BigEndian.Uint32(ip.Payload[4:8])
	id := StreamID{ip.NetworkFlow().Dst(), layers.NewTCPPortEndpoint(dstPort)}

	stream := st.Get(id)
	if stream != nil {
		return stream.icmpReceived(srcIP, seq)
	}
	return nil
}

func (st *StreamTracker) handleTCP(pkt nfq.Packet, ip IPLayer, srcIP net.IP, tcp *layers.TCP) error {
	srcID := StreamID{ip.NetworkFlow().Src(), tcp.TransportFlow().Src()}
	dstID := StreamID{ip.NetworkFlow().Dst(), tcp.TransportFlow().Dst()}

	if tcp.RST || tcp.FIN {
		var dst, src *Stream

		st.mx.Lock()
		dst = st.streams[dstID]
		src = st.streams[srcID]
		delete(st.streams, dstID)
		delete(st.streams, srcID)
		st.mx.Unlock()

		if dst != nil {
			dst.close()
		}
		if src != nil {
			src.close()
		}
	}

	if tcp.SYN && tcp.ACK {
		st.mx.Lock()
		st.streams[dstID] = &Stream{
			seq:    tcpassembly.Sequence(tcp.Seq).Add(1),
			active: make(map[tcpassembly.Sequence]*Claim),
		}
		st.mx.Unlock()
	}

	if src := st.Get(srcID); src != nil {
		if err := src.tcpReceived(srcIP, tcp); err != nil {
			pkt.Accept()
			return err
		}
	}

	dst := st.Get(dstID)
	if dst == nil {
		return pkt.Accept()
	}

	return dst.tcpSent(pkt, ip, tcp)
}

func (st *StreamTracker) Get(id StreamID) *Stream {
	st.mx.RLock()
	stream := st.streams[id]
	st.mx.RUnlock()
	return stream
}

type settings struct {
	Host          string
	Port          uint16        `default:"8080"`
	HopTimeout    time.Duration `default:"1s" split_words:"true"`
	HopRetries    uint          `default:"5" split_words:"true"`
	HopOffset     byte          `default:"0" split_words:"true"`
	FilterQueue   uint16        `default:"0" split_words:"true"`
	HTTPSEnabled  bool          `default:"false" envconfig:"HTTPS_ENABLED"`
	HTTPSCertFile string        `default:"" envconfig:"HTTPS_CERT_FILE"`
	HTTPSKeyFile  string        `default:"" envconfig:"HTTPS_KEY_FILE"`
}

func (s settings) HostPort() string {
	return net.JoinHostPort(s.Host, strconv.FormatUint(uint64(s.Port), 10))
}

func ipFromHostPort(s string) (net.IP, error) {
	host, _, err := net.SplitHostPort(s)
	if err != nil {
		return nil, err
	}

	ip := net.ParseIP(host)
	if ip4 := ip.To4(); ip4 != nil {
		return ip4, nil
	}
	if ip16 := ip.To16(); ip16 != nil {
		return ip16, nil
	}
	return nil, errors.New("not a valid IP address")
}

func main() {
	var s settings
	if err := envconfig.Process("", &s); err != nil {
		log.Fatal(err)
	}
	if s.HTTPSEnabled && (s.HTTPSCertFile == "" || s.HTTPSKeyFile == "") {
		log.Fatal("HTTPS_ENABLED=true requires HTTPS_CERT_FILE and HTTPS_KEY_FILE")
	}
	if !s.HTTPSEnabled && (s.HTTPSCertFile != "" || s.HTTPSKeyFile != "") {
		log.Fatal("HTTPS_CERT_FILE and HTTPS_KEY_FILE require HTTPS_ENABLED=true")
	}

	tracker := NewStreamTracker()
	queue, err := nfq.New(s.FilterQueue, func(pkt nfq.Packet) {
		if err := tracker.HandlePacket(pkt); err != nil {
			panic(err)
		}
	})
	if err != nil {
		log.Fatal(err)
	}
	defer queue.Close()

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}

		id, err := StreamIDFromHostPort(r.RemoteAddr)
		if err != nil {
			log.Panic(err)
		}

		ip, err := ipFromHostPort(r.RemoteAddr)
		if err != nil {
			log.Panic(err)
		}

		// https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control#Preventing_caching
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		writeAndFlush(w, "[")

		stream := tracker.Get(id)
		if stream == nil {
			log.Panic("no valid stream found")
		}

		var claim *Claim
		defer func() {
			if claim != nil {
				claim.Cancel()
			}
		}()

		for ttl := 1 + int(s.HopOffset); ttl < 256; ttl++ {
			var result *Result

			for retries := uint(0); retries <= s.HopRetries; retries++ {
				claim = stream.Trace(byte(ttl), s.HopTimeout, func() error {
					return writeAndFlush(w, " ")
				})

				select {
				case <-r.Context().Done():
					return
				case <-claim.Done():
				}

				result = claim.Result()
				if !result.Timeout {
					break
				}
			}

			if result.Err == ErrStreamClosed {
				return
			}
			if result.Err != nil {
				log.Panic(result.Err)
			}

			var obj object
			var goal bool
			if result.Timeout {
				obj = object{"ttl": result.TTL - s.HopOffset, "timeout": true}
			} else {
				obj = object{"ttl": result.TTL - s.HopOffset, "ip": result.IP}
				goal = result.IP.Equal(ip)
			}

			if err := write(w, "\n  "); err != nil {
				log.Panic(err)
			}
			if err := writeJSON(w, obj); err != nil {
				log.Panic(err)
			}
			if !goal {
				if err := writeAndFlush(w, ","); err != nil {
					log.Panic(err)
				}
			}
			if goal {
				break
			}
		}

		if err := writeAndFlush(w, "\n]\n"); err != nil {
			log.Panic(err)
		}
	})

	fmt.Printf("Serving on %v...\n", s.HostPort())
	server := http.Server{
		Addr:         s.HostPort(),
		Handler:      handlers.CombinedLoggingHandler(os.Stdout, cors.Default().Handler(http.DefaultServeMux)),
		TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){},
	}
	server.SetKeepAlivesEnabled(false)
	if s.HTTPSEnabled {
		log.Fatal(server.ListenAndServeTLS(s.HTTPSCertFile, s.HTTPSKeyFile))
	} else {
		log.Fatal(server.ListenAndServe())
	}
}

func write(w io.Writer, s string) error {
	_, err := w.Write([]byte(s))
	return err
}

func writeAndFlush(w io.Writer, s string) error {
	if err := write(w, s); err != nil {
		return err
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		return errors.New("couldn't flush")
	}
	flusher.Flush()
	return nil
}

type object map[string]interface{}

func writeJSON(writer io.Writer, obj interface{}) error {
	data, err := json.Marshal(obj)
	if err != nil {
		return err
	}
	_, err = writer.Write(data)
	return err
}
