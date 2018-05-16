# nfq-go

nfq-go is a Go library that wraps [`libnetfilter_queue`](https://www.netfilter.org/projects/libnetfilter_queue/). It aims to: 
 * contain a minimal amount of C code
 * be thread-safe (including closing the queue handler)

## Usage

### Import

```go
import nfq "github.com/hownetworks/nfq-go"
```

### Create a New Queue Handle

To creaate a new queue handle call `New` with the queue number (`0` in the following example) and a callback for receiving packets:

```go
queue, err := nfq.New(0, func(pkt nfq.Packet) {
  ...
})
```

### Give a Verdict

You should give every packet a verdict. Do this by calling one of the methods outlined below. Note that giving a verdict more than once for a single packet produces an error.

Let the packet pass the filter with a `NF_ACCEPT` verdict:

```go
err := pkt.Accept()
```

Drop the packet with `NF_DROP`:

```go
err := pkt.Drop()
```

Pass the packet through the filter again with `NF_REPEAT`:

```go
err := pkt.Repeat()
```

Send the packet to some (other) queue with `NF_QUEUE` - this also requires the queue number:

```go
err := pkt.Queue(5)
```

### Modifying Packets

Use `WithData(data []byte)` and `WithMark(mark uint32)` to modify the packet's data and mark. Instead of modifying the original these methods return a new `Packet` and can be chained.

As an example, here's how to (re)queue the packet to queue number 5, this time its data set to `newData` and mark set to `1234`:

```go
err := pkt.WithData(newData).WithMark(1234).Queue(5)
```

### Close

At any point you can close the queue handle:

```go
queue.Close()
```
