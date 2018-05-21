FROM golang:1.10-alpine as builder
RUN apk add --no-cache gcc libnetfilter_queue-dev linux-headers musl-dev
WORKDIR /go/src/github.com/hownetworks/tracetrout
COPY . .
RUN go build -o /tracetrout -ldflags='-s -w'

FROM alpine:3.7
RUN apk add --no-cache iptables libnetfilter_queue
WORKDIR /tracetrout
COPY entrypoint.sh .
COPY --from=builder /tracetrout .
ENV PORT 8080
ENV FILTER_QUEUE 0
ENTRYPOINT ["sh", "entrypoint.sh"]
CMD ["./tracetrout"]
