FROM golang:1.10 as builder
RUN apt-get -y update \
  && apt-get -y install libnetfilter-queue-dev
WORKDIR /go/src/github.com/hownetworks/tracetrout
COPY . .
RUN go build -o /tracetrout -ldflags="-s -w"

FROM debian:stretch-slim
RUN apt-get -y update \
  && apt-get -y install iptables libnetfilter-queue1 \
  && rm -rf /var/lib/apt/lists/*
WORKDIR /go/src/app
COPY entrypoint.sh .
COPY --from=builder /tracetrout .
ENTRYPOINT ["sh", "entrypoint.sh"]
CMD ["./tracetrout"]
