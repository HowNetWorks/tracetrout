FROM golang:1.11-alpine as builder
RUN apk add --no-cache gcc libnetfilter_queue-dev linux-headers musl-dev git
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -mod=readonly -o=/tracetrout -ldflags='-s -w'

FROM alpine:3.8
ARG IPV6_SUPPORT
RUN apk add --no-cache iptables libnetfilter_queue ${IPV6_SUPPORT:+ip6tables}
WORKDIR /tracetrout
COPY entrypoint.sh .
COPY --from=builder /tracetrout .
ENV PORT 8080
ENV FILTER_QUEUE 0
ENTRYPOINT ["sh", "entrypoint.sh"]
CMD ["./tracetrout"]
