# TraceTrout [![CircleCI](https://circleci.com/gh/HowNetWorks/tracetrout.svg?style=shield)](https://circleci.com/gh/HowNetWorks/tracetrout)

TraceTrout is a HTTP(S) server that returns a reverse traceroute from the server to the client. It does this by piggybacking the established connection, modifying the outgoing TCP packets' TTL values while the server is sending the response.

<img src="trout.jpg">**Figure 1:** A dramatization of [a rainbot trout](https://en.wikipedia.org/wiki/File:Rainbow_trout_transparent.png) swimming against [the data stream](https://pixabay.com/en/background-bits-bit-network-blue-213649/).</img>

## Quickstart

```sh
$ docker run -ti --rm -p 8080:8080 --cap-add NET_ADMIN hownetworks/tracetrout
```

The above Docker image doesn't support IPv6. Use the `hownetworks/tracetrout:ipv6` image if you're feeling adventurous and want to [work with Docker and IPv6](https://docs.docker.com/config/daemon/ipv6/).

Here's a [Docker Compose](https://docs.docker.com/compose/) file for getting you started with the following features:

 * HTTPS enabled
 * Automatic certificates from Let's Encrypt
 * Augmenting trace data with [hownetworks/whereabouts](https://github.com/HowNetWorks/whereabouts)

```yaml
version: "3"

services:
  tracetrout:
    image: hownetworks/tracetrout
    volumes:
      - autocert-cache:/autocert-cache
    environment:
      INFO_URI_TEMPLATE: http://whereabouts:8080/ip/{ip}
      HTTPS_ENABLED: "true"
      HTTPS_AUTOCERT_ENABLED: "true"      
      HTTPS_AUTOCERT_DIR_CACHE: /autocert-cache
      ## Uncomment the following line to limit the automatic cert generation to the given hostname(s)
      # HTTPS_AUTOCERT_HOSTS: tracetrout1.example.com,tracetrout2.example.com      
    ports:
      - "443:8080"
    cap_add:
      - NET_ADMIN

  whereabouts:
    image: hownetworks/whereabouts

volumes:
  autocert-cache: {}
```

## A Less Quick Start

### Prerequisites

The code is designed to run on Linux. Also ensure that `iptables` and `libnetfilter-queue1` packages are installed:

```sh
$ apt-get install iptables libnetfilter-queue1
```

Modify your iptables:

```sh
$ iptables -A OUTPUT -p tcp --sport 8080 -j NFQUEUE --queue-num 0
$ iptables -A INPUT -p tcp --dport 8080 -j NFQUEUE --queue-num 0
$ iptables -A INPUT -p icmp --icmp-type time-exceeded -j NFQUEUE --queue-num 0
```

```sh
$ iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 8080
```

### Compiling

Compilation requires the `libnetfilter-queue-dev` package and Go 1.8 or later.

```sh
$ apt-get install libnetfilter-queue-dev
$ go build
```

### Running

To start listening on port 8080:

```sh
$ ./tracetrout
```

## Prior Art

* https://dankaminsky.com/2002/11/18/77/, the section about `paratrace`.
* https://lwn.net/Articles/217023/
* https://github.com/david415/ParasiticTraceroute
