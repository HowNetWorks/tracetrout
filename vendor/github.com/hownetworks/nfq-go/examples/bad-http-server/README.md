# Example: A bad HTTP server

This example uses the [github.com/hownetworks/nfq-go](https://github.com/hownetworks/nfq-go) package and Docker to create a HTTP server that drops 10% of TCP packets.

Build the example Docker image:

```sh
docker build -t bad-http-server .
```

Run the image, exposing the bad server on localhost:8080:

```sh
docker run -ti --rm --cap-add NET_ADMIN -p 8080:8080 bad-http-server
```

The `NET_ADMIN` capability needs to be added for the initial iptables commands in [`entrypoint.sh`](./entrypoint.sh).
