FROM golang:1.10
RUN apt-get -y update \
  && apt-get -y install iptables libnetfilter-queue-dev
WORKDIR /go/src/app
COPY . .
RUN go get -d -v ./...
RUN go install -v ./...
ENTRYPOINT ["sh", "entrypoint.sh"]
CMD ["app"]
