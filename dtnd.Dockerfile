FROM golang:1.22.1-bullseye

RUN apt-get update
RUN apt-get install -y iproute2 iputils-ping

WORKDIR /usr/src/app/bpproxy

COPY go.mod go.sum ./
COPY ./cmd /usr/src/app/bpproxy/cmd
COPY ./pkg /usr/src/app/bpproxy/pkg
RUN go build -v -o bpproxy -ldflags "-s -w" ./cmd/bpproxy

CMD ["./bpproxy"]