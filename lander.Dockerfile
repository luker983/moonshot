FROM golang:1.22.1-bullseye AS builder

WORKDIR /app

COPY go.mod go.sum ./
COPY ./cmd /app/cmd
RUN go build -v -o service -ldflags "-s -w" ./cmd/lander

COPY ./site ./site

CMD ["/app/service"]
