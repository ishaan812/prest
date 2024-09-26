FROM registry.hub.docker.com/library/golang:1.22.2

WORKDIR /workspace
COPY . .
ENV GOOS linux
ENV CGO_ENABLED 1

RUN go mod vendor && \
    go build -ldflags "-s -w" -o prestd cmd/prestd/main.go

ENTRYPOINT ["./prestd"]
