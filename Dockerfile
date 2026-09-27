# Multi-stage Docker build for Go IoT Server
FROM golang:1.23-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o iot-server ./cmd/server

FROM alpine:3.20
RUN apk --no-cache add ca-certificates tzdata
WORKDIR /app
COPY --from=builder /app/iot-server .
# 9090 callback (TLS) and 9091 speedtest listen on 10.10.0.2 only; 8000 dashboard API.
EXPOSE 9090 9091 8000
CMD ["./iot-server"]
