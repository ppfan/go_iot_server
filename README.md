# Go IoT Fleet Server

A lightweight, concurrent Go backend designed to manage dozens to hundreds of ESP32 devices communicating inside a WireGuard VPN tunnel.

## Architecture

- **Callback Ingress (Port 9090)**: Receives and verifies HMAC-SHA256 signed telemetry POSTs from ESP32 units.
- **Speedtest Sink (Port 9091)**: Low-overhead raw TCP stream receiver utilizing a `sync.Pool` memory buffer for high-throughput bandwidth benchmarking without memory churn.
- **Dashboard & Fleet API (Port 8000)**: REST API to list registered devices and dispatch authenticated commands (`relay_up`, `speedtest`, `rotate_hmac`, etc.).

## Quick Start

### 1. Run Locally
```bash
cd /home/cyril/esp/iot_server_go
go run ./cmd/server
```

### 2. Build Binary
```bash
go build -o iot-server ./cmd/server
./iot-server
```

### 3. Run with Docker Compose
```bash
docker compose up -d --build
```

## API Endpoints

- `GET /api/devices`: Returns JSON array of all registered ESP32 devices, presence status, and last telemetry snapshots.
- `POST /api/command`: Dispatches an authenticated HMAC-signed command to a specific device.
  ```json
  {
    "target_ip": "10.10.0.2",
    "port": 8443,
    "payload": {
      "relay_up": true
    }
  }
  ```
- `POST /callback`: Endpoint called by ESP32 devices to push telemetry or command responses.
