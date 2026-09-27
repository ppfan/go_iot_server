# Go IoT Fleet Server — Control Room

Go backend for the ESP32-S3 fleet in `../esp32_wg_http`. It runs **only inside the
WireGuard tunnel** as the Control Room at `10.10.0.2`. Each device has its own HMAC
key from `fleet_keys.json`. See `CLAUDE.md` for the network plan and wire contracts.

| Port | Bind | Purpose |
|---|---|---|
| 9090 | `10.10.0.2` | HTTPS callback receiver (`POST /callback`), per-device HMAC |
| 9091 | `10.10.0.2` | Raw TCP speedtest (`DOWNLOAD:<s>\n` / `UPLOAD:<s>\n`), fleet IPs only |
| 8000 | `127.0.0.1` on the host | Dashboard REST API, bearer token |

## Run with Docker Compose (WireGuard + server)

```bash
cp .env.example .env && sed -i "s/^DASHBOARD_TOKEN=.*/DASHBOARD_TOKEN=$(openssl rand -hex 32)/" .env
# The Python stack uses the same WireGuard identity and port 8000:
(cd ../esp32_wg_http/pc_server && docker compose down)
docker compose up -d --build
```

By default the compose file reuses `../esp32_wg_http/pc_server/{wireguard,certs,fleet_keys.json}`.
Override with `WG_CONFIG_DIR`, `CERTS_DIR` and `FLEET_KEYS`. Restart the server after
provisioning a new device with `scripts/generate_device_identity.py`.

## API

All endpoints except `/api/health` need `Authorization: Bearer $DASHBOARD_TOKEN`.
Requests from fleet device IPs are refused.

```bash
T="Authorization: Bearer $DASHBOARD_TOKEN"
curl -H "$T" localhost:8000/api/devices                 # fleet, presence, last telemetry
curl -H "$T" localhost:8000/api/tunnel                  # wg0 handshake state
curl -H "$T" -d '{"command":"relay_toggle"}' localhost:8000/api/devices/esp32-node-001/command
curl -H "$T" -d '{"command":"speedtest","mode":"both","duration":3}' localhost:8000/api/devices/esp32-node-001/command
curl -H "$T" -X POST localhost:8000/api/devices/esp32-node-001/rotate-key
```

Commands: `device_status`, `relay_up`, `relay_down`, `relay_toggle`, `relay_status`,
`speedtest`. The server generates rotated keys. It commits a new key when the device
confirms it, or when the device first signs a callback with it.

## Develop

```bash
go vet ./... && go test -race ./...
```
