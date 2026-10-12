# Go IoT Fleet Server — Control Room

Go backend for the ESP32-S3 fleet in `../esp32_wg_http`. It runs **only inside the
WireGuard tunnel** as the Control Room at `10.10.0.2` and replaces the Python
`../esp32_wg_http/pc_server`. Each device has its own HMAC key. See `CLAUDE.md` for the
network plan and wire contracts.

| Port | Bind | Purpose |
|---|---|---|
| 9090 | `10.10.0.2` | HTTPS callback receiver (`POST /callback`), per-device HMAC |
| 9091 | `10.10.0.2` | Raw TCP speedtest (`DOWNLOAD:<s>\n` / `UPLOAD:<s>\n`), fleet IPs only |
| 8000 | `127.0.0.1` on the host | Dashboard REST API, login session + CSRF |

## Status

> **`cmd/server` does not build yet.** The packages moved from `fleet_keys.json` +
> a bearer token to a SQLite store + user logins, but `cmd/server/main.go` still uses
> the old API (`fleet.Load`, `api.Server{Token: …}`). Until it is rewired, the server
> cannot be run; `pc_server` remains the working backend.

Remaining wiring in `main.go`:

- Open the store (`store.Open`) with the master key from `MASTER_KEY_FILE`
  (`store.LoadMasterKey`; 32 bytes hex, file mode `0600`).
- On an empty store, import the legacy registry once (`fleet.ImportJSON`), then build
  the vault with `fleet.New(store)`.
- Create `auth.Manager`, `events.Ring`, and an optional `provision.Config`
  (fleet PSK from `FLEET_WG_PSK_FILE`, relay public key from `RELAY_WG_PUBKEY`).
- A way to create the first admin user (`auth.HashPassword` + `store.CreateUser`).
- Mount the store volume in `docker-compose.yml` and replace `DASHBOARD_TOKEN` in
  `.env.example`.

`web/` is empty: the API is JSON only for now (`api.Server.Static` serves it once it exists).

## Storage

SQLite (`modernc.org/sqlite`, no cgo):

- **devices**: ID, IP, current / previous / pending HMAC key with key IDs, WireGuard
  public key, disabled flag. HMAC keys are AES-256-GCM encrypted with the master key,
  which never goes into the database. Device WireGuard private keys are never stored.
- **users**: argon2id password hashes (min. 12 characters).
- **sessions**: only SHA-256 hashes of session tokens.
- **audit**: who did what to which device (relay, speedtest, rotate, provision, disable).

## API

All endpoints except `/api/health` and `/api/login` need the `cr_session` cookie.
`POST` requests also need `X-CSRF-Token` (returned by login and `/api/session`).
Requests from fleet device IPs are refused. Failed logins are rate limited
(5 per 15 min per IP and per user).

| Method | Path | |
|---|---|---|
| GET | `/api/health` | liveness + tunnel state |
| POST | `/api/login` | `{"username","password"}` (JSON only) → cookie + `csrf` |
| POST | `/api/logout` | |
| GET | `/api/session` | user, CSRF token, whether provisioning is enabled |
| GET | `/api/tunnel` | wg0 handshake state (wgctrl) |
| GET | `/api/devices` | fleet, presence, last telemetry |
| GET | `/api/events` | recent events |
| GET | `/api/audit?limit=N` | audit log (default 50, max 500) |
| GET | `/api/admin/devices` | stored devices (never includes keys) |
| POST | `/api/devices` | provision a device: `{"device_id","ip"}`, both optional |
| POST | `/api/devices/{id}/command` | send an allowlisted command |
| POST | `/api/devices/{id}/rotate-key` | rotate the device HMAC key |
| POST | `/api/devices/{id}/disable` | disable a device |

```bash
B=http://127.0.0.1:8000
CSRF=$(curl -s -c jar -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"…"}' $B/api/login | jq -r .csrf)
curl -b jar $B/api/devices
curl -b jar -H "X-CSRF-Token: $CSRF" -d '{"command":"relay_toggle"}' $B/api/devices/esp32-node-001/command
curl -b jar -H "X-CSRF-Token: $CSRF" -d '{"command":"speedtest","mode":"both","duration":3}' $B/api/devices/esp32-node-001/command
curl -b jar -H "X-CSRF-Token: $CSRF" -X POST $B/api/devices/esp32-node-001/rotate-key
```

Commands: `device_status`, `relay_up`, `relay_down`, `relay_toggle`, `relay_status`,
`speedtest` (`mode` `download|upload|both`, `duration` 1–15). A second command to a
device that is still handling one returns `"busy": true` instead of queueing.

**Key rotation:** the server generates the new key and stores it as pending before
sending it. It commits the key when the device confirms it, or when the device first
signs a callback with it, so a lost acknowledgement is recoverable.

**Provisioning** (Go port of `scripts/generate_device_identity.py`): picks the next
`esp32-node-NNN` and the lowest free IP from `10.10.0.3`, generates the WireGuard
keypair and HMAC key, and returns the NVS CSV, the relay `[Peer]` block and flash
commands. The private key is shown once and not stored. IPs above `.64` get a warning:
the device TLS certificate has no SAN for them.

## Develop

```bash
go vet ./pkg/... && go test -race ./pkg/...
```
