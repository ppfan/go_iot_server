// Package api serves the Control Room web page and its JSON API on :8000.
package api

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"time"

	"iot_server_go/pkg/auth"
	"iot_server_go/pkg/devices"
	"iot_server_go/pkg/events"
	"iot_server_go/pkg/fleet"
	"iot_server_go/pkg/provision"
	"iot_server_go/pkg/store"
	"iot_server_go/pkg/wghealth"
)

const sessionCookie = "cr_session"

type Server struct {
	Vault        *fleet.Vault
	Store        *store.Store
	Auth         *auth.Manager
	Registry     *devices.Registry
	Client       *devices.Client
	Tunnel       *wghealth.Monitor
	Events       *events.Ring
	Provision    *provision.Config // nil disables adding devices
	CookieSecure bool
	Static       fs.FS // web page assets; nil serves the API only
}

type ctxKey struct{}

func sessionFrom(r *http.Request) store.Session {
	s, _ := r.Context().Value(ctxKey{}).(store.Session)
	return s
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]any{"ok": false, "error": msg})
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /api/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"status": "online", "tunnel_up": s.Tunnel.Status().Up, "time": time.Now().UTC()})
	})
	mux.HandleFunc("POST /api/login", s.login)
	mux.Handle("POST /api/logout", s.authed(s.logout))
	mux.Handle("GET /api/session", s.authed(func(w http.ResponseWriter, r *http.Request) {
		sess := sessionFrom(r)
		writeJSON(w, 200, map[string]any{"user": sess.UserName, "csrf": sess.CSRF, "expires_at": sess.ExpiresAt,
			"provisioning": s.Provision != nil})
	}))
	mux.Handle("GET /api/tunnel", s.authed(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, s.Tunnel.Status())
	}))
	mux.Handle("GET /api/devices", s.authed(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, s.Registry.List())
	}))
	mux.Handle("GET /api/events", s.authed(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, s.Events.List())
	}))
	mux.Handle("GET /api/audit", s.authed(s.audit))
	mux.Handle("GET /api/admin/devices", s.authed(s.adminDevices))
	mux.Handle("POST /api/devices", s.authed(s.addDevice))
	mux.Handle("POST /api/devices/{id}/command", s.authed(s.command))
	mux.Handle("POST /api/devices/{id}/rotate-key", s.authed(s.rotate))
	mux.Handle("POST /api/devices/{id}/disable", s.authed(s.disable))
	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) { writeErr(w, 404, "not found") })

	if s.Static != nil {
		mux.Handle("GET /", http.FileServerFS(s.Static))
	}
	return securityHeaders(s.rejectDevices(mux))
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		// index.html uses inline style attributes; scripts are external only.
		h.Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}

// rejectDevices blocks fleet devices from the dashboard: they only ever need
// :9090 and :9091.
func (s *Server) rejectDevices(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ip, err := netip.ParseAddr(clientIP(r)); err == nil && s.Vault.IsDeviceIP(ip) {
			writeErr(w, http.StatusForbidden, "forbidden")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// authed requires a live session; state-changing methods also need the
// session's CSRF token in X-CSRF-Token.
func (s *Server) authed(h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(sessionCookie)
		if err != nil {
			writeErr(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		sess, err := s.Auth.Session(r.Context(), c.Value)
		if err != nil {
			if !errors.Is(err, auth.ErrNoSession) {
				log.Printf("[api] session lookup: %v", err)
			}
			writeErr(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-CSRF-Token")), []byte(sess.CSRF)) != 1 {
				writeErr(w, http.StatusForbidden, "missing or invalid CSRF token, reload the page")
				return
			}
		}
		h(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, sess)))
	})
}

func decode(w http.ResponseWriter, r *http.Request, v any, limit int64) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, limit))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return false
	}
	return true
}

func (s *Server) setSessionCookie(w http.ResponseWriter, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    value,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   s.CookieSecure,
		SameSite: http.SameSiteStrictMode,
	})
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	// JSON only: a cross-site HTML form cannot send this content type.
	if r.Header.Get("Content-Type") != "application/json" {
		writeErr(w, http.StatusUnsupportedMediaType, "expected application/json")
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !decode(w, r, &req, 1024) {
		return
	}
	token, csrf, err := s.Auth.Login(r.Context(), req.Username, req.Password, clientIP(r))
	switch {
	case errors.Is(err, auth.ErrRateLimited):
		log.Printf("[auth] rate limited login for %q from %s", req.Username, clientIP(r))
		writeErr(w, http.StatusTooManyRequests, err.Error())
		return
	case errors.Is(err, auth.ErrBadCredentials):
		log.Printf("[auth] failed login for %q from %s", req.Username, clientIP(r))
		writeErr(w, http.StatusUnauthorized, err.Error())
		return
	case err != nil:
		log.Printf("[auth] login error: %v", err)
		writeErr(w, http.StatusInternalServerError, "login failed")
		return
	}
	log.Printf("[auth] %q logged in from %s", req.Username, clientIP(r))
	s.setSessionCookie(w, token, int(s.Auth.TTL.Seconds()))
	writeJSON(w, 200, map[string]any{"ok": true, "user": req.Username, "csrf": csrf})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		s.Auth.Logout(r.Context(), c.Value)
	}
	s.setSessionCookie(w, "", -1)
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) auditLog(r *http.Request, deviceID, action, result string) {
	err := s.Store.AddAudit(context.WithoutCancel(r.Context()), store.AuditEntry{
		User: sessionFrom(r).UserName, DeviceID: deviceID, Action: action, Result: result,
	})
	if err != nil {
		log.Printf("[audit] %v", err)
	}
}

func (s *Server) audit(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 || limit > 500 {
		limit = 50
	}
	entries, err := s.Store.ListAudit(r.Context(), limit)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if entries == nil {
		entries = []store.AuditEntry{}
	}
	writeJSON(w, 200, entries)
}

// commandResult is the shape app.js reads (same as the Python dashboard).
type commandResult struct {
	OK         bool            `json:"ok"`
	HTTPStatus int             `json:"http_status,omitempty"`
	ElapsedMS  int64           `json:"elapsed_ms,omitempty"`
	Body       json.RawMessage `json:"body,omitempty"`
	Error      string          `json:"error,omitempty"`
	Busy       bool            `json:"busy,omitempty"`
}

// Commands that change device state are written to the audit log.
var auditedCommands = map[string]bool{"relay_up": true, "relay_down": true, "relay_toggle": true, "speedtest": true}

func (s *Server) command(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, ok := s.Vault.Get(id); !ok {
		writeErr(w, http.StatusNotFound, "unknown device")
		return
	}
	var cmd devices.Command
	if !decode(w, r, &cmd, 1024) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
	defer cancel()
	res, err := s.Client.Send(ctx, id, cmd)

	out := commandResult{OK: err == nil}
	if res != nil {
		out.HTTPStatus, out.ElapsedMS, out.Body = res.Status, res.Elapsed.Milliseconds(), res.Body
	}
	switch {
	case errors.Is(err, devices.ErrInvalidCommand):
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	case errors.Is(err, devices.ErrBusy):
		out.Busy, out.HTTPStatus, out.Error = true, http.StatusTooManyRequests, err.Error()
	case err != nil:
		out.Error = err.Error()
		log.Printf("[api] %s %s: %v", id, cmd.Name, err)
	}
	if auditedCommands[cmd.Name] && !out.Busy {
		result := "ok"
		if !out.OK {
			result = out.Error
		}
		s.auditLog(r, id, cmd.Name, result)
	}
	// Device-level failures are reported in the body, like the Python dashboard.
	writeJSON(w, 200, out)
}

func (s *Server) rotate(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, ok := s.Vault.Get(id); !ok {
		writeErr(w, http.StatusNotFound, "unknown device")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	keyID, err := s.Client.RotateKey(ctx, id)
	if err != nil {
		log.Printf("[api] %s rotate-key %s: %v", id, keyID, err)
		s.auditLog(r, id, "rotate_key", "pending "+keyID+": "+err.Error())
		writeJSON(w, http.StatusBadGateway, map[string]any{"ok": false, "key_id": keyID, "error": err.Error(), "pending": keyID != ""})
		return
	}
	log.Printf("[api] %s rotated to key_id %s", id, keyID)
	s.auditLog(r, id, "rotate_key", "ok "+keyID)
	writeJSON(w, 200, map[string]any{"ok": true, "key_id": keyID})
}

func (s *Server) disable(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, ok := s.Vault.Get(id); !ok {
		writeErr(w, http.StatusNotFound, "unknown or already disabled device")
		return
	}
	if err := s.Vault.DisableDevice(r.Context(), id); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	log.Printf("[api] %s disabled by %s", id, sessionFrom(r).UserName)
	s.auditLog(r, id, "disable", "ok")
	writeJSON(w, 200, map[string]any{"ok": true})
}

// adminDevice is the admin view of a stored device. It never includes keys.
type adminDevice struct {
	ID              string    `json:"id"`
	IP              string    `json:"ip"`
	KeyID           string    `json:"key_id"`
	RotationPending bool      `json:"rotation_pending"`
	WGPubKey        string    `json:"wg_pubkey"`
	CreatedAt       time.Time `json:"created_at"`
	Disabled        bool      `json:"disabled"`
}

func (s *Server) adminDevices(w http.ResponseWriter, r *http.Request) {
	rows, err := s.Store.ListDevices(r.Context())
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	out := make([]adminDevice, 0, len(rows))
	for _, d := range rows {
		out = append(out, adminDevice{ID: d.ID, IP: d.IP, KeyID: d.KeyID, RotationPending: d.PendingHMAC != "",
			WGPubKey: d.WGPubKey, CreatedAt: d.CreatedAt, Disabled: d.Disabled})
	}
	writeJSON(w, 200, out)
}

// addDevice creates a device identity. The response carries the device's
// WireGuard private key inside the NVS CSV; it is shown once and not stored.
func (s *Server) addDevice(w http.ResponseWriter, r *http.Request) {
	if s.Provision == nil {
		writeErr(w, http.StatusServiceUnavailable, "provisioning is not configured (FLEET_WG_PSK_FILE, RELAY_WG_PUBKEY)")
		return
	}
	var req struct {
		DeviceID string `json:"device_id"`
		IP       string `json:"ip"`
	}
	if !decode(w, r, &req, 1024) {
		return
	}
	existing, err := s.Store.ListDevices(r.Context())
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	nextID, nextIP, err := provision.NextAllocation(existing)
	if req.DeviceID == "" {
		req.DeviceID = nextID
	}
	if req.IP == "" {
		if err != nil {
			writeErr(w, http.StatusConflict, err.Error())
			return
		}
		req.IP = nextIP
	}
	idn, err := provision.New(*s.Provision, req.DeviceID, req.IP)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	err = s.Vault.AddDevice(r.Context(), store.Device{
		ID: idn.DeviceID, IP: idn.IP, HMACKey: idn.HMACKey, WGPubKey: idn.PublicKey,
	})
	if err != nil {
		writeErr(w, http.StatusConflict, err.Error())
		return
	}
	log.Printf("[api] %s (%s) provisioned by %s", idn.DeviceID, idn.IP, sessionFrom(r).UserName)
	s.auditLog(r, idn.DeviceID, "provision", idn.IP)
	writeJSON(w, http.StatusCreated, map[string]any{"ok": true, "device": idn})
}
