package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"iot_server_go/pkg/auth"
	"iot_server_go/pkg/devices"
	"iot_server_go/pkg/events"
	"iot_server_go/pkg/fleet/fleettest"
	"iot_server_go/pkg/provision"
	"iot_server_go/pkg/store"
	"iot_server_go/pkg/wghealth"
)

const password = "correct horse battery"

type env struct {
	h     http.Handler
	store *store.Store
}

func newEnv(t *testing.T) env {
	t.Helper()
	v, st := fleettest.New(t, map[string]fleettest.Dev{"n1": {IP: "10.10.0.3", Key: "k"}})
	hash, _ := auth.HashPassword(password)
	if err := st.CreateUser(context.Background(), "admin", hash); err != nil {
		t.Fatal(err)
	}
	am, err := auth.NewManager(st, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	reg := devices.NewRegistry(v, time.Minute, nil)
	psk, _ := wgtypes.GenerateKey()
	relay, _ := wgtypes.GeneratePrivateKey()
	s := &Server{
		Vault: v, Store: st, Auth: am, Registry: reg,
		Client:    devices.NewClient(v, reg, 1, nil),
		Tunnel:    wghealth.New("wg-test"),
		Events:    events.NewRing(10),
		Provision: &provision.Config{PSK: psk.String(), RelayPub: relay.PublicKey().String()},
		Static:    fstest.MapFS{"index.html": {Data: []byte("<html>control room</html>")}},
	}
	return env{h: s.Handler(), store: st}
}

type client struct {
	t      *testing.T
	h      http.Handler
	cookie *http.Cookie
	csrf   string
	remote string
}

func (c *client) do(method, path, body string, hdr ...string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.RemoteAddr = c.remote
	if c.remote == "" {
		req.RemoteAddr = "127.0.0.1:1"
	}
	req.Header.Set("Content-Type", "application/json")
	if c.cookie != nil {
		req.AddCookie(c.cookie)
	}
	if c.csrf != "" {
		req.Header.Set("X-CSRF-Token", c.csrf)
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	rec := httptest.NewRecorder()
	c.h.ServeHTTP(rec, req)
	return rec
}

func (c *client) login(t *testing.T) {
	t.Helper()
	rec := c.do("POST", "/api/login", `{"username":"admin","password":"`+password+`"}`)
	if rec.Code != 200 {
		t.Fatalf("login: %d %s", rec.Code, rec.Body)
	}
	var out struct{ CSRF string }
	json.Unmarshal(rec.Body.Bytes(), &out)
	c.csrf = out.CSRF
	for _, ck := range rec.Result().Cookies() {
		if ck.Name == sessionCookie {
			c.cookie = ck
			if !ck.HttpOnly || ck.SameSite != http.SameSiteStrictMode {
				t.Fatalf("session cookie flags: %+v", ck)
			}
		}
	}
	if c.cookie == nil || c.csrf == "" {
		t.Fatal("login did not return session cookie and csrf")
	}
}

func TestAccessControl(t *testing.T) {
	e := newEnv(t)
	anon := &client{t: t, h: e.h}

	for _, p := range []string{"/api/devices", "/api/session", "/api/events", "/api/audit", "/api/admin/devices", "/api/tunnel"} {
		if rec := anon.do("GET", p, ""); rec.Code != 401 {
			t.Errorf("GET %s without session: %d", p, rec.Code)
		}
	}
	if rec := anon.do("GET", "/api/health", ""); rec.Code != 200 {
		t.Errorf("health: %d", rec.Code)
	}
	if rec := anon.do("GET", "/", ""); rec.Code != 200 || !strings.Contains(rec.Body.String(), "control room") {
		t.Errorf("static page: %d", rec.Code)
	}
	if rec := anon.do("GET", "/", ""); !strings.Contains(rec.Header().Get("Content-Security-Policy"), "default-src 'self'") {
		t.Error("missing CSP header")
	}
	if rec := anon.do("POST", "/api/login", `{"username":"admin","password":"nope-nope-nope"}`); rec.Code != 401 {
		t.Errorf("bad password: %d", rec.Code)
	}
	if rec := anon.do("POST", "/api/login", `username=admin`, "Content-Type", "application/x-www-form-urlencoded"); rec.Code != 415 {
		t.Errorf("form login: %d", rec.Code)
	}

	c := &client{t: t, h: e.h}
	c.login(t)
	if rec := c.do("GET", "/api/devices", ""); rec.Code != 200 {
		t.Errorf("devices with session: %d", rec.Code)
	}

	// CSRF: POST without or with a wrong token is refused.
	noCSRF := &client{t: t, h: e.h, cookie: c.cookie}
	if rec := noCSRF.do("POST", "/api/devices/n1/command", `{"command":"relay_up"}`); rec.Code != 403 {
		t.Errorf("POST without CSRF: %d", rec.Code)
	}
	badCSRF := &client{t: t, h: e.h, cookie: c.cookie, csrf: "x"}
	if rec := badCSRF.do("POST", "/api/devices/n1/rotate-key", ""); rec.Code != 403 {
		t.Errorf("POST with wrong CSRF: %d", rec.Code)
	}

	// Fleet devices cannot reach the dashboard even with a session.
	fromDevice := &client{t: t, h: e.h, cookie: c.cookie, csrf: c.csrf, remote: "10.10.0.3:1"}
	if rec := fromDevice.do("GET", "/api/devices", ""); rec.Code != 403 {
		t.Errorf("from device IP: %d", rec.Code)
	}

	// Logout ends the session.
	if rec := c.do("POST", "/api/logout", ""); rec.Code != 200 {
		t.Fatalf("logout: %d", rec.Code)
	}
	if rec := c.do("GET", "/api/devices", ""); rec.Code != 401 {
		t.Errorf("after logout: %d", rec.Code)
	}
}

func TestLoginRateLimit(t *testing.T) {
	e := newEnv(t)
	c := &client{t: t, h: e.h}
	for i := 0; i < 5; i++ {
		c.do("POST", "/api/login", `{"username":"admin","password":"wrong-password"}`)
	}
	if rec := c.do("POST", "/api/login", `{"username":"admin","password":"`+password+`"}`); rec.Code != 429 {
		t.Fatalf("after 5 failures: %d", rec.Code)
	}
}

func TestCommandValidationAndShape(t *testing.T) {
	e := newEnv(t)
	c := &client{t: t, h: e.h}
	c.login(t)

	for body, want := range map[string]int{
		`{"command":"rotate_hmac"}`:                  400,
		`{"rotate_hmac":true,"new_key":"x"}`:         400,
		`{"command":"speedtest","duration":99}`:      400,
		`{"command":"relay_up","device_id":"other"}`: 400,
	} {
		if rec := c.do("POST", "/api/devices/n1/command", body); rec.Code != want {
			t.Errorf("%s: %d, want %d", body, rec.Code, want)
		}
	}
	if rec := c.do("POST", "/api/devices/nX/command", `{"command":"relay_up"}`); rec.Code != 404 {
		t.Errorf("unknown device: %d", rec.Code)
	}
	// Device unreachable (port 1): reported in the body with HTTP 200, as app.js expects.
	rec := c.do("POST", "/api/devices/n1/command", `{"command":"relay_up"}`)
	var out commandResult
	json.Unmarshal(rec.Body.Bytes(), &out)
	if rec.Code != 200 || out.OK || out.Error == "" {
		t.Fatalf("unreachable device: %d %s", rec.Code, rec.Body)
	}
	// relay_up is audited.
	rec = c.do("GET", "/api/audit", "")
	if !strings.Contains(rec.Body.String(), `"action":"relay_up"`) || !strings.Contains(rec.Body.String(), `"user":"admin"`) {
		t.Fatalf("audit: %s", rec.Body)
	}
}

func TestProvisionDevice(t *testing.T) {
	e := newEnv(t)
	c := &client{t: t, h: e.h}
	c.login(t)

	rec := c.do("POST", "/api/devices", `{}`)
	if rec.Code != 201 {
		t.Fatalf("provision: %d %s", rec.Code, rec.Body)
	}
	var out struct {
		Device struct {
			DeviceID  string `json:"device_id"`
			IP        string `json:"ip"`
			PublicKey string `json:"wg_pubkey"`
			CSV       string `json:"nvs_csv"`
			RelayPeer string `json:"relay_peer"`
		}
	}
	json.Unmarshal(rec.Body.Bytes(), &out)
	d := out.Device
	if d.DeviceID != "esp32-node-002" || d.IP != "10.10.0.4" {
		t.Fatalf("allocated %s %s, want esp32-node-002 10.10.0.4", d.DeviceID, d.IP)
	}
	var priv string
	for _, line := range strings.Split(d.CSV, "\n") {
		if v, ok := strings.CutPrefix(line, "wg_priv_key,data,string,"); ok {
			priv = v
		}
	}
	if priv == "" || !strings.Contains(d.RelayPeer, d.PublicKey) {
		t.Fatalf("incomplete provisioning output: %+v", d)
	}

	// Live immediately; private key not stored; public key is.
	if rec := c.do("GET", "/api/devices", ""); !strings.Contains(rec.Body.String(), "esp32-node-002") {
		t.Fatal("new device not listed")
	}
	rows, _ := e.store.ListDevices(context.Background())
	for _, r := range rows {
		if r.ID == "esp32-node-002" && r.WGPubKey != d.PublicKey {
			t.Fatal("public key not stored")
		}
	}
	admin := c.do("GET", "/api/admin/devices", "").Body.Bytes()
	if bytes.Contains(admin, []byte(priv)) || bytes.Contains(admin, []byte("hmac")) {
		t.Fatalf("admin listing leaks key material: %s", admin)
	}

	// Explicit ID/IP conflicts are rejected.
	if rec := c.do("POST", "/api/devices", `{"device_id":"esp32-node-002","ip":"10.10.0.9"}`); rec.Code != 409 {
		t.Errorf("duplicate ID: %d", rec.Code)
	}
	if rec := c.do("POST", "/api/devices", `{"ip":"10.10.0.2"}`); rec.Code != 400 {
		t.Errorf("control room IP: %d", rec.Code)
	}

	// Disable revokes it.
	if rec := c.do("POST", "/api/devices/esp32-node-002/disable", ""); rec.Code != 200 {
		t.Fatalf("disable: %d", rec.Code)
	}
	if rec := c.do("GET", "/api/devices", ""); strings.Contains(rec.Body.String(), "esp32-node-002") {
		t.Fatal("disabled device still active")
	}
}
