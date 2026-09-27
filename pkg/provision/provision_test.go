package provision

import (
	"strings"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"iot_server_go/pkg/store"
)

func testConfig(t *testing.T) Config {
	psk, _ := wgtypes.GenerateKey()
	relay, _ := wgtypes.GeneratePrivateKey()
	return Config{PSK: psk.String(), RelayPub: relay.PublicKey().String()}
}

// Reference output of generate_csv() in esp32_wg_http/scripts/generate_device_identity.py.
const pythonCSV = "key,type,encoding,value\nsecure_cfg,namespace,,\ndevice_id,data,string,esp32-node-009\nwg_local_ip,data,string,10.10.0.9\nwg_priv_key,data,string,PRIV\nwg_peer_pub,data,string,PUB\nwg_psk,data,string,PSK\nhmac_key,data,string,HMAC\n"

func TestCSVMatchesPythonScript(t *testing.T) {
	if got := CSV("esp32-node-009", "10.10.0.9", "PRIV", "PUB", "PSK", "HMAC"); got != pythonCSV {
		t.Fatalf("CSV mismatch:\n%q\nwant\n%q", got, pythonCSV)
	}
}

func TestNew(t *testing.T) {
	cfg := testConfig(t)
	idn, err := New(cfg, "esp32-node-005", "10.10.0.5")
	if err != nil {
		t.Fatal(err)
	}
	priv, err := wgtypes.ParseKey(idn.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	if priv.PublicKey().String() != idn.PublicKey {
		t.Fatal("public key does not derive from private key")
	}
	if len(idn.HMACKey) != 64 {
		t.Fatalf("HMAC key length %d", len(idn.HMACKey))
	}
	for _, want := range []string{"wg_priv_key,data,string," + idn.PrivateKey, "hmac_key,data,string," + idn.HMACKey, "wg_psk,data,string," + cfg.PSK, "wg_peer_pub,data,string," + cfg.RelayPub} {
		if !strings.Contains(idn.CSV, want) {
			t.Errorf("CSV lacks %q", want)
		}
	}
	if !strings.Contains(idn.RelayPeer, "PublicKey = "+idn.PublicKey) || !strings.Contains(idn.RelayPeer, "AllowedIPs = 10.10.0.5/32") {
		t.Errorf("relay peer block: %s", idn.RelayPeer)
	}
	if idn.Warning != "" {
		t.Errorf("unexpected warning %q", idn.Warning)
	}
	if hi, _ := New(cfg, "esp32-node-070", "10.10.0.70"); hi.Warning == "" {
		t.Error("no certificate SAN warning above .64")
	}
}

func TestNewRejects(t *testing.T) {
	cfg := testConfig(t)
	for _, c := range []struct{ id, ip string }{
		{"esp32-node-001", "10.10.0.1"},
		{"esp32-node-001", "10.10.0.2"},
		{"esp32-node-001", "10.10.1.5"},
		{"node,1", "10.10.0.5"},
		{"", "10.10.0.5"},
	} {
		if _, err := New(cfg, c.id, c.ip); err == nil {
			t.Errorf("New(%q, %q) accepted", c.id, c.ip)
		}
	}
	if _, err := New(Config{PSK: "nope", RelayPub: cfg.RelayPub}, "n", "10.10.0.5"); err == nil {
		t.Error("invalid PSK accepted")
	}
}

func TestNextAllocation(t *testing.T) {
	id, ip, _ := NextAllocation(nil)
	if id != "esp32-node-001" || ip != "10.10.0.3" {
		t.Fatalf("empty fleet: %s %s", id, ip)
	}
	existing := []store.Device{
		{ID: "esp32-node-001", IP: "10.10.0.3"},
		{ID: "esp32-node-002", IP: "10.10.0.4", Disabled: true},
		{ID: "lab-7", IP: "10.10.0.6"},
	}
	id, ip, _ = NextAllocation(existing)
	if id != "esp32-node-008" || ip != "10.10.0.5" {
		t.Fatalf("got %s %s, want esp32-node-008 10.10.0.5", id, ip)
	}
}
