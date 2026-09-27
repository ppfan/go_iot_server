// Package provision creates new device identities. It is the Go port of
// esp32_wg_http/scripts/generate_device_identity.py.
package provision

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"iot_server_go/pkg/fleet"
	"iot_server_go/pkg/store"
)

// Device certificates (esp32_wg_http/certs/esp32_ext.cnf) have IP SANs up to .64.
const lastCertCoveredHost = 64

// Config holds the fleet-wide WireGuard values written into every device's NVS.
type Config struct {
	PSK       string // fleet preshared key (secret file, never stored in the DB)
	RelayPub  string // relay (10.10.0.1) public key
	FlashPort string // shown in the flash instructions, e.g. /dev/ttyUSB0
}

func (c Config) Validate() error {
	if _, err := wgtypes.ParseKey(c.PSK); err != nil {
		return fmt.Errorf("fleet WireGuard PSK: %w", err)
	}
	if _, err := wgtypes.ParseKey(c.RelayPub); err != nil {
		return fmt.Errorf("relay WireGuard public key: %w", err)
	}
	return nil
}

// Identity is a freshly generated device. PrivateKey is returned to the admin
// once (inside CSV) and never stored.
type Identity struct {
	DeviceID   string `json:"device_id"`
	IP         string `json:"ip"`
	PublicKey  string `json:"wg_pubkey"`
	HMACKey    string `json:"-"`
	PrivateKey string `json:"-"`
	CSV        string `json:"nvs_csv"`
	RelayPeer  string `json:"relay_peer"`
	Commands   string `json:"flash_commands"`
	Warning    string `json:"warning,omitempty"`
}

var trailingNum = regexp.MustCompile(`(\d+)$`)

// NextAllocation picks the next esp32-node-NNN after the highest number in use
// (like get_next_fleet_allocation in the Python script) and the lowest free IP
// from .3 upwards (the script takes max+1 instead, which never reuses gaps).
// Disabled devices still reserve their ID and IP.
func NextAllocation(existing []store.Device) (id, ip string, err error) {
	maxNum := 0
	used := map[string]bool{}
	usedIP := map[string]bool{}
	for _, d := range existing {
		used[d.ID] = true
		usedIP[d.IP] = true
		if m := trailingNum.FindStringSubmatch(d.ID); m != nil {
			if n, _ := strconv.Atoi(m[1]); n > maxNum {
				maxNum = n
			}
		}
	}
	for n := maxNum + 1; ; n++ {
		id = fmt.Sprintf("esp32-node-%03d", n)
		if !used[id] {
			break
		}
	}
	for host := 3; host <= 254; host++ {
		cand := fmt.Sprintf("10.10.0.%d", host)
		if !usedIP[cand] {
			return id, cand, nil
		}
	}
	return "", "", fmt.Errorf("no free device IP left in 10.10.0.3-254")
}

// New generates a WireGuard keypair and HMAC key for id/ip and renders the NVS
// CSV, the relay [Peer] block and flash instructions.
func New(cfg Config, id, ip string) (*Identity, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if err := fleet.ValidateDeviceID(id); err != nil {
		return nil, err
	}
	addr, err := fleet.ValidateDeviceIP(ip)
	if err != nil {
		return nil, err
	}
	priv, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return nil, err
	}
	hmacKey, err := fleet.NewHMACKey()
	if err != nil {
		return nil, err
	}
	idn := &Identity{
		DeviceID:   id,
		IP:         ip,
		PrivateKey: priv.String(),
		PublicKey:  priv.PublicKey().String(),
		HMACKey:    hmacKey,
	}
	idn.CSV = CSV(id, ip, idn.PrivateKey, cfg.RelayPub, cfg.PSK, hmacKey)
	idn.RelayPeer = fmt.Sprintf("# ----- Peer: %s -----\n[Peer]\nPublicKey = %s\nPresharedKey = %s\nAllowedIPs = %s/32\n",
		id, idn.PublicKey, cfg.PSK, ip)
	port := cfg.FlashPort
	if port == "" {
		port = "/dev/ttyUSB0"
	}
	idn.Commands = fmt.Sprintf(
		"python $IDF_PATH/components/nvs_flash/nvs_partition_generator/nvs_partition_gen.py generate nvs_%[1]s.csv nvs_%[1]s.bin 0x6000\n"+
			"esptool.py --chip esp32s3 -p %[2]s -b 460800 write_flash 0x9000 nvs_%[1]s.bin\n"+
			"# on the relay, after adding the [Peer] block:\n"+
			"sudo wg syncconf wg0 <(wg-quick strip wg0)\n", id, port)
	if host := addr.As4()[3]; host > lastCertCoveredHost {
		idn.Warning = fmt.Sprintf("%s is above 10.10.0.%d: the device TLS certificate has no SAN for it, so commands will fail TLS verification until the certificate is reissued.", ip, lastCertCoveredHost)
	}
	return idn, nil
}

// CSV renders the NVS manifest exactly like generate_csv() in the Python script.
func CSV(id, ip, privKey, peerPub, psk, hmacKey string) string {
	return strings.Join([]string{
		"key,type,encoding,value",
		"secure_cfg,namespace,,",
		"device_id,data,string," + id,
		"wg_local_ip,data,string," + ip,
		"wg_priv_key,data,string," + privKey,
		"wg_peer_pub,data,string," + peerPub,
		"wg_psk,data,string," + psk,
		"hmac_key,data,string," + hmacKey,
	}, "\n") + "\n"
}
