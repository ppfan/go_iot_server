package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"iot_server_go/pkg/api"
	"iot_server_go/pkg/callback"
	"iot_server_go/pkg/devices"
	"iot_server_go/pkg/fleet"
	"iot_server_go/pkg/speedtest"
	"iot_server_go/pkg/wghealth"
)

func getEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func getDuration(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			log.Fatalf("%s: %v", key, err)
		}
		return d
	}
	return def
}

// listen retries while the address is not assigned yet: wg0 may come up after
// this process starts when both share the WireGuard container's network.
func listen(ctx context.Context, addr string, wait time.Duration) (net.Listener, error) {
	deadline := time.Now().Add(wait)
	for {
		ln, err := net.Listen("tcp", addr)
		if err == nil || !errors.Is(err, syscall.EADDRNOTAVAIL) || time.Now().After(deadline) {
			return ln, err
		}
		log.Printf("waiting for %s to become available...", addr)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}

func newHTTPServer(h http.Handler, writeTimeout time.Duration) *http.Server {
	return &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    8 << 10,
	}
}

func main() {
	controlIP := getEnv("CONTROL_ROOM_IP", "10.10.0.2")
	callbackAddr := net.JoinHostPort(controlIP, getEnv("CALLBACK_PORT", "9090"))
	speedtestAddr := net.JoinHostPort(controlIP, getEnv("SPEEDTEST_PORT", "9091"))
	dashboardAddr := getEnv("DASHBOARD_ADDR", "127.0.0.1:8000")
	devicePort, err := strconv.Atoi(getEnv("DEVICE_PORT", "8443"))
	if err != nil {
		log.Fatalf("DEVICE_PORT: %v", err)
	}
	token := os.Getenv("DASHBOARD_TOKEN")
	if len(token) < 32 {
		log.Fatal("DASHBOARD_TOKEN must be set to at least 32 characters (e.g. `openssl rand -hex 32`)")
	}

	vault, err := fleet.Load(getEnv("FLEET_KEYS_FILE", "fleet_keys.json"))
	if err != nil {
		log.Fatalf("fleet registry: %v", err)
	}
	caPEM, err := os.ReadFile(getEnv("CA_CERT_FILE", "certs/ca_cert.pem"))
	if err != nil {
		log.Fatalf("CA certificate: %v", err)
	}
	deviceTLS, err := devices.NewTLSConfig(caPEM)
	if err != nil {
		log.Fatalf("CA certificate: %v", err)
	}
	serverCert, err := tls.LoadX509KeyPair(getEnv("TLS_CERT_FILE", "certs/server_cert.pem"), getEnv("TLS_KEY_FILE", "certs/server_key.pem"))
	if err != nil {
		log.Fatalf("callback TLS certificate: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	tunnel := wghealth.New(getEnv("WG_INTERFACE", "wg0"))
	go tunnel.Run(ctx, 10*time.Second)

	registry := devices.NewRegistry(vault, getDuration("ONLINE_WINDOW", 3*time.Minute), tunnel.Up)
	client := devices.NewClient(vault, registry, devicePort, deviceTLS)

	log.Printf("==================================================")
	log.Printf("Go IoT Fleet Server (Control Room %s)", controlIP)
	log.Printf("Devices   : %d registered", len(vault.IDs()))
	log.Printf("Callback  : https://%s/callback", callbackAddr)
	log.Printf("Speedtest : tcp://%s", speedtestAddr)
	log.Printf("Dashboard : http://%s", dashboardAddr)
	log.Printf("==================================================")

	listenWait := getDuration("LISTEN_WAIT", 60*time.Second)
	cbLn, err := listen(ctx, callbackAddr, listenWait)
	if err != nil {
		log.Fatalf("callback listener: %v (is WireGuard up with %s?)", err, controlIP)
	}
	stLn, err := listen(ctx, speedtestAddr, listenWait)
	if err != nil {
		log.Fatalf("speedtest listener: %v", err)
	}
	dashLn, err := listen(ctx, dashboardAddr, listenWait)
	if err != nil {
		log.Fatalf("dashboard listener: %v", err)
	}

	callbackSrv := newHTTPServer(callback.Handler(vault, registry), 10*time.Second)
	callbackSrv.TLSConfig = &tls.Config{Certificates: []tls.Certificate{serverCert}, MinVersion: tls.VersionTLS12}
	dashboardSrv := newHTTPServer((&api.Server{
		Token: token, Vault: vault, Registry: registry, Client: client, Tunnel: tunnel,
	}).Handler(), 30*time.Second)

	errc := make(chan error, 3)
	go func() { errc <- fmt.Errorf("callback: %w", callbackSrv.ServeTLS(cbLn, "", "")) }()
	go func() { errc <- fmt.Errorf("dashboard: %w", dashboardSrv.Serve(dashLn)) }()
	go func() {
		errc <- fmt.Errorf("speedtest: %w", speedtest.NewServer(vault.IsDeviceIP).Serve(ctx, stLn))
	}()
	if every := getDuration("POLL_INTERVAL", time.Minute); every > 0 {
		go client.Poll(ctx, every, 8)
	}

	select {
	case <-ctx.Done():
	case err := <-errc:
		log.Printf("server stopped: %v", err)
	}
	stop()

	log.Println("Shutting down...")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	callbackSrv.Shutdown(shutdownCtx)
	dashboardSrv.Shutdown(shutdownCtx)
	log.Println("Server stopped cleanly.")
}
