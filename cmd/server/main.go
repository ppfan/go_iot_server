package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"iot_server_go/pkg/crypto"
	"iot_server_go/pkg/devices"
	"iot_server_go/pkg/models"
	"iot_server_go/pkg/speedtest"
)

func getEnv(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}

func getActiveSecret() string {
	isDebug := strings.ToLower(os.Getenv("APP_DEBUG")) == "true"
	if isDebug {
		if sec := os.Getenv("APP_HMAC_DEV_KEY"); sec != "" {
			return sec
		}
	} else {
		if sec := os.Getenv("APP_HMAC_PROD_KEY"); sec != "" {
			return sec
		}
	}
	if sec := os.Getenv("APP_HMAC_SHARED_SECRET"); sec != "" {
		return sec
	}
	// Fallback development default
	return "dev_secret_change_in_production"
}

func main() {
	secret := getActiveSecret()
	callbackPort := getEnv("CALLBACK_PORT", "9090")
	speedtestPort, _ := strconv.Atoi(getEnv("SPEEDTEST_PORT", "9091"))
	dashboardPort := getEnv("DASHBOARD_PORT", "8000")

	log.Printf("==================================================")
	log.Printf("Starting Go IoT Fleet Server")
	log.Printf("Callback Port : %s", callbackPort)
	log.Printf("Speedtest Port: %d", speedtestPort)
	log.Printf("Dashboard Port: %s", dashboardPort)
	log.Printf("Debug Mode    : %s", getEnv("APP_DEBUG", "false"))
	log.Printf("==================================================")

	registry := devices.NewRegistry(secret)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 1. Start raw TCP speed test sink
	speedtestServer := speedtest.NewServer(speedtestPort)
	go func() {
		if err := speedtestServer.Start(ctx); err != nil {
			log.Fatalf("Speedtest server error: %v", err)
		}
	}()

	// 2. Start Callback Receiver (Port 9090)
	callbackMux := http.NewServeMux()
	callbackMux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		body, err := io.ReadAll(io.LimitReader(r.Body, 8192))
		if err != nil {
			http.Error(w, "Failed to read body", http.StatusBadRequest)
			return
		}

		sig := r.Header.Get("X-Signature-SHA256")
		verified := crypto.VerifyHMAC(secret, body, sig)
		if !verified {
			log.Printf("[Callback] WARNING: Invalid signature from %s", r.RemoteAddr)
			http.Error(w, "Bad signature", http.StatusUnauthorized)
			return
		}

		var payload models.TelemetryPayload
		if err := json.Unmarshal(body, &payload); err == nil {
			// Extract IP from remote addr if not in JSON
			remoteIP := r.RemoteAddr
			if idx := strings.LastIndex(remoteIP, ":"); idx != -1 {
				remoteIP = remoteIP[:idx]
			}
			registry.RecordTelemetry(remoteIP, &payload)
			log.Printf("[Callback] Telemetry from %s | Uptime: %ds | Heap: %d B | Relay: %v",
				remoteIP, payload.UptimeS, payload.FreeHeap, payload.RelayState)
		} else {
			log.Printf("[Callback] Non-telemetry callback body: %s", string(body))
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok","received":true}`))
	})

	callbackServer := &http.Server{
		Addr:    ":" + callbackPort,
		Handler: callbackMux,
	}

	go func() {
		log.Printf("[Callback] HTTP Callback receiver listening on :%s", callbackPort)
		if err := callbackServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Callback server error: %v", err)
		}
	}()

	// 3. Start REST / Dashboard API Server (Port 8000)
	dashboardMux := http.NewServeMux()

	// GET /api/devices - List all tracked ESP32s
	dashboardMux.HandleFunc("/api/devices", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(registry.ListDevices())
	})

	// POST /api/command - Send action to a specific ESP32
	dashboardMux.HandleFunc("/api/command", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req struct {
			TargetIP string                 `json:"target_ip"`
			Port     int                    `json:"port"`
			Payload  map[string]interface{} `json:"payload"`
		}

		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}

		if req.Port == 0 {
			req.Port = 8443
		}
		if req.TargetIP == "" {
			http.Error(w, "target_ip is required", http.StatusBadRequest)
			return
		}

		cmdCtx, cmdCancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cmdCancel()

		resp, err := registry.SendHTTPCommand(cmdCtx, req.TargetIP, req.Port, req.Payload)
		w.Header().Set("Content-Type", "application/json")
		if err != nil {
			w.WriteHeader(http.StatusBadGateway)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"ok":    false,
				"error": err.Error(),
				"body":  string(resp),
			})
			return
		}

		var jsonResp interface{}
		if err := json.Unmarshal(resp, &jsonResp); err == nil {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"ok":   true,
				"body": jsonResp,
			})
		} else {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"ok":   true,
				"body": string(resp),
			})
		}
	})

	// Simple status probe
	dashboardMux.HandleFunc("/api/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"status":"online","time":"%s"}`, time.Now().Format(time.RFC3339))
	})

	dashboardServer := &http.Server{
		Addr:    ":" + dashboardPort,
		Handler: dashboardMux,
	}

	go func() {
		log.Printf("[Dashboard API] REST API listening on :%s", dashboardPort)
		if err := dashboardServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Dashboard server error: %v", err)
		}
	}()

	// Graceful shutdown handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	log.Println("Shutting down server gracefully...")
	cancel()

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	callbackServer.Shutdown(shutdownCtx)
	dashboardServer.Shutdown(shutdownCtx)
	log.Println("Server stopped cleanly.")
}
