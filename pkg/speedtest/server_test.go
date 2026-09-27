package speedtest

import (
	"context"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestParseRequest(t *testing.T) {
	tests := []struct {
		line, mode string
		sec        int
		ok         bool
	}{
		{"DOWNLOAD:3\n", "DOWNLOAD", 3, true},
		{"UPLOAD:15\n", "UPLOAD", 15, true},
		{"UPLOAD:16\n", "", 0, false},
		{"DOWNLOAD:0\n", "", 0, false},
		{"DOWNLOAD:-5\n", "", 0, false},
		{"\x01", "", 0, false},
		{"SIDEWAYS:3\n", "", 0, false},
	}
	for _, tt := range tests {
		mode, sec, err := parseRequest(tt.line)
		if (err == nil) != tt.ok || mode != tt.mode || sec != tt.sec {
			t.Errorf("parseRequest(%q) = %q, %d, %v", tt.line, mode, sec, err)
		}
	}
}

func start(t *testing.T, allowed bool) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go NewServer(func(netip.Addr) bool { return allowed }).Serve(ctx, ln)
	return ln.Addr().String()
}

func TestDownloadStreamsForDuration(t *testing.T) {
	conn, err := net.Dial("tcp", start(t, true))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.Write([]byte("DOWNLOAD:1\n"))
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	t0 := time.Now()
	n, err := io.Copy(io.Discard, conn)
	if err != nil {
		t.Fatal(err)
	}
	if n == 0 {
		t.Fatal("no data streamed")
	}
	if d := time.Since(t0); d < 900*time.Millisecond || d > 3*time.Second {
		t.Fatalf("stream lasted %v, want ~1s", d)
	}
}

func TestUploadReadsUntilEOF(t *testing.T) {
	conn, err := net.Dial("tcp", start(t, true))
	if err != nil {
		t.Fatal(err)
	}
	conn.Write([]byte("UPLOAD:1\n"))
	conn.Write([]byte(strings.Repeat("U", 100000)))
	conn.(*net.TCPConn).CloseWrite()
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadAll(conn); err != nil {
		t.Fatalf("server did not close after upload EOF: %v", err)
	}
}

func TestRefusesNonFleetAddress(t *testing.T) {
	conn, err := net.Dial("tcp", start(t, false))
	if err != nil {
		t.Fatal(err)
	}
	conn.Write([]byte("DOWNLOAD:1\n"))
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if n, _ := io.Copy(io.Discard, conn); n != 0 {
		t.Fatalf("got %d bytes from refused connection", n)
	}
}
