// Package speedtest implements the raw TCP sink/source used by main/speedtest.c.
//
// Protocol: the device connects and sends one line, "DOWNLOAD:<sec>\n" or
// "UPLOAD:<sec>\n". DOWNLOAD → the server streams data for <sec> seconds and
// closes. UPLOAD → the server reads until EOF. Mode "both" is two connections.
package speedtest

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	maxDurationSec = 15 // same bound as data_server.c
	maxConcurrent  = 4
	chunkSize      = 1440 // fits in one WireGuard packet
)

type Server struct {
	allowed func(netip.Addr) bool
	sem     chan struct{}
	pool    sync.Pool
}

// NewServer accepts connections only from addresses for which allowed returns true.
func NewServer(allowed func(netip.Addr) bool) *Server {
	s := &Server{allowed: allowed, sem: make(chan struct{}, maxConcurrent)}
	s.pool.New = func() any {
		b := make([]byte, 64*1024)
		for i := range b {
			b[i] = 'X'
		}
		return &b
	}
	return s
}

// Serve accepts connections on ln until ctx is cancelled.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if errors.Is(err, net.ErrClosed) {
				return err
			}
			log.Printf("[speedtest] accept: %v", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		src, _ := netip.ParseAddrPort(conn.RemoteAddr().String())
		if !s.allowed(src.Addr().Unmap()) {
			log.Printf("[speedtest] refused %s: not a fleet device", src.Addr())
			conn.Close()
			continue
		}
		select {
		case s.sem <- struct{}{}:
			go func() {
				defer func() { <-s.sem }()
				s.handle(conn)
			}()
		default:
			log.Printf("[speedtest] busy, refused %s", src.Addr())
			conn.Close()
		}
	}
}

func parseRequest(line string) (mode string, sec int, err error) {
	mode, num, ok := strings.Cut(strings.TrimSpace(line), ":")
	if !ok || (mode != "DOWNLOAD" && mode != "UPLOAD") {
		return "", 0, fmt.Errorf("bad request %q", line)
	}
	sec, err = strconv.Atoi(num)
	if err != nil || sec < 1 || sec > maxDurationSec {
		return "", 0, fmt.Errorf("bad duration %q", num)
	}
	return mode, sec, nil
}

func (s *Server) handle(conn net.Conn) {
	defer conn.Close()
	peer := conn.RemoteAddr().String()

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	line, err := bufio.NewReaderSize(io.LimitReader(conn, 32), 32).ReadString('\n')
	if err != nil {
		log.Printf("[speedtest] %s: no request line: %v", peer, err)
		return
	}
	mode, sec, err := parseRequest(line)
	if err != nil {
		log.Printf("[speedtest] %s: %v", peer, err)
		return
	}

	bufPtr := s.pool.Get().(*[]byte)
	defer s.pool.Put(bufPtr)
	buf := *bufPtr

	start := time.Now()
	var n int64
	switch mode {
	case "DOWNLOAD":
		conn.SetWriteDeadline(start.Add(time.Duration(sec)*time.Second + 5*time.Second))
		end := start.Add(time.Duration(sec) * time.Second)
		for time.Now().Before(end) {
			w, err := conn.Write(buf[:chunkSize])
			n += int64(w)
			if err != nil {
				break
			}
		}
	case "UPLOAD":
		conn.SetReadDeadline(start.Add(time.Duration(sec)*time.Second + 10*time.Second))
		n, _ = io.CopyBuffer(io.Discard, conn, buf)
	}
	elapsed := time.Since(start).Seconds()
	log.Printf("[speedtest] %s %s: %d bytes in %.2fs (%.2f Mbps)", peer, mode, n, elapsed, float64(n)*8/1e6/elapsed)
}
