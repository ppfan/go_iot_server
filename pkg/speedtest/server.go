package speedtest

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Server handles high-throughput raw TCP speed tests with minimal allocations.
type Server struct {
	port       int
	bufferPool *sync.Pool
	bytesRecv  atomic.Uint64
	bytesSent  atomic.Uint64
}

// NewServer initializes the speedtest server with a reusable buffer pool.
func NewServer(port int) *Server {
	return &Server{
		port: port,
		bufferPool: &sync.Pool{
			New: func() interface{} {
				// 64 KB recycled chunk buffer
				buf := make([]byte, 64*1024)
				return &buf
			},
		},
	}
}

// Start listens for speedtest TCP connections from ESP32 devices.
func (s *Server) Start(ctx context.Context) error {
	addr := fmt.Sprintf("0.0.0.0:%d", s.port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("speedtest listener failed on %s: %w", addr, err)
	}
	defer listener.Close()

	log.Printf("[Speedtest] Raw TCP speedtest server listening on :%d", s.port)

	go func() {
		<-ctx.Done()
		listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				log.Printf("[Speedtest] Accept error: %v", err)
				continue
			}
		}

		go s.handleConnection(conn)
	}
}

func (s *Server) handleConnection(conn net.Conn) {
	defer conn.Close()

	// Recycled buffer from pool
	bufPtr := s.bufferPool.Get().(*[]byte)
	defer s.bufferPool.Put(bufPtr)
	buf := *bufPtr

	// Read initial mode header if applicable, or stream bytes
	conn.SetDeadline(time.Now().Add(20 * time.Second))

	totalRead := 0
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			totalRead += n
			s.bytesRecv.Add(uint64(n))
		}
		if err != nil {
			if err != io.EOF {
				// Socket closed or timeout
			}
			break
		}
	}
}
