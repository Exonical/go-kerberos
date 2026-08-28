package kdc

import (
	"net"
	"testing"
	"time"

	"github.com/Exonical/go-kerberos/krb5/transport"
)

func TestKDCConnectionCapEvictsOldestConnection(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	server := &Server{MaxTCPConnections: 1, TCPIdleTimeout: time.Second}
	done := make(chan error, 1)
	go func() { done <- server.serveTCP(listener) }()
	first, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	_ = first.SetReadDeadline(time.Now().Add(time.Second))
	var one [1]byte
	if _, err := first.Read(one[:]); err == nil {
		t.Fatal("oldest TCP connection remained open")
	}
	_ = second.SetReadDeadline(time.Now().Add(time.Second))
	_ = transport.WriteTCPFrame(second, []byte("x"))
	response, err := transport.ReadTCPFrame(second, transport.DefaultMaxFrameSize)
	if err != nil {
		t.Fatalf("newest TCP connection was closed: %v", err)
	}
	if len(response) == 0 {
		t.Fatal("newest TCP connection returned an empty response")
	}
	_ = listener.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("TCP server did not stop")
	}
}

func TestKDCConnectionCapPreservesNewestConnectionsUnderChurn(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	server := &Server{MaxTCPConnections: 2, TCPIdleTimeout: time.Second}
	done := make(chan error, 1)
	go func() { done <- server.serveTCP(listener) }()
	var conns []net.Conn
	t.Cleanup(func() {
		for _, conn := range conns {
			_ = conn.Close()
		}
	})
	for i := 0; i < 6; i++ {
		conn, err := net.Dial("tcp", listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		conns = append(conns, conn)
		if i >= 2 {
			_ = conns[i-2].SetReadDeadline(time.Now().Add(time.Second))
			var one [1]byte
			if _, err := conns[i-2].Read(one[:]); err == nil {
				t.Fatalf("connection %d was not evicted during churn", i-2)
			}
		}
	}
	for i := len(conns) - 2; i < len(conns); i++ {
		_ = conns[i].SetReadDeadline(time.Now().Add(time.Second))
		if err := transport.WriteTCPFrame(conns[i], []byte("x")); err != nil {
			t.Fatalf("newest connection %d write: %v", i, err)
		}
		response, err := transport.ReadTCPFrame(conns[i], transport.DefaultMaxFrameSize)
		if err != nil {
			t.Fatalf("newest connection %d was closed: %v", i, err)
		}
		if len(response) == 0 {
			t.Fatalf("newest connection %d returned an empty response", i)
		}
	}
	_ = listener.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("TCP server did not stop")
	}
}
