package kdc

import (
	"net"
	"testing"
	"time"

	"github.com/Exonical/go-kerberos/krb5/transport"
)

func TestKDCConnectionCapClosesExcessConnection(t *testing.T) {
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
	_ = second.SetReadDeadline(time.Now().Add(time.Second))
	_ = transport.WriteTCPFrame(second, []byte("x"))
	var one [1]byte
	if _, err := second.Read(one[:]); err == nil {
		t.Fatal("excess TCP connection remained open")
	}
	_ = listener.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("TCP server did not stop")
	}
}
