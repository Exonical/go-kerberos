package krad

import (
	"context"
	"net"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"
)

func testResponse(requestWire []byte, secret string) ([]byte, error) {
	request, err := DecodeRequest(requestWire, secret)
	if err != nil {
		return nil, err
	}
	response, err := NewResponse(AccessAccept, request, NewAttributes())
	if err != nil {
		return nil, err
	}
	wire, err := response.Bytes(secret)
	return wire, err
}

func TestClientUDPAndTCP(t *testing.T) {
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	go func() {
		buf := make([]byte, PacketSizeMax)
		n, addr, readErr := udp.ReadFrom(buf)
		if readErr == nil {
			if wire, responseErr := testResponse(buf[:n], "secret"); responseErr == nil {
				_, _ = udp.WriteTo(wire, addr)
			}
		}
	}()
	port := strconv.Itoa(udp.LocalAddr().(*net.UDPAddr).Port)
	response, err := NewClient().Send(context.Background(), AccessRequest,
		NewAttributes(), "127.0.0.1:"+port, "secret", time.Second, 1)
	if err != nil || response.Code != AccessAccept {
		t.Fatalf("UDP response = %#v, %v", response, err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		wire, readErr := ReadPacket(conn)
		if readErr == nil {
			if responseWire, responseErr := testResponse(wire, "secret"); responseErr == nil {
				_, _ = conn.Write(responseWire)
			}
		}
	}()
	response, err = NewClient().Send(context.Background(), AccessRequest,
		NewAttributes(), "tcp://"+listener.Addr().String(), "secret", time.Second, 3)
	if err != nil || response.Code != AccessAccept {
		t.Fatalf("TCP response = %#v, %v", response, err)
	}
}

func TestClientUnixEmptySecret(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix-domain RADIUS sockets are unavailable on Windows")
	}
	path := filepath.Join(t.TempDir(), "radius.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		wire, readErr := ReadPacket(conn)
		if readErr == nil {
			if responseWire, responseErr := testResponse(wire, ""); responseErr == nil {
				_, _ = conn.Write(responseWire)
			}
		}
	}()
	response, err := NewClient().Send(context.Background(), AccessRequest,
		NewAttributes(), path, "", time.Second, 3)
	if err != nil || response.Code != AccessAccept {
		t.Fatalf("Unix response = %#v, %v", response, err)
	}
}
