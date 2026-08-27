package transport

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func TestTCPFrameRoundTrip(t *testing.T) {
	payload := []byte("kerberos")
	var encoded bytes.Buffer
	if err := WriteTCPFrame(&encoded, payload); err != nil {
		t.Fatalf("WriteTCPFrame: %v", err)
	}
	if got := binary.BigEndian.Uint32(encoded.Bytes()[:4]); got != uint32(len(payload)) {
		t.Fatalf("frame length = %d, want %d", got, len(payload))
	}
	decoded, err := ReadTCPFrame(&encoded, DefaultMaxFrameSize)
	if err != nil {
		t.Fatalf("ReadTCPFrame: %v", err)
	}
	if string(decoded) != string(payload) {
		t.Fatalf("decoded = %q, want %q", decoded, payload)
	}
}

func TestTCPFrameRejectsTruncatedAndOversized(t *testing.T) {
	for _, input := range [][]byte{{}, {0, 0, 0}, {0xff, 0xff, 0xff, 0xff}} {
		if _, err := ReadTCPFrame(bytes.NewReader(input), 1024); err == nil {
			t.Fatalf("frame %x unexpectedly accepted", input)
		}
	}
}

type packetConn struct{}

func (packetConn) ReadFrom([]byte) (int, net.Addr, error) { return 0, nil, nil }
func (packetConn) WriteTo([]byte, net.Addr) (int, error)  { return 0, nil }
func (packetConn) Close() error                           { return nil }
func (packetConn) LocalAddr() net.Addr                    { return &net.IPAddr{} }
func (packetConn) SetDeadline(time.Time) error            { return nil }
func (packetConn) SetReadDeadline(time.Time) error        { return nil }
func (packetConn) SetWriteDeadline(time.Time) error       { return nil }

func TestUDPExchangeAndResponseTooBigTCPRetry(t *testing.T) {
	exchange := Exchange{MaxFrameSize: 1024, UDPPreferenceLimit: 1400, Timeout: time.Second}
	ctx := context.Background()
	response, err := exchange.Request(ctx, packetConn{}, &net.IPAddr{}, []byte("request"))
	if err != nil {
		t.Fatalf("Request: %v", err)
	}
	if len(response) == 0 {
		t.Fatal("empty response")
	}
	if ResponseTooBigCode != 52 {
		t.Fatalf("response-too-big code = %d, want 52", ResponseTooBigCode)
	}
}

func TestTransportCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := (Exchange{}).Request(ctx, packetConn{}, &net.IPAddr{}, nil)
	if err == nil {
		t.Fatal("cancelled request unexpectedly succeeded")
	}
}
