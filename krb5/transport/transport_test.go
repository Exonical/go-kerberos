package transport

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
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

type testDialer struct{}

func (testDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, network, address)
}

func listenUDPAndTCP(t *testing.T) (*net.UDPConn, net.Listener) {
	t.Helper()
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	tcp, err := net.Listen("tcp", udp.LocalAddr().String())
	if err != nil {
		udp.Close()
		t.Fatalf("ListenTCP: %v", err)
	}
	t.Cleanup(func() {
		udp.Close()
		tcp.Close()
	})
	return udp, tcp
}

func readFrame(r io.Reader) ([]byte, error) {
	var length uint32
	if err := binary.Read(r, binary.BigEndian, &length); err != nil {
		return nil, err
	}
	data := make([]byte, length)
	_, err := io.ReadFull(r, data)
	return data, err
}

func writeFrame(w io.Writer, payload []byte) error {
	if err := binary.Write(w, binary.BigEndian, uint32(len(payload))); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

func TestUDPExchangePlainResponse(t *testing.T) {
	udp, _ := listenUDPAndTCP(t)
	received := make(chan struct{})
	go func() {
		buf := make([]byte, 4096)
		udp.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, addr, err := udp.ReadFrom(buf)
		if err == nil {
			_, _ = udp.WriteTo([]byte("udp-response"), addr)
			close(received)
		}
	}()
	exchange := Exchange{MaxFrameSize: 1024, UDPPreferenceLimit: 1400, Timeout: time.Second, Dialer: testDialer{}}
	response, err := exchange.Request(context.Background(), udp, udp.LocalAddr(), []byte("request"))
	if err != nil {
		t.Fatalf("Request: %v", err)
	}
	if !bytes.Equal(response, []byte("udp-response")) {
		t.Fatalf("response = %q", response)
	}
	<-received
}

func responseTooBigDER() []byte {
	// RFC 4120 KRB-ERROR application 30 with error-code 52.
	return []byte{
		0x7e, 0x22,
		0xa0, 0x03, 0x02, 0x01, 0x05,
		0xa1, 0x03, 0x02, 0x01, 0x1e,
		0xa4, 0x11, 0x1b, 0x0f, '2', '0', '2', '4', '0', '1', '0', '1',
		'0', '0', '0', '0', '0', '0', 'Z',
		0xa6, 0x03, 0x02, 0x01, 0x34,
	}
}

func TestUDPResponseTooBigRetriesTCP(t *testing.T) {
	udp, tcp := listenUDPAndTCP(t)
	tcpRequest := make(chan []byte, 1)
	go func() {
		buf := make([]byte, 4096)
		udp.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, addr, err := udp.ReadFrom(buf)
		if err == nil {
			_, _ = udp.WriteTo(responseTooBigDER(), addr)
		}
	}()
	go func() {
		tcp.(*net.TCPListener).SetDeadline(time.Now().Add(2 * time.Second))
		conn, err := tcp.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		request, err := readFrame(conn)
		if err == nil {
			tcpRequest <- request
			_ = writeFrame(conn, []byte("tcp-response"))
		}
	}()
	exchange := Exchange{MaxFrameSize: 1024, UDPPreferenceLimit: 1400, Timeout: time.Second, Dialer: testDialer{}}
	response, err := exchange.Request(context.Background(), udp, udp.LocalAddr(), []byte("request"))
	if err != nil {
		t.Fatalf("Request: %v", err)
	}
	if !bytes.Equal(response, []byte("tcp-response")) {
		t.Fatalf("response = %q", response)
	}
	select {
	case request := <-tcpRequest:
		if !bytes.Equal(request, []byte("request")) {
			t.Fatalf("TCP request = %q", request)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("TCP retry was not observed")
	}
}

func TestLargeUDPRequestUsesTCP(t *testing.T) {
	udp, tcp := listenUDPAndTCP(t)
	payload := bytes.Repeat([]byte{'x'}, 32)
	tcpRequest := make(chan []byte, 1)
	go func() {
		tcp.(*net.TCPListener).SetDeadline(time.Now().Add(2 * time.Second))
		conn, err := tcp.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		request, err := readFrame(conn)
		if err == nil {
			tcpRequest <- request
			_ = writeFrame(conn, []byte("large-response"))
		}
	}()
	exchange := Exchange{MaxFrameSize: 1024, UDPPreferenceLimit: 4, Timeout: time.Second, Dialer: testDialer{}}
	response, err := exchange.Request(context.Background(), udp, udp.LocalAddr(), payload)
	if err != nil {
		t.Fatalf("Request: %v", err)
	}
	if !bytes.Equal(response, []byte("large-response")) {
		t.Fatalf("response = %q", response)
	}
	select {
	case request := <-tcpRequest:
		if !bytes.Equal(request, payload) {
			t.Fatalf("TCP request = %q, want %q", request, payload)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("large request did not use TCP")
	}
}

func TestTransportCancellation(t *testing.T) {
	udp, _ := listenUDPAndTCP(t)
	udp.SetReadDeadline(time.Now().Add(2 * time.Second))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		buf := make([]byte, 1024)
		_, _, _ = udp.ReadFrom(buf)
	}()
	done := make(chan error, 1)
	go func() {
		_, err := (Exchange{Timeout: 10 * time.Second, Dialer: testDialer{}}).Request(ctx, udp, udp.LocalAddr(), []byte("request"))
		done <- err
	}()
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled request unexpectedly succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled request did not return")
	}
}

func TestTransportResponseTooBigCode(t *testing.T) {
	if ResponseTooBigCode != 52 {
		t.Fatalf("response-too-big code = %d, want 52", ResponseTooBigCode)
	}
	if len(responseTooBigDER()) == 0 {
		t.Fatal("empty response-too-big fixture")
	}
}
