package kdc

import (
	"bytes"
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/Exonical/go-kerberos/krb5/asn1"
	"github.com/Exonical/go-kerberos/krb5/principal"
	"github.com/Exonical/go-kerberos/krb5/protocol"
	"github.com/Exonical/go-kerberos/krb5/transport"
)

func TestKDCTooBigUDPReplyUsesKRBError(t *testing.T) {
	now := time.Unix(2000000000, 0).UTC()
	server, _ := testServer(t, now)
	server.MaxDatagramReplySize = 1
	user := principalForKDC("alice")
	service := principal.Principal{
		Realm: "TEST.REALM", NameType: principal.NTSrvInstance,
		Components: []string{"krbtgt", "TEST.REALM"},
	}
	request := asRequest(user, service, 9)
	addPreauthPassword(t, &request, "alice-password", now)
	response := server.dispatch(mustMarshal(t, request), false)
	var kerberosError protocol.KRBError
	if err := asn1.Unmarshal(response, &kerberosError); err != nil {
		t.Fatalf("KRB-ERROR: %v", err)
	}
	if kerberosError.ErrorCode != transport.ResponseTooBigCode {
		t.Fatalf("error code = %d, want %d", kerberosError.ErrorCode, transport.ResponseTooBigCode)
	}
	if kerberosError.SName.NameType != int32(service.NameType) ||
		!bytes.Equal([]byte(stringsJoin(kerberosError.SName.NameString)), []byte(stringsJoin(service.Components))) {
		t.Fatalf("error server = %#v, want %#v", kerberosError.SName, service)
	}
	if kerberosError.Realm != server.Realm {
		t.Fatalf("error server realm = %q, want %q", kerberosError.Realm, server.Realm)
	}
	if kerberosError.CName != nil {
		t.Fatalf("error client = %#v, want absent", kerberosError.CName)
	}
}

func TestKDCTooBigUDPReplyRetriesTCP(t *testing.T) {
	now := time.Unix(2000000000, 0).UTC()
	server, _ := testServer(t, now)
	server.MaxDatagramReplySize = 1
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	tcp, err := net.Listen("tcp", udp.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = server.ListenAndServe(ctx, udp, tcp) }()
	user := principalForKDC("alice")
	request := asRequest(user, principalForKDC("krbtgt", "TEST.REALM"), 10)
	addPreauthPassword(t, &request, "alice-password", now)
	payload := mustMarshal(t, request)
	address := udp.LocalAddr()
	response, err := (transport.Exchange{Timeout: 2 * time.Second, UDPPreferenceLimit: 1400}).Request(
		context.Background(), net.PacketConn(udp), address, payload)
	if err != nil {
		t.Fatalf("transport request: %v", err)
	}
	var reply protocol.ASRep
	if err := asn1.Unmarshal(response, &reply); err != nil {
		t.Fatalf("TCP AS-REP after UDP fallback: %v", err)
	}
	if reply.MsgType != 11 {
		t.Fatalf("reply message type = %d, want AS-REP", reply.MsgType)
	}
}

func TestKDCDispatchCachesSuccessfulReply(t *testing.T) {
	now := time.Unix(2000000000, 0).UTC()
	server, _ := testServer(t, now)
	request := asRequest(principalForKDC("alice"), principalForKDC("krbtgt", "TEST.REALM"), 12)
	addPreauthPassword(t, &request, "alice-password", now)
	raw := mustMarshal(t, request)
	first := server.dispatch(raw, true)
	second := server.dispatch(raw, true)
	if !bytes.Equal(first, second) {
		t.Fatal("successful duplicate did not replay the exact cached response")
	}
	if len(server.lookaside.entries) != 1 {
		t.Fatalf("successful request cache entries = %d, want 1", len(server.lookaside.entries))
	}
}

func TestKDCDispatchDropsInProgressDuplicate(t *testing.T) {
	now := time.Unix(2000000000, 0).UTC()
	server, _ := testServer(t, now)
	request := mustMarshal(t, asRequest(principalForKDC("alice"), principalForKDC("krbtgt", "TEST.REALM"), 13))
	cache := server.getLookaside()
	if _, hit := cache.begin(request, now); hit {
		t.Fatal("placeholder insertion reported a hit")
	}
	if response := server.dispatch(request, true); response != nil {
		t.Fatalf("in-progress duplicate response = %x, want nil", response)
	}
	cache.complete(request, nil, now)
}

type countingPacketConn struct {
	writes int
}

func (c *countingPacketConn) ReadFrom([]byte) (int, net.Addr, error) {
	return 0, nil, errors.New("not implemented")
}
func (c *countingPacketConn) WriteTo([]byte, net.Addr) (int, error) {
	c.writes++
	return 0, nil
}
func (c *countingPacketConn) Close() error                     { return nil }
func (c *countingPacketConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (c *countingPacketConn) SetDeadline(time.Time) error      { return nil }
func (c *countingPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (c *countingPacketConn) SetWriteDeadline(time.Time) error { return nil }

func TestKDCUDPEmptyResponseSkipsWrite(t *testing.T) {
	now := time.Unix(2000000000, 0).UTC()
	server, _ := testServer(t, now)
	request := mustMarshal(t, asRequest(principalForKDC("alice"), principalForKDC("krbtgt", "TEST.REALM"), 14))
	cache := server.getLookaside()
	cache.begin(request, now)
	conn := &countingPacketConn{}
	server.handleUDP(conn, &net.UDPAddr{}, request, make(chan error, 1))
	if conn.writes != 0 {
		t.Fatalf("empty response writes = %d, want 0", conn.writes)
	}
	cache.complete(request, nil, now)
}

func TestKDCStalledTCPConnectionCloses(t *testing.T) {
	server := &Server{TCPIdleTimeout: 20 * time.Millisecond}
	left, right := net.Pipe()
	defer right.Close()
	done := make(chan struct{})
	go func() {
		server.handleTCPConn(left)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("stalled TCP connection did not close")
	}
}

func TestKDCDispatchDoesNotCacheErrors(t *testing.T) {
	now := time.Unix(2000000000, 0).UTC()
	server, _ := testServer(t, now)
	request := mustMarshal(t, asRequest(principalForKDC("missing"), principalForKDC("krbtgt", "TEST.REALM"), 11))
	first := server.dispatch(request, true)
	second := server.dispatch(request, true)
	if !bytes.Equal(first, second) {
		t.Fatal("error responses unexpectedly differ only by cache")
	}
	if len(server.lookaside.entries) != 0 {
		t.Fatalf("error request remained cached: %d entries", len(server.lookaside.entries))
	}
}

func principalForKDC(components ...string) principal.Principal {
	return principal.Principal{Realm: "TEST.REALM", NameType: principal.NTPrincipal, Components: components}
}
