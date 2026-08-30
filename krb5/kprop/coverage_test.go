package kprop

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/Exonical/go-kerberos/krb5/asn1"
	"github.com/Exonical/go-kerberos/krb5/crypto"
	"github.com/Exonical/go-kerberos/krb5/protocol"
	"github.com/Exonical/go-kerberos/krb5/types"
)

func TestKpropValidationAndWireErrors(t *testing.T) {
	if err := (&Client{}).Send(context.Background(), nil, nil, 0); err == nil {
		t.Fatal("incomplete client send accepted")
	}
	if err := Send(context.Background(), nil, nil, nil, 0); err == nil {
		t.Fatal("incomplete send accepted")
	}
	if err := DialAndSend(context.Background(), "bad-address", nil, nil, 0); err == nil {
		t.Fatal("invalid dial accepted")
	}
	if err := (&Server{}).Serve(nil); err == nil {
		t.Fatal("incomplete server accepted")
	}
	if err := (&Server{}).ServeConn(nil, nil); err == nil {
		t.Fatal("incomplete server connection accepted")
	}
	if _, err := ServiceCredentials(context.Background(), nil, nil, "", ""); err == nil {
		t.Fatal("incomplete service credential request accepted")
	}
	if err := contextError(nil); err == nil {
		t.Fatal("nil context accepted")
	}
	if err := contextError(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := hostAddress(nil); got.AddrType != 0 || len(got.Address) != 0 {
		t.Fatalf("nil address = %#v", got)
	}
	if err := checkError(nil); err != nil {
		t.Fatal(err)
	}
	if err := checkError([]byte("not an error")); err != nil {
		t.Fatal(err)
	}
	errText := "replication failed\x00"
	errorDER, err := asn1.Marshal(protocol.KRBError{
		PVNO: 5, MsgType: 30, STime: types.KerberosTime{Time: time.Unix(1, 0), Present: true},
		ErrorCode: 60, Realm: "TEST",
		SName: protocol.PrincipalName{NameType: 2, NameString: []string{"host", "replica"}},
		EText: &errText,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := checkError(errorDER); !errors.Is(err, ErrRemote) || !strings.Contains(err.Error(), "replication failed") {
		t.Fatalf("remote error = %v", err)
	}
	if _, _, err := decodeDatabaseSize([]byte{1}); err == nil {
		t.Fatal("short database size accepted")
	}
	key := &protocol.EncryptionKey{KeyType: 999, KeyValue: []byte{1}}
	if _, err := makeSafe(key, []byte("x"), 1, protocol.HostAddress{}); err == nil {
		t.Fatal("unknown safe enctype accepted")
	}
	if _, _, err := makePriv(key, []byte("x"), 1, protocol.HostAddress{}, make([]byte, 16)); err == nil {
		t.Fatal("unknown priv enctype accepted")
	}
	var short strings.Builder
	if err := writeAll(&short, []byte("abc")); err != nil || short.String() != "abc" {
		t.Fatal("writeAll failed")
	}
	if err := writeAll(zeroWriter{}, []byte{1}); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("zero writer error = %v", err)
	}
	for _, id := range []int32{crypto.EnctypeAES128SHA1, crypto.EnctypeAES256SHA1,
		crypto.EnctypeAES128SHA256, crypto.EnctypeAES256SHA384,
		crypto.EnctypeCamellia128, crypto.EnctypeCamellia256} {
		if checksumType(id) == 0 {
			t.Fatalf("missing checksum mapping for %d", id)
		}
	}
	if checksumType(999) != 0 {
		t.Fatal("unknown checksum mapping accepted")
	}
	for _, address := range []net.Addr{
		&net.TCPAddr{IP: net.ParseIP("127.0.0.1")},
		&net.UDPAddr{IP: net.ParseIP("2001:db8::1")},
	} {
		if got := hostAddress(address); len(got.Address) == 0 {
			t.Fatalf("address %v not encoded", address)
		}
	}
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	go func() { _ = writeContextByte(context.Background(), left, 7) }()
	if got, err := readContextByte(context.Background(), right); err != nil || got != 7 {
		t.Fatalf("context byte = %d/%v", got, err)
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], maxFrameSize+1)
	go func() { _, _ = left.Write(header[:]) }()
	if _, err := readContextFrame(context.Background(), right); err == nil {
		t.Fatal("oversized frame accepted")
	}
	errorDone := make(chan error, 1)
	go func() { errorDone <- (&Server{}).writeError(context.Background(), left, 200, "bad") }()
	if _, err := readContextFrame(context.Background(), right); err != nil {
		t.Fatalf("error frame unreadable: %v", err)
	}
	if err := <-errorDone; err != nil {
		t.Fatal(err)
	}
}

type zeroWriter struct{}

func (zeroWriter) Write([]byte) (int, error) { return 0, nil }
