package kprop

import (
	"bytes"
	"context"
	"encoding/hex"
	"io"
	"net"
	"testing"
	"time"

	"github.com/Exonical/go-kerberos/krb5/asn1"
	"github.com/Exonical/go-kerberos/krb5/client"
	"github.com/Exonical/go-kerberos/krb5/crypto"
	"github.com/Exonical/go-kerberos/krb5/keytab"
	"github.com/Exonical/go-kerberos/krb5/principal"
	"github.com/Exonical/go-kerberos/krb5/protocol"
	"github.com/Exonical/go-kerberos/krb5/types"
)

func TestDatabaseSizeEncoding(t *testing.T) {
	tests := []struct {
		size uint64
		hex  string
	}{
		{0, "000000000000000000000000"},
		{1, "00000001"},
		{^uint64(0) >> 32, "ffffffff"},
		{uint64(1) << 32, "000000000000000100000000"},
	}
	for _, test := range tests {
		encoded := EncodeDatabaseSize(test.size)
		if got := hex.EncodeToString(encoded); got != test.hex {
			t.Fatalf("size %d encoded %s, want %s", test.size, got, test.hex)
		}
		got, err := DecodeDatabaseSize(encoded)
		if err != nil || got != test.size {
			t.Fatalf("size %d decoded %d (%v)", test.size, got, err)
		}
	}
	if _, err := DecodeDatabaseSize([]byte{0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0}); err == nil {
		t.Fatal("nonzero extended prefix accepted")
	}
	if _, err := DecodeDatabaseSize([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}); err == nil {
		t.Fatal("noncanonical extended size accepted")
	}
}

func TestKRBSafeGolden(t *testing.T) {
	seq := uint32(7)
	value := protocol.KRBSafe{
		PVNO: 5, MsgType: 20,
		SafeBody: protocol.SafeBody{
			UserData: []byte{1, 2, 3}, SeqNumber: &seq,
			SAddress: protocol.HostAddress{AddrType: 2, Address: []byte{127, 0, 0, 1}},
		},
		Checksum: protocol.Checksum{ChecksumType: 15, Checksum: []byte{4, 5, 6}},
	}
	got, err := asn1.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := hex.DecodeString("743d303ba003020105a103020114a21f301da0050403010203a303020107a40f300da003020102a10604047f000001a30e300ca00302010fa1050403040506")
	if !bytes.Equal(got, want) {
		t.Fatalf("DER = %x, want %x", got, want)
	}
	var decoded protocol.KRBSafe
	if err := asn1.Unmarshal(got, &decoded); err != nil {
		t.Fatal(err)
	}
}

func TestChainedAESState(t *testing.T) {
	for _, id := range []int32{
		crypto.EnctypeAES128SHA1, crypto.EnctypeAES256SHA1,
		crypto.EnctypeAES128SHA256, crypto.EnctypeAES256SHA384,
	} {
		etype, err := crypto.NewRegistry().Get(id)
		if err != nil {
			t.Fatal(err)
		}
		key := bytes.Repeat([]byte{byte(id)}, etype.KeySize())
		iv := make([]byte, 16)
		first, next, err := crypto.EncryptWithIV(etype, key, PrivUsage, []byte("first message"), iv)
		if err != nil {
			t.Fatalf("etype %d first encrypt: %v", id, err)
		}
		second, next2, err := crypto.EncryptWithIV(etype, key, PrivUsage, []byte("second message"), next)
		if err != nil {
			t.Fatalf("etype %d second encrypt: %v", id, err)
		}
		plain, gotNext, err := crypto.DecryptWithIV(etype, key, PrivUsage, first, iv)
		if err != nil || string(plain) != "first message" || !bytes.Equal(gotNext, next) {
			t.Fatalf("etype %d first decrypt: %q %x (%v)", id, plain, gotNext, err)
		}
		plain, gotNext, err = crypto.DecryptWithIV(etype, key, PrivUsage, second, gotNext)
		if err != nil || string(plain) != "second message" || !bytes.Equal(gotNext, next2) {
			t.Fatalf("etype %d second decrypt: %q %x (%v)", id, plain, gotNext, err)
		}
		if id == crypto.EnctypeAES128SHA256 || id == crypto.EnctypeAES256SHA384 {
			if bytes.Equal(next, make([]byte, 16)) {
				t.Fatalf("etype %d chaining state unexpectedly remained zero", id)
			}
			if _, _, err := crypto.DecryptWithIV(etype, key, PrivUsage, second, make([]byte, 16)); err == nil {
				t.Fatalf("etype %d accepted second message with wrong IV", id)
			}
		}
	}
}

func TestFramingPreservesEmptyFrame(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	done := make(chan error, 1)
	go func() {
		done <- WriteFrame(context.Background(), left, nil)
	}()
	got, err := ReadFrame(context.Background(), right)
	if err != nil || len(got) != 0 {
		t.Fatalf("empty frame = %x (%v)", got, err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestGoClientServerTransfer(t *testing.T) {
	const realm = "TEST.LOCAL"
	service := principal.Principal{Realm: realm, NameType: principal.NTSrvInstance, Components: []string{"host", "replica"}}
	user := principal.Principal{Realm: realm, NameType: principal.NTEnterprise, Components: []string{"master"}}
	etype, _ := crypto.NewRegistry().Get(crypto.EnctypeAES256SHA1)
	serviceKey := bytes.Repeat([]byte{0x31}, etype.KeySize())
	sessionKey := bytes.Repeat([]byte{0x42}, etype.KeySize())
	now := time.Now().UTC()
	end := types.KerberosTime{Time: now.Add(time.Hour), Present: true}
	ticketPart := protocol.EncTicketPart{
		Flags: types.TicketInitial, Key: protocol.EncryptionKey{KeyType: etype.ID(), KeyValue: sessionKey},
		CRealm: realm, CName: protocol.PrincipalName{NameType: int32(user.NameType), NameString: user.Components},
		AuthTime: types.KerberosTime{Time: now, Present: true}, EndTime: end,
	}
	ticketPlain, err := asn1.Marshal(ticketPart)
	if err != nil {
		t.Fatal(err)
	}
	ticketCipher, err := etype.Encrypt(serviceKey, 2, ticketPlain)
	if err != nil {
		t.Fatal(err)
	}
	ticketDER, err := asn1.Marshal(protocol.Ticket{TktVNO: 5, Realm: realm,
		SName:   protocol.PrincipalName{NameType: int32(service.NameType), NameString: service.Components},
		EncPart: protocol.EncryptedData{EType: etype.ID(), Cipher: ticketCipher}})
	if err != nil {
		t.Fatal(err)
	}
	creds := &client.Credentials{Client: user, Server: service,
		Key: protocol.EncryptionKey{KeyType: etype.ID(), KeyValue: sessionKey}, Ticket: ticketDER}
	payload := bytes.Repeat([]byte("kprop"), 10000)
	var loaded []byte
	server := &Server{
		Keytab: &keytab.Keytab{Entries: []keytab.Entry{{Principal: service, KVNO: 1, Enctype: etype.ID(), Key: serviceKey}}},
		Realm:  realm,
		Authorize: func(got principal.Principal) error {
			if got.String() != user.String() {
				t.Fatalf("authorized principal = %s", got)
			}
			return nil
		},
		Load: func(r io.Reader, size uint64) error {
			var err error
			loaded, err = io.ReadAll(r)
			if err != nil {
				return err
			}
			if uint64(len(loaded)) != size {
				t.Fatalf("load size = %d, want %d", len(loaded), size)
			}
			return nil
		},
	}
	left, right := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- server.ServeConn(context.Background(), right) }()
	if err := Send(context.Background(), left, creds, bytes.NewReader(payload), uint64(len(payload))); err != nil {
		t.Fatal(err)
	}
	_ = left.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(loaded, payload) {
		t.Fatalf("loaded payload mismatch: %d vs %d", len(loaded), len(payload))
	}
}
