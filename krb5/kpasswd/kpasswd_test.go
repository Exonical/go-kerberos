package kpasswd

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
	"time"

	"github.com/Exonical/go-kerberos/krb5/ap"
	"github.com/Exonical/go-kerberos/krb5/asn1"
	"github.com/Exonical/go-kerberos/krb5/crypto"
	"github.com/Exonical/go-kerberos/krb5/protocol"
	"github.com/Exonical/go-kerberos/krb5/types"
)

func testKpasswdState(now time.Time) *ap.APReq {
	session := protocol.EncryptionKey{KeyType: crypto.EnctypeAES256SHA1, KeyValue: bytes.Repeat([]byte{0x11}, 32)}
	subkey := protocol.EncryptionKey{KeyType: crypto.EnctypeAES256SHA1, KeyValue: bytes.Repeat([]byte{0x22}, 32)}
	seq := uint32(0x10203040)
	return &ap.APReq{
		SessionKey:        session,
		AuthenticatorTime: now,
		Cusec:             123456,
		SubKey:            &subkey,
		SeqNumber:         &seq,
		APOptions:         types.APMutualRequired,
	}
}

func TestBuildPasswordChangePacket(t *testing.T) {
	packet, err := buildPasswordChangePacket([]byte{0xaa, 0xbb}, []byte{0xcc, 0xdd, 0xee})
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0, 11, 0, 1, 0, 2, 0xaa, 0xbb, 0xcc, 0xdd, 0xee}
	if !bytes.Equal(packet, want) {
		t.Fatalf("packet = %x, want %x", packet, want)
	}
	if got := int(binary.BigEndian.Uint16(packet[:2])); got != len(packet) {
		t.Fatalf("length = %d, want %d", got, len(packet))
	}
}

func TestBuildKRBPrivRoundTrip(t *testing.T) {
	now := time.Date(2026, 4, 5, 6, 7, 8, 0, time.UTC)
	state := testKpasswdState(now)
	der, err := buildKRBPriv(state, []byte("new-password"), now)
	if err != nil {
		t.Fatal(err)
	}
	var priv protocol.KRBPriv
	if err := asn1.Unmarshal(der, &priv); err != nil {
		t.Fatal(err)
	}
	if priv.PVNO != 5 || priv.MsgType != 21 || priv.EncPart.EType != crypto.EnctypeAES256SHA1 {
		t.Fatalf("KRB-PRIV header = %#v", priv)
	}
	etype, err := crypto.NewRegistry().Get(state.SubKey.KeyType)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := etype.Decrypt(state.SubKey.KeyValue, kpasswdPrivUsage, priv.EncPart.Cipher)
	if err != nil {
		t.Fatal(err)
	}
	var part protocol.EncKRBPrivPart
	if err := asn1.Unmarshal(plain, &part); err != nil {
		t.Fatal(err)
	}
	if string(part.UserData) != "new-password" || part.SeqNumber == nil ||
		*part.SeqNumber != *state.SeqNumber || !part.Timestamp.Present {
		t.Fatalf("encrypted part = %#v", part)
	}
}

func TestParsePasswordChangeReply(t *testing.T) {
	now := time.Date(2026, 4, 5, 6, 7, 8, 0, time.UTC)
	state := testKpasswdState(now)
	apRep := testAPRep(t, state)
	priv, err := buildKRBPriv(state, []byte{0, 0}, now)
	if err != nil {
		t.Fatal(err)
	}
	packet := make([]byte, 6+len(apRep)+len(priv))
	binary.BigEndian.PutUint16(packet[:2], uint16(len(packet)))
	binary.BigEndian.PutUint16(packet[2:4], kpasswdVersion)
	binary.BigEndian.PutUint16(packet[4:6], uint16(len(apRep)))
	copy(packet[6:], apRep)
	copy(packet[6+len(apRep):], priv)
	result, err := parsePasswordChangeReply(packet, state, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if result.Code != 0 || result.Message != "" {
		t.Fatalf("result = %#v", result)
	}
}

func TestParsePasswordChangeReplyRejectsMalformed(t *testing.T) {
	now := time.Now().UTC()
	state := testKpasswdState(now)
	tests := []struct {
		name string
		data []byte
	}{
		{"truncated", []byte{0, 6}},
		{"bad length", []byte{0, 7, 0, 1, 0, 0}},
		{"bad version", []byte{0, 6, 0, 2, 0, 0}},
		{"missing APREP", []byte{0, 6, 0, 1, 0, 0}},
		{"truncated APREP", []byte{0, 8, 0, 1, 0, 3, 1, 2}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := parsePasswordChangeReply(test.data, state, now, time.Minute); err == nil {
				t.Fatal("parse unexpectedly succeeded")
			}
		})
	}
}

func TestParsePasswordChangeReplyErrors(t *testing.T) {
	now := time.Now().UTC()
	errDER, err := asn1.Marshal(protocol.KRBError{
		PVNO: 5, MsgType: 30, STime: types.KerberosTime{Time: now, Present: true},
		Susec: 0, ErrorCode: 25, Realm: "TEST.REALM",
		SName: protocol.PrincipalName{NameType: 2, NameString: []string{"kadmin", "changepw"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parsePasswordChangeReply(errDER, testKpasswdState(now), now, time.Minute); err == nil ||
		!strings.Contains(err.Error(), "KRB-ERROR") {
		t.Fatalf("error = %v", err)
	}
}

func TestParsePasswordChangeReplyRejectsStaleResult(t *testing.T) {
	now := time.Now().UTC()
	state := testKpasswdState(now)
	priv, err := buildKRBPriv(state, []byte{0, 0}, now.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	packet := framedReply(t, state, priv)
	if _, err := parsePasswordChangeReply(packet, state, now, time.Minute); err == nil {
		t.Fatal("stale result unexpectedly succeeded")
	}
}

func TestParsePasswordChangeReplyRejectsMissingReplayData(t *testing.T) {
	now := time.Now().UTC()
	state := testKpasswdState(now)
	priv, err := buildKRBPrivWithoutReplay(state, []byte{0, 0})
	if err != nil {
		t.Fatal(err)
	}
	packet := framedReply(t, state, priv)
	if _, err := parsePasswordChangeReply(packet, state, now, time.Minute); err == nil {
		t.Fatal("reply without replay data unexpectedly succeeded")
	}
}

func TestParsePasswordChangeReplyRejectsResultCode(t *testing.T) {
	now := time.Now().UTC()
	state := testKpasswdState(now)
	priv, err := buildKRBPriv(state, []byte{0, 4, 'p', 'o', 'l', 'i', 'c', 'y'}, now)
	if err != nil {
		t.Fatal(err)
	}
	packet := framedReply(t, state, priv)
	result, err := parsePasswordChangeReply(packet, state, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if result.Code != 4 || result.Message != "policy" {
		t.Fatalf("result = %#v", result)
	}
}

func testAPRep(t *testing.T, state *ap.APReq) []byte {
	t.Helper()
	etype, err := crypto.NewRegistry().Get(state.SessionKey.KeyType)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := asn1.Marshal(protocol.EncAPRepPart{
		Ctime: types.KerberosTime{Time: state.AuthenticatorTime, Present: true},
		Cusec: state.Cusec,
	})
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := etype.Encrypt(state.SessionKey.KeyValue, 12, plain)
	if err != nil {
		t.Fatal(err)
	}
	der, err := asn1.Marshal(protocol.APRep{
		PVNO: 5, MsgType: 15,
		EncPart: protocol.EncryptedData{EType: state.SessionKey.KeyType, Cipher: cipher},
	})
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func framedReply(t *testing.T, state *ap.APReq, priv []byte) []byte {
	t.Helper()
	apRep := testAPRep(t, state)
	packet := make([]byte, 6+len(apRep)+len(priv))
	binary.BigEndian.PutUint16(packet[:2], uint16(len(packet)))
	binary.BigEndian.PutUint16(packet[2:4], kpasswdVersion)
	binary.BigEndian.PutUint16(packet[4:6], uint16(len(apRep)))
	copy(packet[6:], apRep)
	copy(packet[6+len(apRep):], priv)
	return packet
}

func buildKRBPrivWithoutReplay(state *ap.APReq, userData []byte) ([]byte, error) {
	key := state.SubKey
	if key == nil {
		key = &state.SessionKey
	}
	etype, err := crypto.NewRegistry().Get(key.KeyType)
	if err != nil {
		return nil, err
	}
	plaintext, err := asn1.Marshal(protocol.EncKRBPrivPart{
		UserData: userData,
		SAddress: protocol.HostAddress{},
	})
	if err != nil {
		return nil, err
	}
	ciphertext, err := etype.Encrypt(key.KeyValue, kpasswdPrivUsage, plaintext)
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(protocol.KRBPriv{
		PVNO: 5, MsgType: 21,
		EncPart: protocol.EncryptedData{EType: key.KeyType, Cipher: ciphertext},
	})
}
