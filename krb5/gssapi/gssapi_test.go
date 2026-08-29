package gssapi

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/Exonical/go-kerberos/krb5/ap"
	"github.com/Exonical/go-kerberos/krb5/asn1"
	"github.com/Exonical/go-kerberos/krb5/client"
	"github.com/Exonical/go-kerberos/krb5/crypto"
	krberrors "github.com/Exonical/go-kerberos/krb5/errors"
	"github.com/Exonical/go-kerberos/krb5/keytab"
	"github.com/Exonical/go-kerberos/krb5/principal"
	"github.com/Exonical/go-kerberos/krb5/protocol"
	"github.com/Exonical/go-kerberos/krb5/types"
)

func samePrincipal(left, right principal.Principal) bool {
	if left.Realm != right.Realm || left.NameType != right.NameType ||
		len(left.Components) != len(right.Components) {
		return false
	}
	for i := range left.Components {
		if left.Components[i] != right.Components[i] {
			return false
		}
	}
	return true
}

func mustMarshal(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := asn1.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func TestInitialTokenFraming(t *testing.T) {
	creds, kt := syntheticCredentials(t, crypto.EnctypeAES256SHA1)
	initiator, err := NewInitiator(creds, GSSMutualFlag|GSSIntegrityFlag)
	if err != nil {
		t.Fatal(err)
	}
	token, err := initiator.InitialToken(time.Unix(1700000000, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	if len(token) < 2 || token[0] != 0x60 || !bytes.Contains(token, append(append([]byte(nil), kerberosOID...), 0x01, 0x00)) {
		t.Fatalf("unexpected initial token framing: %x", token[:min(len(token), 16)])
	}
	_, mutual, err := NewAcceptor(kt).Accept(token, time.Unix(1700000000, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	if len(mutual) == 0 || !bytes.Contains(mutual, []byte{0x02, 0x00}) {
		t.Fatalf("missing AP-REP token id: %x", mutual)
	}
}

func TestKRBCredRoundTrip(t *testing.T) {
	creds, _ := syntheticCredentials(t, crypto.EnctypeAES256SHA1)
	start := types.KerberosTime{Time: creds.AuthTime.Time.Add(time.Minute), Present: true}
	renew := types.KerberosTime{Time: creds.EndTime.Time.Add(time.Hour), Present: true}
	creds.StartTime = &start
	creds.RenewTill = &renew
	creds.Flags = types.TicketForwarded
	key := &creds.Key
	encoded, err := MarshalKRBCred([]*client.Credentials{creds}, key, krbCredEncPartUsage)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := ReadKRBCred(encoded, key, krbCredEncPartUsage)
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 1 || !samePrincipal(decoded[0].Client, creds.Client) ||
		!samePrincipal(decoded[0].Server, creds.Server) ||
		!bytes.Equal(decoded[0].Key.KeyValue, creds.Key.KeyValue) ||
		!bytes.Equal(decoded[0].Ticket, creds.Ticket) ||
		decoded[0].Flags != creds.Flags || decoded[0].StartTime == nil ||
		decoded[0].RenewTill == nil {
		t.Fatalf("decoded KRB-CRED = %#v", decoded)
	}
	wrongKey := *key
	wrongKey.KeyValue = append([]byte(nil), key.KeyValue...)
	wrongKey.KeyValue[0] ^= 1
	if _, err := ReadKRBCred(encoded, &wrongKey, krbCredEncPartUsage); err == nil {
		t.Fatal("wrong KRB-CRED key unexpectedly succeeded")
	}
	plaintext, err := MarshalKRBCred([]*client.Credentials{creds}, nil, krbCredEncPartUsage)
	if err != nil {
		t.Fatal(err)
	}
	if decoded, err := ReadKRBCred(plaintext, nil, krbCredEncPartUsage); err != nil || len(decoded) != 1 {
		t.Fatalf("plaintext KRB-CRED decode = %#v, %v", decoded, err)
	}
}

func TestDelegatedCredentialsRoundTrip(t *testing.T) {
	creds, kt := syntheticCredentials(t, crypto.EnctypeAES256SHA1)
	now := time.Unix(1700000100, 0).UTC()
	tgt := *creds
	tgt.AuthTime = types.KerberosTime{Time: now, Present: true}
	tgt.EndTime = types.KerberosTime{Time: now.Add(time.Hour), Present: true}
	tgt.Server = principal.Principal{
		Realm: creds.Client.Realm, NameType: principal.NTSrvInstance,
		Components: []string{"krbtgt", creds.Client.Realm},
	}
	forwarded := *creds
	forwarded.AuthTime = tgt.AuthTime
	forwarded.EndTime = tgt.EndTime
	forwarded.Server = tgt.Server
	forwarded.Flags |= types.TicketForwarded
	kclient := &client.Client{
		Now: func() time.Time { return now },
		Exchange: func(_ context.Context, _ string, payload []byte) ([]byte, error) {
			var request protocol.TGSReq
			if err := asn1.Unmarshal(payload, &request); err != nil {
				return nil, err
			}
			if request.ReqBody.KDCOptions&types.KDCForwarded == 0 {
				t.Fatal("forwarded request missing KDCForwarded")
			}
			if len(request.ReqBody.Addresses) != 0 {
				t.Fatalf("forwarded request addresses = %#v, want omitted", request.ReqBody.Addresses)
			}
			return forwardedTGSReply(t, request, forwarded), nil
		},
	}
	initiator, err := NewInitiatorWithDelegationClient(creds, &tgt, kclient, GSSDelegFlag)
	if err != nil {
		t.Fatal(err)
	}
	token, err := initiator.InitialToken(now)
	if err != nil {
		t.Fatal(err)
	}
	acceptor := NewAcceptor(kt)
	context, _, _, err := acceptor.accept(token, now)
	if err != nil {
		t.Fatal(err)
	}
	if context == nil || len(context.DelegatedCredentials) != 1 {
		t.Fatalf("delegated credentials = %#v", context)
	}
}

func forwardedTGSReply(t *testing.T, request protocol.TGSReq, credentials client.Credentials) []byte {
	t.Helper()
	etype, err := crypto.NewRegistry().Get(credentials.Key.KeyType)
	if err != nil {
		t.Fatal(err)
	}
	part, err := asn1.Marshal(protocol.EncTGSRepPart{
		Key:      credentials.Key,
		Flags:    credentials.Flags,
		Nonce:    request.ReqBody.Nonce,
		AuthTime: credentials.AuthTime,
		EndTime:  credentials.EndTime,
		SRealm:   credentials.Server.Realm,
		SName: protocol.PrincipalName{
			NameType:   int32(credentials.Server.NameType),
			NameString: credentials.Server.Components,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := etype.Encrypt(credentials.Key.KeyValue, 8, part)
	if err != nil {
		t.Fatal(err)
	}
	return mustMarshal(t, protocol.TGSRep{
		PVNO: 5, MsgType: 13, CRealm: credentials.Client.Realm,
		CName: protocol.PrincipalName{
			NameType:   int32(credentials.Client.NameType),
			NameString: credentials.Client.Components,
		},
		Ticket: protocol.Ticket{
			TktVNO: 5, Realm: credentials.Server.Realm,
			SName: protocol.PrincipalName{
				NameType:   int32(credentials.Server.NameType),
				NameString: credentials.Server.Components,
			},
			EncPart: protocol.EncryptedData{EType: credentials.Key.KeyType, Cipher: []byte{2}},
		},
		EncPart: protocol.EncryptedData{EType: credentials.Key.KeyType, Cipher: cipher},
	})
}

func TestContextAndPerMessageRoundTrip(t *testing.T) {
	for _, etypeID := range []int32{
		crypto.EnctypeAES128SHA1, crypto.EnctypeAES256SHA1,
		crypto.EnctypeAES128SHA256, crypto.EnctypeAES256SHA384,
	} {
		t.Run(cryptoName(etypeID), func(t *testing.T) {
			creds, kt := syntheticCredentials(t, etypeID)
			now := time.Unix(1700000000+int64(etypeID), 0).UTC()
			initiator, err := NewInitiator(creds, GSSMutualFlag|GSSIntegrityFlag|GSSConfidentialityFlag)
			if err != nil {
				t.Fatal(err)
			}
			token, err := initiator.InitialToken(now)
			if err != nil {
				t.Fatal(err)
			}
			acceptor := NewAcceptor(kt)
			acceptorContext, mutual, err := acceptor.Accept(token, now)
			if err != nil {
				t.Fatal(err)
			}
			if err := initiator.VerifyToken(mutual); err != nil {
				t.Fatal(err)
			}
			if initiator.ctx.acceptorSubkey {
				t.Fatal("initiator treated its subkey as an acceptor subkey")
			}
			plain := []byte("gss-api sealed message")
			wrapped, err := initiator.Wrap(plain, true)
			if err != nil {
				t.Fatal(err)
			}
			if got, want := binary.BigEndian.Uint64(wrapped[8:16]), sequenceValue(initiator.state.SeqNumber); got != want {
				t.Fatalf("initiator token sequence = %d, want %d", got, want)
			}
			if wrapped[2]&tokenFlagAcceptorSubkey != 0 {
				t.Fatal("initiator token asserted an acceptor subkey")
			}
			got, err := acceptorContext.Unwrap(wrapped)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, plain) {
				t.Fatalf("unwrapped = %q, want %q", got, plain)
			}
			unsealed, err := initiator.Wrap(plain, false)
			if err != nil {
				t.Fatal(err)
			}
			got, err = acceptorContext.Unwrap(unsealed)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, plain) {
				t.Fatalf("unwrapped integrity token = %q, want %q", got, plain)
			}
			mic, err := initiator.MIC(plain)
			if err != nil {
				t.Fatal(err)
			}
			if err := acceptorContext.VerifyMIC(plain, mic); err != nil {
				t.Fatal(err)
			}
			reply, err := acceptorContext.Wrap(plain, false)
			if err != nil {
				t.Fatal(err)
			}
			if got := binary.BigEndian.Uint64(reply[8:16]); got != 0 {
				t.Fatalf("acceptor token sequence = %d, want 0", got)
			}
			if _, err := initiator.Unwrap(reply); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestVerifyAPRepSeedsAcceptorSequenceAndTracksSubkey(t *testing.T) {
	creds, _ := syntheticCredentials(t, crypto.EnctypeAES256SHA1)
	now := time.Unix(1700001000, 0).UTC()
	initiator, err := NewInitiator(creds, GSSMutualFlag|GSSIntegrityFlag)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := initiator.InitialToken(now); err != nil {
		t.Fatal(err)
	}
	seq := uint32(17)
	apRep := buildGSSAPRep(t, initiator.state, nil, &seq)
	if err := initiator.VerifyToken(frameToken([]byte{0x02, 0x00}, apRep)); err != nil {
		t.Fatal(err)
	}
	if initiator.ctx.recvSeq != uint64(seq) {
		t.Fatalf("initiator receive sequence = %d, want %d", initiator.ctx.recvSeq, seq)
	}
	if initiator.ctx.acceptorSubkey {
		t.Fatal("initiator treated its own subkey as an acceptor subkey")
	}

	acceptorSubkey := &protocol.EncryptionKey{
		KeyType:  crypto.EnctypeAES256SHA1,
		KeyValue: bytes.Repeat([]byte{0x73}, 32),
	}
	apRep = buildGSSAPRep(t, initiator.state, acceptorSubkey, nil)
	if err := initiator.VerifyToken(frameToken([]byte{0x02, 0x00}, apRep)); err != nil {
		t.Fatal(err)
	}
	if !initiator.ctx.acceptorSubkey || !bytes.Equal(initiator.ctx.key.KeyValue, acceptorSubkey.KeyValue) {
		t.Fatal("initiator did not adopt the asserted acceptor subkey")
	}
}

func TestPerMessageRejectsTamperingDirectionAndReplay(t *testing.T) {
	creds, kt := syntheticCredentials(t, crypto.EnctypeAES256SHA1)
	now := time.Unix(1700010000, 0).UTC()
	initiator, err := NewInitiator(creds, GSSMutualFlag|GSSIntegrityFlag)
	if err != nil {
		t.Fatal(err)
	}
	token, err := initiator.InitialToken(now)
	if err != nil {
		t.Fatal(err)
	}
	acceptorContext, mutual, err := NewAcceptor(kt).Accept(token, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := initiator.VerifyToken(mutual); err != nil {
		t.Fatal(err)
	}
	wrapped, err := initiator.Wrap([]byte("message"), false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := acceptorContext.Unwrap(append([]byte(nil), wrapped...)); err != nil {
		t.Fatal(err)
	}
	if _, err := acceptorContext.Unwrap(wrapped); err == nil {
		t.Fatal("replayed token unexpectedly accepted")
	}
	next, err := initiator.Wrap([]byte("tamper"), false)
	if err != nil {
		t.Fatal(err)
	}
	tampered := append([]byte(nil), next...)
	tampered[len(tampered)-1] ^= 1
	if _, err := acceptorContext.Unwrap(tampered); err == nil || !isIntegrity(err) {
		t.Fatalf("tampered token error = %v", err)
	}
	if _, err := initiator.Unwrap(wrapped); err == nil {
		t.Fatal("wrong direction token unexpectedly accepted")
	}
}

func buildGSSAPRep(t *testing.T, request *ap.APReq, subkey *protocol.EncryptionKey, sequence *uint32) []byte {
	t.Helper()
	part := protocol.EncAPRepPart{
		Ctime:     types.KerberosTime{Time: request.AuthenticatorTime, Microseconds: request.Cusec, Present: true},
		Cusec:     request.Cusec,
		SubKey:    subkey,
		SeqNumber: sequence,
	}
	plain, err := asn1.Marshal(part)
	if err != nil {
		t.Fatal(err)
	}
	etype, err := crypto.NewRegistry().Get(request.SessionKey.KeyType)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := etype.Encrypt(request.SessionKey.KeyValue, 12, plain)
	if err != nil {
		t.Fatal(err)
	}
	der, err := asn1.Marshal(protocol.APRep{
		PVNO: 5, MsgType: 15,
		EncPart: protocol.EncryptedData{EType: request.SessionKey.KeyType, Cipher: ciphertext},
	})
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestPerMessageRRCIsRotatedOnReceive(t *testing.T) {
	creds, kt := syntheticCredentials(t, crypto.EnctypeAES128SHA1)
	now := time.Unix(1700020000, 0).UTC()
	initiator, err := NewInitiator(creds, GSSMutualFlag|GSSIntegrityFlag)
	if err != nil {
		t.Fatal(err)
	}
	token, err := initiator.InitialToken(now)
	if err != nil {
		t.Fatal(err)
	}
	acceptorContext, mutual, err := NewAcceptor(kt).Accept(token, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := initiator.VerifyToken(mutual); err != nil {
		t.Fatal(err)
	}
	wrapped, err := initiator.Wrap([]byte("rotation"), false)
	if err != nil {
		t.Fatal(err)
	}
	rotated := rotateTokenData(t, wrapped, 3)
	plain, err := acceptorContext.Unwrap(rotated)
	if err != nil {
		t.Fatal(err)
	}
	if string(plain) != "rotation" {
		t.Fatalf("rotated token payload = %q", plain)
	}
}

func TestRFC4121PerMessageTokenLayouts(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	etype, err := crypto.NewRegistry().Get(crypto.EnctypeAES256SHA1)
	if err != nil {
		t.Fatal(err)
	}
	restore := crypto.SetRandomSource(bytes.NewReader(bytes.Repeat([]byte{0xa5}, 16)))
	defer restore()

	sealedContext := &Context{
		key:       protocol.EncryptionKey{KeyType: crypto.EnctypeAES256SHA1, KeyValue: key},
		initiator: true,
	}
	sealed, err := sealedContext.Wrap([]byte("golden"), true)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(sealed[:16]); got != "050402ff000000000000000000000000" {
		t.Fatalf("sealed header = %s", got)
	}
	if got := hex.EncodeToString(sealed); got != "050402ff000000000000000000000000baa4162f84bc1b8a4672581ac3000dfa15a3628d7479ed990b15db1dc619f7775a12f6e98f33aa18f4e48d0bf82f7a845942" {
		t.Fatalf("sealed token = %s", got)
	}
	decrypted, err := etype.Decrypt(key, 24, sealed[16:])
	if err != nil {
		t.Fatal(err)
	}
	wantSealedPlaintext := append([]byte("golden"), sealed[:16]...)
	if !bytes.Equal(decrypted, wantSealedPlaintext) {
		t.Fatalf("sealed plaintext = %x, want %x", decrypted, wantSealedPlaintext)
	}
	micContext := &Context{
		key:       protocol.EncryptionKey{KeyType: crypto.EnctypeAES256SHA1, KeyValue: key},
		initiator: true,
	}
	mic, err := micContext.MIC([]byte("golden"))
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(mic[:16]); got != "040400ffffffffff0000000000000000" {
		t.Fatalf("MIC header = %s", got)
	}
	if got := hex.EncodeToString(mic); got != "040400ffffffffff0000000000000000a0eb91295c829986e1b4607c" {
		t.Fatalf("MIC token = %s", got)
	}
	wantMICHeader := append([]byte("golden"), mic[:16]...)
	wantMIC, err := etype.Checksum(key, 25, wantMICHeader)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(mic[16:], wantMIC) {
		t.Fatalf("MIC checksum = %x, want %x", mic[16:], wantMIC)
	}
}

func syntheticCredentials(t *testing.T, etypeID int32) (*client.Credentials, *keytab.Keytab) {
	t.Helper()
	etype, err := crypto.NewRegistry().Get(etypeID)
	if err != nil {
		t.Fatal(err)
	}
	clientPrincipal := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTPrincipal, Components: []string{"alice"}}
	servicePrincipal := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTSrvInstance, Components: []string{"host", "service.test"}}
	sessionKey := bytes.Repeat([]byte{0x31}, etype.KeySize())
	serviceKey := bytes.Repeat([]byte{0x52}, etype.KeySize())
	now := time.Unix(1700000000, 0).UTC()
	end := types.KerberosTime{Time: time.Unix(2000000000, 0).UTC(), Present: true}
	ticketPart, err := asn1.Marshal(protocol.EncTicketPart{
		Key:      protocol.EncryptionKey{KeyType: etypeID, KeyValue: sessionKey},
		CRealm:   clientPrincipal.Realm,
		CName:    protocol.PrincipalName{NameType: int32(clientPrincipal.NameType), NameString: clientPrincipal.Components},
		AuthTime: types.KerberosTime{Time: now, Present: true},
		EndTime:  end,
	})
	if err != nil {
		t.Fatal(err)
	}
	ticketCipher, err := etype.Encrypt(serviceKey, 2, ticketPart)
	if err != nil {
		t.Fatal(err)
	}
	kvno := uint32(2)
	ticket, err := asn1.Marshal(protocol.Ticket{
		TktVNO: 5, Realm: servicePrincipal.Realm,
		SName:   protocol.PrincipalName{NameType: int32(servicePrincipal.NameType), NameString: servicePrincipal.Components},
		EncPart: protocol.EncryptedData{EType: etypeID, KVNO: &kvno, Cipher: ticketCipher},
	})
	if err != nil {
		t.Fatal(err)
	}
	return &client.Credentials{
			Client: clientPrincipal, Server: servicePrincipal,
			Key:      protocol.EncryptionKey{KeyType: etypeID, KeyValue: sessionKey},
			AuthTime: types.KerberosTime{Time: now, Present: true}, EndTime: end, Ticket: ticket,
		}, &keytab.Keytab{Entries: []keytab.Entry{{
			Principal: servicePrincipal, KVNO: kvno, Enctype: etypeID, Key: serviceKey,
		}}}
}

func rotateTokenData(t *testing.T, token []byte, rrc int) []byte {
	t.Helper()
	if len(token) < 16 {
		t.Fatal("short token")
	}
	rotated := append([]byte(nil), token...)
	binary.BigEndian.PutUint16(rotated[6:8], uint16(rrc))
	data := append([]byte(nil), rotated[16:]...)
	rrc %= len(data)
	copy(rotated[16:], append(data[len(data)-rrc:], data[:len(data)-rrc]...))
	return rotated
}

func isIntegrity(err error) bool {
	return errors.Is(err, krberrors.ErrIntegrity)
}

func cryptoName(id int32) string {
	switch id {
	case crypto.EnctypeAES128SHA1:
		return "aes128-sha1"
	case crypto.EnctypeAES256SHA1:
		return "aes256-sha1"
	case crypto.EnctypeAES128SHA256:
		return "aes128-sha256"
	default:
		return "aes256-sha384"
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
