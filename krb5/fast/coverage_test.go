package fast

import (
	"bytes"
	"testing"
	"time"

	"github.com/Exonical/go-kerberos/krb5/crypto"
	"github.com/Exonical/go-kerberos/krb5/protocol"
)

func TestFASTValidationAndReplyKey(t *testing.T) {
	etype, err := crypto.NewRegistry().Get(crypto.EnctypeAES128SHA1)
	if err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{1}, etype.KeySize())
	armor := &Armor{EType: etype, Key: key}
	if _, err := NewArmor(TGT{}, time.Unix(0, 0)); err == nil {
		t.Fatal("incomplete armor TGT accepted")
	}
	if _, err := NewTGSArmor(TGT{Key: protocol.EncryptionKey{KeyType: etype.ID(), KeyValue: key}},
		protocol.EncryptionKey{KeyType: crypto.EnctypeAES256SHA1, KeyValue: key}); err == nil {
		t.Fatal("mismatched TGS armor accepted")
	}
	if _, err := armor.WrapASReq(protocol.KDCReqBody{}, nil); err == nil {
		t.Fatal("armor without AP-REQ accepted")
	}
	if _, err := armor.WrapTGSReq(protocol.KDCReqBody{}, nil, nil); err == nil {
		t.Fatal("TGS armor without checksum data accepted")
	}
	reply, err := armor.ReplyKey(protocol.EncryptionKey{KeyType: etype.ID(), KeyValue: key}, nil)
	if err != nil || !bytes.Equal(reply.KeyValue, key) {
		t.Fatalf("plain reply key = %#v/%v", reply, err)
	}
	if _, err := armor.ReplyKey(protocol.EncryptionKey{KeyType: etype.ID(), KeyValue: key},
		&protocol.EncryptionKey{KeyType: crypto.EnctypeAES256SHA1, KeyValue: key}); err == nil {
		t.Fatal("mismatched strengthen key accepted")
	}
	strengthen := &protocol.EncryptionKey{KeyType: etype.ID(), KeyValue: bytes.Repeat([]byte{2}, etype.KeySize())}
	replyKey := protocol.EncryptionKey{KeyType: crypto.EnctypeAES256SHA1, KeyValue: bytes.Repeat([]byte{3}, 32)}
	derived, err := armor.ReplyKey(replyKey, strengthen)
	if err != nil || derived.KeyType != etype.ID() || len(derived.KeyValue) != etype.KeySize() {
		t.Fatalf("strengthened reply key = %#v/%v", derived, err)
	}
	for _, id := range []int32{
		crypto.EnctypeAES128SHA1, crypto.EnctypeAES256SHA1,
		crypto.EnctypeAES128SHA256, crypto.EnctypeAES256SHA384,
		crypto.EnctypeCamellia128, crypto.EnctypeCamellia256,
	} {
		if ChecksumType(id) == 0 {
			t.Fatalf("checksum mapping missing for enctype %d", id)
		}
	}
	if ChecksumType(999) != 0 {
		t.Fatal("unknown checksum mapping accepted")
	}
	restore := crypto.SetRandomSource(bytes.NewReader([]byte{0xff, 0xff, 0xff, 0xff}))
	if got := randomNonce(); got != 0x7fffffff {
		t.Fatalf("nonce = %08x", got)
	}
	restore()
	if _, err := (&Armor{}).UnwrapReply(nil, nil, 0); err == nil {
		t.Fatal("incomplete reply armor accepted")
	}
	if _, err := armor.UnwrapReply(nil, nil, 0); err == nil {
		t.Fatal("missing FAST reply accepted")
	}
}
