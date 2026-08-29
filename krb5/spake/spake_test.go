package spake

import (
	"encoding/hex"
	"testing"

	"github.com/Exonical/go-kerberos/krb5/asn1"
	"github.com/Exonical/go-kerberos/krb5/crypto"
	"github.com/Exonical/go-kerberos/krb5/protocol"
)

func mustHex(t *testing.T, value string) []byte {
	t.Helper()
	out, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestMITAES256EdwardsVector(t *testing.T) {
	etype, err := crypto.NewRegistry().Get(crypto.EnctypeAES256SHA1)
	if err != nil {
		t.Fatal(err)
	}
	initial := mustHex(t, "01B897121D933AB44B47EB5494DB15E50EB74530DBDAE9B634D65020FF5D88C1")
	w, err := DeriveW(etype, initial, GroupEdwards25519)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(w); got != "e902341590a1b4bb4d606a1c643cccb3f2108f1b6aa97b381012b9400c9e3f4e" {
		t.Fatalf("w = %s", got)
	}
	x := mustHex(t, "88C6C0A4F0241EF217C9788F02C32D00B72E4310748CD8FB5F94717607E6417D")
	y := mustHex(t, "88B859DF58EF5C69BACDFE681C582754EAAB09A74DC29CFF50B328613C232F55")
	tPub, err := KeygenWithPrivate(GroupEdwards25519, w, x, true)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(tPub); got != "6f301aacae1220e91be42868c163c5009aeea1e9d9e28afcfc339cda5e7105b5" {
		t.Fatalf("T = %s", got)
	}
	sPub, err := KeygenWithPrivate(GroupEdwards25519, w, y, false)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(sPub); got != "9e2cc32908fc46273279ec75354b4aeafa70c3d99a4d507175ed70d80b255dda" {
		t.Fatalf("S = %s", got)
	}
	k, err := Result(GroupEdwards25519, w, x, sPub, false)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(k); got != "cf57f58f6e60169d2ecc8f20bb923a8e4c16e5bc95b9e64b5dc870da7026321b" {
		t.Fatalf("K = %s", got)
	}
	k2, err := Result(GroupEdwards25519, w, y, tPub, true)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(k2) != hex.EncodeToString(k) {
		t.Fatalf("K mismatch")
	}
	body := mustHex(t, "3075A00703050000000000A1143012A003020101A10B30091B07726165627572"+
		"6EA2101B0E415448454E412E4D49542E454455A3233021A003020102A11A3018"+
		"1B066B72627467741B0E415448454E412E4D49542E454455A511180F31393730"+
		"303130313030303030305AA703020100A8053003020112")
	transcript := mustHex(t, "1C605649D4658B58CBE79A5FAF227ACC16C355C58B7DADE022F90C158FE5ED8E")
	support := mustHex(t, "A0093007A0053003020101")
	challenge := mustHex(t, "A1363034A003020101A12204206F301AACAE1220E91BE42868C163C5009AEEA1"+
		"E9D9E28AFCFC339CDA5E7105B5A20930073005A003020101")
	if got := Transcript(Transcript(nil, support, challenge), sPub, nil); hex.EncodeToString(got) != hex.EncodeToString(transcript) {
		t.Fatalf("transcript = %x", got)
	}
	k0, err := DeriveKey(etype, initial, w, k, transcript, body, GroupEdwards25519, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(k0); got != "a9bfa71c95c575756f922871524b65288b3f695573ccc0633e87449568210c23" {
		t.Fatalf("K'[0] = %s", got)
	}
}

func TestMITAES128WAndGroupVector(t *testing.T) {
	etype, err := crypto.NewRegistry().Get(crypto.EnctypeAES128SHA1)
	if err != nil {
		t.Fatal(err)
	}
	initial := mustHex(t, "FCA822951813FB252154C883F5EE1CF4")
	w, err := DeriveW(etype, initial, GroupEdwards25519)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(w); got != "0d591b197b667e083c2f5f98ac891d3c9f99e710e464e62f1fb7c9b67936f3eb" {
		t.Fatalf("w = %s", got)
	}
	x := mustHex(t, "50BE049A5A570FA1459FB9F666E6FD80602E4E87790A0E567F12438A2C96C138")
	y := mustHex(t, "B877AFE8612B406D96BE85BD9F19D423E95BE96C0E1E0B5824127195C3ED5917")
	tPub, err := KeygenWithPrivate(GroupEdwards25519, w, x, true)
	if err != nil {
		t.Fatal(err)
	}
	sPub, err := KeygenWithPrivate(GroupEdwards25519, w, y, false)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(tPub) != "9e9311d985c1355e022d7c3c694ad8d6f7ad6d647b68a90b0fe46992818002da" ||
		hex.EncodeToString(sPub) != "fbe08f7f96cd5d4139e7c9eccb95e79b8ace41e270a60198c007df18525b628e" {
		t.Fatalf("unexpected public values T=%x S=%x", tPub, sPub)
	}
	k, err := Result(GroupEdwards25519, w, x, sPub, false)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(k) != "c2f7f99997c585e6b686ceb62db42f17cc70932def3bb4cf009e36f22ea5473d" {
		t.Fatalf("K = %x", k)
	}
	transcript := mustHex(t, "951285F107C87F0169B9C918A1F51F60CB1A75B9F8BB799A99F53D03ADD94B5F")
	body := mustHex(t, "3075A00703050000000000A1143012A003020101A10B30091B07726165627572"+
		"6EA2101B0E415448454E412E4D49542E454455A3233021A003020102A11A3018"+
		"1B066B72627467741B0E415448454E412E4D49542E454455A511180F31393730"+
		"303130313030303030305AA703020100A8053003020111")
	k0, err := DeriveKey(etype, initial, w, k, transcript, body, GroupEdwards25519, 0)
	if err != nil {
		t.Fatal(err)
	}
	k1, err := DeriveKey(etype, initial, w, k, transcript, body, GroupEdwards25519, 1)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(k0) != "548022d58a7c47eae8c49dccf6baa407" ||
		hex.EncodeToString(k1) != "b2c9ba0e13fc8ab3a9d96b51b601cf4a" {
		t.Fatalf("derived keys K0=%x K1=%x", k0, k1)
	}
}

func TestDERChoices(t *testing.T) {
	support, err := EncodeSupport([]int32{1, 2})
	if err != nil {
		t.Fatal(err)
	}
	want := "a00c300aa0083006020101020102"
	if got := hex.EncodeToString(support); got != want {
		t.Fatalf("support DER = %s, want %s", got, want)
	}
	var msg protocol.PASPAKE
	if err := asn1.Unmarshal(support, &msg); err != nil || msg.Support == nil {
		t.Fatalf("decode support: %v", err)
	}
	factor, err := EncodeFactor()
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(factor); got != "3005a003020101" {
		t.Fatalf("factor DER = %s", got)
	}
	response, err := EncodeResponse(make([]byte, 32), []byte{1, 2, 3}, 18)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := Decode(response)
	if err != nil || decoded.Response == nil || len(decoded.Response.Factor.Cipher) != 3 {
		t.Fatalf("response decode: %v %#v", err, decoded)
	}
	goldenResponse, err := asn1.Marshal(protocol.PASPAKE{Response: &protocol.SPAKEResponse{
		PubKey: []byte("S value"),
		Factor: protocol.EncryptedData{
			EType: 0, KVNO: uint32Pointer(5), Cipher: []byte("krbASN.1 test message"),
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(goldenResponse); got !=
		"a2343032a0090407532076616c7565a1253023a003020100a103020105a21704156b726241534e2e312074657374206d657373616765" {
		t.Fatalf("response DER = %s", got)
	}
	challenge, err := EncodeChallenge(1, []byte("T value"))
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(challenge); got != "a11d301ba003020101a1090407542076616c7565a20930073005a003020101" {
		t.Fatalf("challenge DER = %s", got)
	}
	encData, err := asn1.Marshal(protocol.PASPAKE{EncData: &protocol.EncryptedData{
		EType: 0, KVNO: uint32Pointer(5), Cipher: []byte("krbASN.1 test message"),
	}})
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(encData); got !=
		"a3253023a003020100a103020105a21704156b726241534e2e312074657374206d657373616765" {
		t.Fatalf("encrypted-data DER = %s", got)
	}
}

func uint32Pointer(value uint32) *uint32 { return &value }

func TestRejectsUnsupportedGroupAndPoint(t *testing.T) {
	if _, err := DeriveW(nil, nil, 2); err == nil {
		t.Fatal("unsupported group accepted")
	}
	if _, err := Result(GroupEdwards25519, make([]byte, 32), make([]byte, 32), make([]byte, 32), false); err == nil {
		t.Fatal("invalid point accepted")
	}
}
