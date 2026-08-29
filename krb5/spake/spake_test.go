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
	p256Challenge, err := EncodeChallenge(GroupP256, mustHex(t,
		"024F62078CEB53840D02612195494D0D0D88DE21FEEB81187C71CBF3D01E71788D"))
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(p256Challenge); got !=
		"a1373035a003020102a1230421024f62078ceb53840d02612195494d0d0d88de21feeb81187c71cbf3d01e71788da20930073005a003020101" {
		t.Fatalf("P-256 challenge DER = %s", got)
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
	for _, group := range []int32{GroupP256, GroupP384, GroupP521} {
		_, multLen, elemLen, _, err := GroupInfo(group)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Result(group, make([]byte, multLen), make([]byte, multLen), make([]byte, elemLen-1), false); err == nil {
			t.Fatalf("group %d accepted wrong-length point", group)
		}
		if _, err := Result(group, make([]byte, multLen), make([]byte, multLen), []byte{0}, false); err == nil {
			t.Fatalf("group %d accepted identity point", group)
		}
		invalid := make([]byte, elemLen)
		invalid[0] = 2
		for i := 1; i < len(invalid); i++ {
			invalid[i] = 0xff
		}
		if _, err := Result(group, make([]byte, multLen), make([]byte, multLen), invalid, false); err == nil {
			t.Fatalf("group %d accepted invalid compressed point", group)
		}
	}
}

func TestMITNISTVectors(t *testing.T) {
	const body = "3075A00703050000000000A1143012A003020101A10B30091B07726165627572" +
		"6EA2101B0E415448454E412E4D49542E454455A3233021A003020102A11A3018" +
		"1B066B72627467741B0E415448454E412E4D49542E454455A511180F31393730" +
		"303130313030303030305AA703020100A8053003020112"
	vectors := []struct {
		name                                                                string
		group                                                               int32
		w, x, y, pubX, pubY, result, support, challenge, transcript, k0, k1 string
	}{
		{"P-256", GroupP256,
			"EB2984AF18703F94DD5288B8596CD36988D0D4E83BFB2B44DE14D0E95E2090BD",
			"935DDD725129FB7C6288E1A5CC45782198A6416D1775336D71EACD0549A3E80E",
			"E07405EB215663ABC1F254B8ADC0DA7A16FEBAA011AF923D79FDEF7C42930B33",
			"024F62078CEB53840D02612195494D0D0D88DE21FEEB81187C71CBF3D01E71788D",
			"021D07DC31266FC7CFD904CE2632111A169B7EC730E5F74A7E79700F86638E13C8",
			"0268489D7A9983F2FDE69C6E6A1307E9D252259264F5F2DFC32F58CCA19671E79B",
			"A0093007A0053003020102",
			"A1373035A003020102A1230421024F62078CEB53840D02612195494D0D0D88DE21FEEB81187C71CBF3D01E71788DA20930073005A003020101",
			"20AD3C1A9A90FC037D1963A1C4BFB15AB4484D7B6CF07B12D24984F14652DE60",
			"7D3B906F7BE49932DB22CD3463F032D06C9C078BE4B1D076D201FC6E61EF531E",
			"17D74E36F8993841FBB7FEB12FA4F011243D3AE4D2ACE55B39379294BBC4DB2C"},
		{"P-384", GroupP384,
			"0304CFC55151C6BBE889653DB96DBFE0BA4ACAFC024C1E8840CB3A486F6D80C16E1B8974016AA4B7FA43042A9B3825B1",
			"F323CA74D344749096FD35D0ADF20806E521460637176E84D977E9933C49D76FCFC6E62585940927468FF53D864A7A50",
			"5B7C709ACB175A5AFB82860DEABCA8D0B341FACDFF0AC0F1A425799AA905D7507E1EA9C573581A81467437419466E472",
			"02A1524603EF14F184696F854229D3397507A66C63F841BA748451056BE07879AC298912387B1C5CDFF6381C264701BE57",
			"020D5ADFDB92BC377041CF5837412574C5D13E0F4739208A4F0C859A0A302BC6A533440A245B9D97A0D34AF5016A20053D",
			"0264AA8C61DA9600DFB0BEB5E46550D63740E4EF29E73F1A30D543EB43C25499037AD16538586552761B093CF0E37C703A",
			"A0093007A0053003020103",
			"A1473045A003020103A133043102A1524603EF14F184696F854229D3397507A66C63F841BA748451056BE07879AC298912387B1C5CDFF6381C264701BE57A20930073005A003020101",
			"5AC0D99EF9E5A73998797FE64F074673E3952DEC4C7D1AACCE8B75F64D2B0276A901CB8539B4E8ED69E4DB0CE805B47B",
			"B917D37C16DD1D8567FBE379F64E1EE36CA3FD127AA4E60F97E4AFA3D9E56D91",
			"93D40079DAB229B9C79366829F4E7E7282E6A4B943AC7BAC69922D516673F49A"},
		{"P-521", GroupP521,
			"DE3A095A2B2386EFF3EB15B735398DA1CAF95BC8425665D82370AFF58B0471F34A57BCCDDF1EBF0A2965B58A93EE5B45E85D1A5435D1C8C83662999722D542831F9A",
			"017C38701A14B490B6081DFC83524562BE7FBB42E0B20426465E3E37952D30BCAB0ED857010255D44936A1515607964A870C7C879B741D878F9F9CDF5A865306F3F5",
			"003E2E2950656FA231E959ACDD984D125E7FA59CEC98126CBC8F3888447911EBCD49428A1C22D5FDB76A19FBEB1D9EDFA3DA6CF55B158B53031D05D51433ADE9B2B4",
			"02017D3DE19A3EC53D0174905665EF37947D142535102CD9809C0DFBD0DFE007353D54CF406CE2A59950F2BB540DF6FBE75F8BBBEF811C9BA06CC275ADBD96756696EC",
			"02004D142D87477841F6BA053C8F651F3395AD264B7405CA5911FB9A55ABD454FEF658A5F9ED97D1EFAC68764E9092FA15B9E0050880D78E95FD03ABF59317916822B5",
			"03007C303F62F09282CC849490805BD4457A6793A832CBEB55DF427DB6A31E99B055D5DC99756D24D47B70AD8B6015B0FB8742A718462ED423B90FA3FE631AC13FA916",
			"A0093007A0053003020104",
			"A1593057A003020104A145044302017D3DE19A3EC53D0174905665EF37947D142535102CD9809C0DFBD0DFE007353D54CF406CE2A59950F2BB540DF6FBE75F8BBBEF811C9BA06CC275ADBD96756696ECA20930073005A003020101",
			"8D6A89AE4D80CC4E47B6F4E48EA3E57919CC69598D0D3DC7C8BD49B6F1DB1409CA0312944CD964E213ABA98537041102237CFF5B331E5347A0673869B412302E",
			"1EB3D10BEE8FAB483ADCD3EB38F3EBF1F4FEB8DB96ECC035F563CF2E1115D276",
			"482B92781CE57F49176E4C94153CC622FE247A7DBE931D1478315F856F085890"},
	}
	initial := mustHex(t, "01B897121D933AB44B47EB5494DB15E50EB74530DBDAE9B634D65020FF5D88C1")
	etype, err := crypto.NewRegistry().Get(crypto.EnctypeAES256SHA1)
	if err != nil {
		t.Fatal(err)
	}
	for _, vector := range vectors {
		t.Run(vector.name, func(t *testing.T) {
			group := vector.group
			w, err := DeriveW(etype, initial, group)
			if err != nil {
				t.Fatal(err)
			}
			if got := hex.EncodeToString(w); got != hex.EncodeToString(mustHex(t, vector.w)) {
				t.Fatalf("w = %s", got)
			}
			x, y := mustHex(t, vector.x), mustHex(t, vector.y)
			tPub, err := KeygenWithPrivate(group, w, x, true)
			if err != nil {
				t.Fatal(err)
			}
			sPub, err := KeygenWithPrivate(group, w, y, false)
			if err != nil {
				t.Fatal(err)
			}
			if hex.EncodeToString(tPub) != hex.EncodeToString(mustHex(t, vector.pubX)) ||
				hex.EncodeToString(sPub) != hex.EncodeToString(mustHex(t, vector.pubY)) {
				t.Fatalf("public values = %x, %x", tPub, sPub)
			}
			result, err := Result(group, w, x, sPub, false)
			if err != nil {
				t.Fatal(err)
			}
			if hex.EncodeToString(result) != hex.EncodeToString(mustHex(t, vector.result)) {
				t.Fatalf("result = %x", result)
			}
			support := mustHex(t, vector.support)
			challenge := mustHex(t, vector.challenge)
			transcript := TranscriptForGroup(group, nil, support, challenge)
			transcript = TranscriptForGroup(group, transcript, sPub, nil)
			if hex.EncodeToString(transcript) != hex.EncodeToString(mustHex(t, vector.transcript)) {
				t.Fatalf("transcript = %x", transcript)
			}
			bodyDER := mustHex(t, body)
			for n, expected := range []string{vector.k0, vector.k1} {
				key, err := DeriveKey(etype, initial, w, result, transcript, bodyDER, group, uint32(n))
				if err != nil {
					t.Fatal(err)
				}
				if hex.EncodeToString(key) != hex.EncodeToString(mustHex(t, expected)) {
					t.Fatalf("K'[%d] = %x", n, key)
				}
			}
		})
	}
}
