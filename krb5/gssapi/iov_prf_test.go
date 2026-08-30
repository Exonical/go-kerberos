package gssapi

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/Exonical/go-kerberos/krb5/crypto"
	"github.com/Exonical/go-kerberos/krb5/protocol"
)

func testPRFContext(key []byte) *Context {
	value := protocol.EncryptionKey{KeyType: crypto.EnctypeAES128SHA1, KeyValue: key}
	return &Context{key: value, prfPartial: value, prfFull: value, initiator: true}
}

func testPRFContextWithType(etype int32, partial, full []byte) *Context {
	partialKey := protocol.EncryptionKey{KeyType: etype, KeyValue: partial}
	fullKey := protocol.EncryptionKey{KeyType: etype, KeyValue: full}
	return &Context{key: fullKey, prfPartial: partialKey, prfFull: fullKey, initiator: true}
}

func TestWrapIOVMatchesFlatWrap(t *testing.T) {
	key, _ := hex.DecodeString("6c742096eb896230312b73972fa28b5d")
	data := []byte("iov data split over buffers")
	restore := crypto.SetRandomSource(bytes.NewReader(bytes.Repeat([]byte{0x42}, 32)))
	defer restore()
	flatCtx := testPRFContext(key)
	want, err := flatCtx.Wrap(data, true)
	if err != nil {
		t.Fatal(err)
	}
	iovCtx := testPRFContext(key)
	iov := []IOVBuffer{
		{Type: IOVHeader},
		{Type: IOVData, Buffer: append([]byte(nil), data[:9]...)},
		{Type: IOVData, Buffer: append([]byte(nil), data[9:]...)},
		{Type: IOVPadding},
		{Type: IOVTrailer},
	}
	if err := iovCtx.WrapIOV(iov, true); err != nil {
		t.Fatal(err)
	}
	got := append([]byte(nil), iov[0].Buffer...)
	for _, part := range iov[1:] {
		if part.Type == IOVData || part.Type == IOVTrailer {
			got = append(got, part.Buffer...)
		}
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("IOV token = %x, flat = %x", got, want)
	}
}

func TestWrapUnwrapIOVIntegrityAndSignOnly(t *testing.T) {
	key, _ := hex.DecodeString("6c742096eb896230312b73972fa28b5d")
	iov := []IOVBuffer{
		{Type: IOVHeader},
		{Type: IOVData, Buffer: []byte("payload")},
		{Type: IOVSignOnly, Buffer: []byte("associated")},
		{Type: IOVPadding},
		{Type: IOVTrailer},
	}
	sender := testPRFContext(key)
	if err := sender.WrapIOV(iov, false); err != nil {
		t.Fatal(err)
	}
	receiver := testPRFContext(key)
	receiver.initiator = false
	receiver.recvSeq = 0
	if err := receiver.UnwrapIOV(iov); err != nil {
		t.Fatal(err)
	}
	if got := string(iov[1].Buffer); got != "payload" {
		t.Fatalf("unwrapped data = %q", got)
	}
	iov[3].Buffer = nil
}

func TestWrapUnwrapIOVIntegrity(t *testing.T) {
	key, _ := hex.DecodeString("6c742096eb896230312b73972fa28b5d")
	iov := []IOVBuffer{
		{Type: IOVHeader},
		{Type: IOVData, Buffer: []byte("integrity payload")},
		{Type: IOVTrailer},
	}
	sender := testPRFContext(key)
	if err := sender.WrapIOV(iov, false); err != nil {
		t.Fatal(err)
	}
	if len(iov[2].Buffer) == 0 {
		t.Fatal("integrity trailer was not populated")
	}
	receiver := testPRFContext(key)
	receiver.initiator = false
	if err := receiver.UnwrapIOV(iov); err != nil {
		t.Fatal(err)
	}
	if got := string(iov[1].Buffer); got != "integrity payload" {
		t.Fatalf("integrity plaintext = %q", got)
	}
}

func TestWrapUnwrapIOVConfidentialityAndSignOnly(t *testing.T) {
	key, _ := hex.DecodeString("6c742096eb896230312b73972fa28b5d")
	iov := []IOVBuffer{
		{Type: IOVHeader},
		{Type: IOVData, Buffer: []byte("payload")},
		{Type: IOVSignOnly, Buffer: []byte("associated")},
		{Type: IOVTrailer},
	}
	sender := testPRFContext(key)
	if err := sender.WrapIOV(iov, true); err != nil {
		t.Fatal(err)
	}
	receiver := testPRFContext(key)
	receiver.initiator = false
	if err := receiver.UnwrapIOV(iov); err != nil {
		t.Fatal(err)
	}
	if got := string(iov[1].Buffer); got != "payload" {
		t.Fatalf("unwrapped data = %q", got)
	}
	iov[2].Buffer[0] ^= 1
	receiver.recvSeq = 0
	if err := receiver.UnwrapIOV(iov); err == nil {
		t.Fatal("tampered SIGN_ONLY buffer unexpectedly verified")
	}
}

func TestWrapUnwrapIOVInterleavedSignOnly(t *testing.T) {
	key, _ := hex.DecodeString("6c742096eb896230312b73972fa28b5d")
	for _, sealed := range []bool{false, true} {
		t.Run(fmt.Sprintf("sealed-%t", sealed), func(t *testing.T) {
			iov := []IOVBuffer{
				{Type: IOVHeader},
				{Type: IOVSignOnly, Buffer: []byte("before")},
				{Type: IOVData, Buffer: []byte("one")},
				{Type: IOVSignOnly, Buffer: []byte("between")},
				{Type: IOVData, Buffer: []byte("two")},
				{Type: IOVTrailer},
			}
			sender := testPRFContext(key)
			if err := sender.WrapIOV(iov, sealed); err != nil {
				t.Fatal(err)
			}
			receiver := testPRFContext(key)
			receiver.initiator = false
			if err := receiver.UnwrapIOV(iov); err != nil {
				t.Fatal(err)
			}
			if got := string(iov[2].Buffer) + string(iov[4].Buffer); got != "onetwo" {
				t.Fatalf("unwrapped interleaved data = %q", got)
			}
		})
	}
}

func rotateIOVPayload(iov []IOVBuffer, rrc int) []IOVBuffer {
	out := make([]IOVBuffer, len(iov))
	for index, buffer := range iov {
		out[index] = IOVBuffer{Type: buffer.Type, Buffer: append([]byte(nil), buffer.Buffer...)}
	}
	payload := append([]byte(nil), out[0].Buffer[16:]...)
	for _, buffer := range out[1:] {
		if buffer.Type == IOVData || buffer.Type == IOVPadding || buffer.Type == IOVTrailer {
			payload = append(payload, buffer.Buffer...)
		}
	}
	rrc %= len(payload)
	rotated := append(append([]byte(nil), payload[len(payload)-rrc:]...), payload[:len(payload)-rrc]...)
	binary.BigEndian.PutUint16(out[0].Buffer[6:8], uint16(rrc))
	offset := 0
	headerExtra := len(out[0].Buffer) - 16
	out[0].Buffer = append(out[0].Buffer[:16], rotated[:headerExtra]...)
	offset += headerExtra
	for index := 1; index < len(out); index++ {
		if out[index].Type != IOVData && out[index].Type != IOVPadding && out[index].Type != IOVTrailer {
			continue
		}
		length := len(out[index].Buffer)
		out[index].Buffer = append([]byte(nil), rotated[offset:offset+length]...)
		offset += length
	}
	return out
}

func TestUnwrapIOVSignOnlyRRC(t *testing.T) {
	key, _ := hex.DecodeString("6c742096eb896230312b73972fa28b5d")
	for _, sealed := range []bool{false, true} {
		t.Run(fmt.Sprintf("sealed-%t", sealed), func(t *testing.T) {
			iov := []IOVBuffer{
				{Type: IOVHeader},
				{Type: IOVSignOnly, Buffer: []byte("associated")},
				{Type: IOVData, Buffer: []byte("payload")},
				{Type: IOVTrailer},
			}
			sender := testPRFContext(key)
			if err := sender.WrapIOV(iov, sealed); err != nil {
				t.Fatal(err)
			}
			rotated := rotateIOVPayload(iov, 5)
			receiver := testPRFContext(key)
			receiver.initiator = false
			if err := receiver.UnwrapIOV(rotated); err != nil {
				t.Fatal(err)
			}
			if got := string(rotated[2].Buffer); got != "payload" {
				t.Fatalf("unwrapped RRC data = %q", got)
			}
		})
	}
}

func TestUnwrapIOVRejectsShortPeerBuffers(t *testing.T) {
	key, _ := hex.DecodeString("6c742096eb896230312b73972fa28b5d")
	ctx := testPRFContext(key)
	tests := map[string][]IOVBuffer{
		"short header": {
			{Type: IOVHeader, Buffer: []byte{0x05}},
			{Type: IOVData, Buffer: []byte("x")},
			{Type: IOVTrailer, Buffer: make([]byte, 12)},
		},
		"short sealed trailer": {
			{Type: IOVHeader, Buffer: append([]byte{0x05, 0x04, tokenFlagSealed, 0xff}, make([]byte, 12)...)},
			{Type: IOVData, Buffer: []byte("x")},
			{Type: IOVTrailer, Buffer: []byte{1}},
		},
	}
	for name, iov := range tests {
		t.Run(name, func(t *testing.T) {
			if err := ctx.UnwrapIOV(iov); err == nil {
				t.Fatal("malformed IOV unexpectedly accepted")
			}
		})
	}
}

func standardSealedNonzeroECToken(t *testing.T) []byte {
	t.Helper()
	key, _ := hex.DecodeString("6c742096eb896230312b73972fa28b5d")
	etype, err := crypto.NewRegistry().Get(crypto.EnctypeAES128SHA1)
	if err != nil {
		t.Fatal(err)
	}
	header := messageHeader([]byte{0x05, 0x04}, tokenFlagSealed, 16, 0, 0)
	input := append([]byte("payload"), bytes.Repeat([]byte{0xff}, 16)...)
	input = append(input, header...)
	restore := crypto.SetRandomSource(bytes.NewReader(bytes.Repeat([]byte{0x42}, 16)))
	encrypted, err := etype.Encrypt(key, 24, input)
	restore()
	if err != nil {
		t.Fatal(err)
	}
	return append(append([]byte(nil), header...), encrypted...)
}

func TestStandardSealedNonzeroEC(t *testing.T) {
	key, _ := hex.DecodeString("6c742096eb896230312b73972fa28b5d")
	token := standardSealedNonzeroECToken(t)
	receiver := testPRFContext(key)
	receiver.initiator = false
	plain, err := receiver.unwrap(token)
	if err != nil {
		t.Fatal(err)
	}
	if string(plain) != "payload" {
		t.Fatalf("standard EC plaintext = %q", plain)
	}
}

func TestUnwrapIOVStandardSealedNonzeroEC(t *testing.T) {
	key, _ := hex.DecodeString("6c742096eb896230312b73972fa28b5d")
	token := standardSealedNonzeroECToken(t)
	iov := []IOVBuffer{
		{Type: IOVHeader, Buffer: append([]byte(nil), token[:32]...)},
		{Type: IOVData, Buffer: append([]byte(nil), token[32:39]...)},
		{Type: IOVPadding, Buffer: append([]byte(nil), token[39:55]...)},
		{Type: IOVTrailer, Buffer: append([]byte(nil), token[len(token)-28:]...)},
	}
	receiver := testPRFContext(key)
	receiver.initiator = false
	if err := receiver.UnwrapIOV(iov); err != nil {
		t.Fatal(err)
	}
	if string(iov[1].Buffer) != "payload" {
		t.Fatalf("fragmented standard EC plaintext = %q", iov[1].Buffer)
	}
}

func TestUnwrapIOVStreamStandardSealedNonzeroEC(t *testing.T) {
	key, _ := hex.DecodeString("6c742096eb896230312b73972fa28b5d")
	iov := []IOVBuffer{{Type: IOVStream, Buffer: standardSealedNonzeroECToken(t)}}
	receiver := testPRFContext(key)
	receiver.initiator = false
	if err := receiver.UnwrapIOV(iov); err != nil {
		t.Fatal(err)
	}
	if string(iov[0].Buffer) != "payload" {
		t.Fatalf("stream standard EC plaintext = %q", iov[0].Buffer)
	}
}

func TestUnwrapIOVStream(t *testing.T) {
	key, _ := hex.DecodeString("6c742096eb896230312b73972fa28b5d")
	sender := testPRFContext(key)
	token, err := sender.Wrap([]byte("stream"), false)
	if err != nil {
		t.Fatal(err)
	}
	receiver := testPRFContext(key)
	receiver.initiator = false
	iov := []IOVBuffer{{Type: IOVStream, Buffer: token}}
	if err := receiver.UnwrapIOV(iov); err != nil {
		t.Fatal(err)
	}
	if string(iov[0].Buffer) != "stream" {
		t.Fatalf("stream plaintext = %q", iov[0].Buffer)
	}
}

func TestWrapIOVDCEStyle(t *testing.T) {
	key, _ := hex.DecodeString("6c742096eb896230312b73972fa28b5d")
	iov := []IOVBuffer{
		{Type: IOVHeader},
		{Type: IOVData, Buffer: []byte("dce payload")},
		{Type: IOVTrailer},
	}
	sender := testPRFContext(key)
	if err := sender.WrapIOVWithOptions(iov, true, IOVOptions{DCEStyle: true}); err != nil {
		t.Fatal(err)
	}
	if got := binary.BigEndian.Uint16(iov[0].Buffer[4:6]); got != 16 {
		t.Fatalf("DCE EC = %d, want 16", got)
	}
	if len(iov[2].Buffer) != 44 || !bytes.Equal(iov[2].Buffer[:16], bytes.Repeat([]byte{0xff}, 16)) {
		t.Fatalf("DCE trailer = %x", iov[2].Buffer)
	}
	receiver := testPRFContext(key)
	receiver.initiator = false
	receiver.SetDCEStyle(true)
	if err := receiver.UnwrapIOV(iov); err != nil {
		t.Fatal(err)
	}
	if got := string(iov[1].Buffer); got != "dce payload" {
		t.Fatalf("DCE plaintext = %q", got)
	}
}

func TestWrapIOVLengthAndBufferValidation(t *testing.T) {
	key, _ := hex.DecodeString("6c742096eb896230312b73972fa28b5d")
	ctx := testPRFContext(key)
	iov := []IOVBuffer{
		{Type: IOVHeader},
		{Type: IOVData, Buffer: []byte("payload")},
		{Type: IOVPadding},
		{Type: IOVTrailer},
	}
	lengths, err := ctx.WrapIOVLength(iov, true)
	if err != nil {
		t.Fatal(err)
	}
	if lengths != (IOVLengths{Header: 32, Padding: 0, Trailer: 28}) {
		t.Fatalf("lengths = %+v", lengths)
	}
	if len(iov[0].Buffer) != 0 || len(iov[3].Buffer) != 0 {
		t.Fatalf("query mutated output buffers: header=%d trailer=%d",
			len(iov[0].Buffer), len(iov[3].Buffer))
	}
}

func TestIOVRejectsMalformedLayouts(t *testing.T) {
	key, _ := hex.DecodeString("6c742096eb896230312b73972fa28b5d")
	ctx := testPRFContext(key)
	for name, iov := range map[string][]IOVBuffer{
		"missing header": {{Type: IOVData, Buffer: []byte("x")}},
		"missing data":   {{Type: IOVHeader}, {Type: IOVTrailer}},
		"duplicate header": {
			{Type: IOVHeader}, {Type: IOVHeader}, {Type: IOVData, Buffer: []byte("x")},
		},
		"stream with data": {
			{Type: IOVStream, Buffer: []byte("x")}, {Type: IOVData},
		},
		"wrap without trailer": {
			{Type: IOVHeader}, {Type: IOVData, Buffer: []byte("x")},
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := ctx.WrapIOV(iov, false); err == nil {
				t.Fatal("malformed layout unexpectedly accepted")
			}
		})
	}
}

func TestPseudoRandomMITAES128Vector(t *testing.T) {
	key, _ := hex.DecodeString("6c742096eb896230312b73972fa28b5d")
	ctx := testPRFContext(key)
	got, err := ctx.PseudoRandom(GSSPRFKeyPartial, nil, 44)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := hex.DecodeString("94208d982fc1bb7778128bdd77904420b45c9da699f3117bce66e39602128ef0296611a6d191a5828530f20f")
	if !bytes.Equal(got, want) {
		t.Fatalf("PRF = %x, want %x", got, want)
	}
	if got, err := ctx.PseudoRandom(GSSPRFKeyFull, nil, 0); err != nil || len(got) != 0 {
		t.Fatalf("zero PRF = %x, %v", got, err)
	}
	if _, err := ctx.PseudoRandom(99, nil, 1); err == nil {
		t.Fatal("invalid PRF selector succeeded")
	}
}

func TestPseudoRandomMITVectors(t *testing.T) {
	const input = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz123456789"
	vectors := []struct {
		name       string
		etype      int32
		keyPartial string
		partial    string
		keyFull    string
		full       string
	}{
		{"aes256-sha1", crypto.EnctypeAES256SHA1,
			"08fcdafd5832611b73ba7b497febff8c954b4b58031cad9b977c3b8c25192fd6",
			"e627efc14ef5b6d629f830c7109dea0d3d7d36e8cd57a1f301c5452494a1928f05affbee3360232209d3be0d",
			"f5b68b7823d8944f33f41541b4e4d38c9b2934f8d16334a796645b066152b4be",
			"112f2b2d878590653ccc7de278e9f0aa46fa5a380b6259f774cb7c134fcd37f61a50fd0d9f89bf8fe1a6b593"},
		{"camellia128", crypto.EnctypeCamellia128,
			"866e0466a178279a32ac0bda92b72aeb",
			"97fbb354bf341c3a160dcc86a7a910fda824601df67768797baceebf5d250ae929dec9760772084267f50a54",
			"d4893fd37da1a211e12dd1e03e0f03b7",
			"1dee2ff126ca563a2a2326b9dd3f0095013257414c83fad4398901013d55f367c82681186b7b2fe62f746ba4"},
		{"aes256-sha384", crypto.EnctypeAES256SHA384,
			"45bd806dbf6a833a9cffc1c94589a222367a79bc21c413718906e9f578a78467",
			"1c613ae8b77a3b4d783f3dce6c9178fc025e87f48a44784a69cb5fc697fe266a6141905067ef78566d309085",
			"6d404d37faf79f9df0d33568d320669800eb4836472ea8a026d16b7182460c52",
			"d15944b0a44508d1e61213f6455f292a02298f870c01a3f74ad0345a4a6651ebe101976e933f32d44f0b5947"},
	}
	for _, vector := range vectors {
		t.Run(vector.name, func(t *testing.T) {
			clean := func(value string) string {
				return strings.ReplaceAll(value, " ", "")
			}
			partialKey, _ := hex.DecodeString(clean(vector.keyPartial))
			fullKey, _ := hex.DecodeString(clean(vector.keyFull))
			partial, _ := hex.DecodeString(clean(vector.partial))
			full, _ := hex.DecodeString(clean(vector.full))
			partialContext := testPRFContextWithType(vector.etype, partialKey, partialKey)
			got, err := partialContext.PseudoRandom(GSSPRFKeyPartial, nil, len(partial))
			if err != nil {
				if vector.etype == crypto.EnctypeCamellia128 {
					t.Skipf("Camellia unavailable: %v", err)
				}
				t.Fatal(err)
			}
			if !bytes.Equal(got, partial) {
				t.Fatalf("partial PRF = %x, want %x", got, partial)
			}
			ctx := testPRFContextWithType(vector.etype, partialKey, fullKey)
			got, err = ctx.PseudoRandom(GSSPRFKeyFull, []byte(input), len(full))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, full) {
				t.Fatalf("full PRF = %x, want %x", got, full)
			}
		})
	}
}
