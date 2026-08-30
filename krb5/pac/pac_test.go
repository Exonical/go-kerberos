package pac

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/Exonical/go-kerberos/krb5/asn1"
	"github.com/Exonical/go-kerberos/krb5/crypto"
	"github.com/Exonical/go-kerberos/krb5/principal"
	"github.com/Exonical/go-kerberos/krb5/protocol"
)

func TestParseMarshalPAC(t *testing.T) {
	input := make([]byte, 8+2*16+8+8)
	input[0] = 2
	input[8] = 1
	input[12] = 8
	input[16] = 40
	input[24] = 2
	input[28] = 3
	input[32] = 48
	input[40] = 1
	input[48] = 2
	p, err := Parse(input)
	if err != nil {
		t.Fatal(err)
	}
	out, err := p.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(input, out) {
		t.Fatalf("round trip differs:\n%s\n%s", hex.EncodeToString(input), hex.EncodeToString(out))
	}
}

func TestMarshalReflectsDirectEditsAfterParse(t *testing.T) {
	raw := (&PAC{Buffers: []Buffer{{Type: LogonInfoBuffer, Data: []byte{1}}}}).mustMarshal(t)
	parsed, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	parsed.Version = 7
	parsed.Buffers[0].Data[0] = 2
	parsed.Buffers[0].Type = UPNDNSInfo
	got, err := parsed.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(raw, got) {
		t.Fatal("MarshalBinary returned stale raw encoding")
	}
	if binary.LittleEndian.Uint32(got[4:]) != 7 ||
		binary.LittleEndian.Uint32(got[8:]) != UPNDNSInfo ||
		got[24] != 2 {
		t.Fatalf("direct edits were not encoded: %x", got)
	}
}

func TestMITSavedPACVector(t *testing.T) {
	const saved = "040000000000000001000000d801000048000000000000000a000000200000002002000000000000060000001400000040020000000000000700000014000000580200000000000001100800ccccccccc8010000000000000000020030dfa6cb4f7dc501ffffffffffffff7fffffffffffffff7fc03c4e596273c501c03c4e596273c501ffffffffffffff7f16001600040002000000000008000200000000000c00020000000000100002000000000014000200000000001800020065000000ed03000004020000010000001c0002002000000000000000000000000000000000000000140016002000020016001800240002002800020000000000000000000021000000000000000000000000000000000000000000000000000000000000010000002c0002000000000000000000000000000b000000000000000b00000057003200300030003300460049004e0041004c00240000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000004020000070000000b000000000000000a00000057003200300030003300460049004e0041004c000c000000000000000b000000570049004e0032004b0033005400480049004e004b00000004000000010400000000000515000000112fafb590041bec503becdc0100000030000200070000000100000001010000000000050900000000000000806628ea3780c501160077003200300030003300660069006e0061006c00240076ffffff37d5b0f724f0d6d4ec09865aa0e8c3a90000000076ffffffb4d8b8fe83b3133ffc5c41ade26483e000000000"
	data, err := hex.DecodeString(saved)
	if err != nil {
		t.Fatal(err)
	}
	p, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Buffers) != 4 {
		t.Fatalf("MIT saved PAC buffers = %d, want 4", len(p.Buffers))
	}
	if got, ok := p.Buffer(LogonInfoBuffer); !ok || len(got) != 472 {
		t.Fatalf("MIT logon-info length = %d", len(got))
	}
	for _, typ := range []uint32{ClientInfo, ServerChecksum, KDCChecksum} {
		if _, ok := p.Buffer(typ); !ok {
			t.Fatalf("MIT PAC missing buffer type %d", typ)
		}
	}
	encoded, err := p.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encoded, data) {
		t.Fatal("MIT saved PAC did not preserve canonical encoding")
	}
}

func TestPACSignVerifyAndClientInfo(t *testing.T) {
	etype, err := crypto.NewRegistry().Get(crypto.EnctypeAES256SHA1)
	if err != nil {
		t.Fatal(err)
	}
	serverKey := Key{EType: etype, Key: bytes.Repeat([]byte{0x11}, etype.KeySize())}
	privsvrKey := Key{EType: etype, Key: bytes.Repeat([]byte{0x22}, etype.KeySize())}
	user := principal.Principal{Realm: "EXAMPLE.COM", NameType: principal.NTPrincipal, Components: []string{"alice"}}
	p := &PAC{Buffers: []Buffer{{Type: LogonInfoBuffer, Data: []byte{1, 2, 3}}}}
	authTime := time.Unix(1700000000, 0).UTC()
	encoded, err := p.Sign(authTime, &user, serverKey, privsvrKey, true)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := Parse(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if err := parsed.Verify(serverKey, privsvrKey); err != nil {
		t.Fatal(err)
	}
	gotTime, gotName, err := parsed.ClientInfo()
	if err != nil {
		t.Fatal(err)
	}
	if !gotTime.Equal(authTime) || gotName != user.String() {
		t.Fatalf("client info = %v, %q", gotTime, gotName)
	}
}

func TestAddTicketSignature(t *testing.T) {
	etype, err := crypto.NewRegistry().Get(crypto.EnctypeAES256SHA1)
	if err != nil {
		t.Fatal(err)
	}
	key := Key{EType: etype, Key: bytes.Repeat([]byte{0x41}, etype.KeySize())}
	p := &PAC{Buffers: []Buffer{{Type: LogonInfoBuffer, Data: []byte{9}}}}
	if _, err := p.Sign(time.Unix(1700000000, 0), nil, key, key, false); err != nil {
		t.Fatal(err)
	}
	if err := p.AddTicketSignature([]byte("encoded ticket"), key); err != nil {
		t.Fatal(err)
	}
	value, ok := p.Buffer(TicketChecksum)
	if !ok || len(value) != 4+etype.ChecksumSize() {
		t.Fatalf("ticket checksum = %x", value)
	}
}

func TestParseRejectsUnalignedBuffer(t *testing.T) {
	data := make([]byte, 24)
	data[0] = 1
	data[8] = 1
	data[12] = 1
	data[16] = 9
	if _, err := Parse(data); err == nil {
		t.Fatal("Parse accepted unaligned buffer")
	}
}

func TestParseRejectsUnsupportedVersion(t *testing.T) {
	data := make([]byte, 24)
	data[0] = 1
	data[12] = 1
	data[16] = 24
	data[5] = 1
	if _, err := Parse(data); err == nil {
		t.Fatal("Parse accepted unsupported PAC version")
	}
}

func TestClientInfoRejectsOversizedName(t *testing.T) {
	client := principal.Principal{Realm: "EXAMPLE.COM", Components: []string{strings.Repeat("a", 40000)}}
	if err := (&PAC{}).SetClientInfo(time.Unix(1700000000, 0), client); err == nil {
		t.Fatal("SetClientInfo accepted oversized UTF-16 name")
	}
}

func TestVerifyRejectsChecksumTypeMismatch(t *testing.T) {
	etype, err := crypto.NewRegistry().Get(crypto.EnctypeAES256SHA1)
	if err != nil {
		t.Fatal(err)
	}
	key := Key{EType: etype, Key: bytes.Repeat([]byte{0x31}, etype.KeySize())}
	p := &PAC{Buffers: []Buffer{{Type: LogonInfoBuffer, Data: []byte{1}}}}
	encoded, err := p.Sign(time.Unix(1700000000, 0), nil, key, key, false)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := Parse(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Buffers[1].Type == ServerChecksum {
		binary.LittleEndian.PutUint32(parsed.Buffers[1].Data, uint32(999))
	} else {
		for i := range parsed.Buffers {
			if parsed.Buffers[i].Type == ServerChecksum {
				binary.LittleEndian.PutUint32(parsed.Buffers[i].Data, uint32(999))
			}
		}
	}
	if err := parsed.Verify(key, key); err == nil {
		t.Fatal("Verify accepted mismatched checksum type")
	}
}

func TestParseRejectsOverlapAndDuplicateTypes(t *testing.T) {
	data := make([]byte, 8+2*16+8)
	data[0] = 2
	data[8] = 1
	data[12] = 8
	data[16] = 40
	data[24] = 1
	data[28] = 8
	data[32] = 40
	if _, err := Parse(data); err == nil {
		t.Fatal("Parse accepted duplicate or overlapping buffers")
	}
}

func TestCVE202242898RejectsOverflowingBufferHeaders(t *testing.T) {
	countOverflow := make([]byte, headerLen)
	binary.LittleEndian.PutUint32(countOverflow, ^uint32(0))
	if _, err := Parse(countOverflow); err == nil {
		t.Fatal("PAC accepted an overflowing buffer count")
	}

	sizeOverflow := make([]byte, headerLen+bufferLen)
	binary.LittleEndian.PutUint32(sizeOverflow, 1)
	binary.LittleEndian.PutUint32(sizeOverflow[headerLen+4:], ^uint32(0))
	binary.LittleEndian.PutUint64(sizeOverflow[headerLen+8:], uint64(headerLen+bufferLen))
	if _, err := Parse(sizeOverflow); err == nil {
		t.Fatal("PAC accepted an overflowing buffer size")
	}

	offsetOverflow := make([]byte, headerLen+bufferLen)
	binary.LittleEndian.PutUint32(offsetOverflow, 1)
	binary.LittleEndian.PutUint64(offsetOverflow[headerLen+8:], ^uint64(0))
	if _, err := Parse(offsetOverflow); err == nil {
		t.Fatal("PAC accepted an overflowing buffer offset")
	}
}

func TestAuthorizationDataRoundTrip(t *testing.T) {
	raw := (&PAC{Buffers: []Buffer{{Type: LogonInfoBuffer, Data: []byte{1, 2, 3}}}}).mustMarshal(t)
	ad, err := AuthorizationData(raw)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := FromAuthorizationData(ad)
	if err != nil {
		t.Fatal(err)
	}
	got, err := parsed.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, got) {
		t.Fatalf("PAC changed through authdata wrapping")
	}
}

func TestAddAuthorizationDataReplacesAllPACs(t *testing.T) {
	raw := (&PAC{Buffers: []Buffer{{Type: LogonInfoBuffer, Data: []byte{1}}}}).mustMarshal(t)
	outer, err := AuthorizationData(raw)
	if err != nil {
		t.Fatal(err)
	}
	combined := append(append(protocol.AuthorizationData(nil), outer...),
		outer...)
	replacement := (&PAC{Buffers: []Buffer{{Type: LogonInfoBuffer, Data: []byte{2}}}}).mustMarshal(t)
	updated, err := AddAuthorizationData(combined, replacement)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range updated {
		if entry.ADType != ADIfRelevant {
			continue
		}
		var inner protocol.AuthorizationData
		if err := asn1.Unmarshal(entry.ADData, &inner); err != nil {
			t.Fatal(err)
		}
		for _, nested := range inner {
			if nested.ADType == ADWin2KPac && !bytes.Equal(nested.ADData, replacement) {
				t.Fatal("PAC occurrence was not replaced")
			}
		}
	}
}

func (p *PAC) mustMarshal(t *testing.T) []byte {
	t.Helper()
	value, err := p.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	return value
}
