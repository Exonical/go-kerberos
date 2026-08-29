package pac

import (
	"bytes"
	"encoding/binary"
	"os"
	"testing"
)

func TestNDRSIDUsesSingleConformanceCount(t *testing.T) {
	sid, err := ParseSID("S-1-5-21-1-2-3")
	if err != nil {
		t.Fatal(err)
	}
	var w ndrWriter
	if err := w.sid(&sid); err != nil {
		t.Fatal(err)
	}
	data := w.buf.Bytes()
	if len(data) != 4+8+len(sid.SubAuthorities)*4 {
		t.Fatalf("NDR SID length = %d", len(data))
	}
	if got := binary.LittleEndian.Uint32(data[:4]); got != uint32(len(sid.SubAuthorities)) {
		t.Fatalf("NDR SID conformance count = %d", got)
	}
	raw, err := sid.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data[4:12], raw[:8]) {
		t.Fatalf("NDR SID body = %x, want %x", data[4:12], raw[:8])
	}
}

func TestLogonInfoRoundTrip(t *testing.T) {
	domain, err := ParseSID("S-1-5-21-1-2-3")
	if err != nil {
		t.Fatal(err)
	}
	info := LogonInfo{
		LogonTime: 1, PasswordMustChange: ^uint64(0),
		EffectiveName: "alice", FullName: "Alice Example",
		LogonCount: 2, UserID: 1000, PrimaryGroupID: 513,
		GroupIDs:    []GroupMembership{{RelativeID: 513, Attributes: 7}},
		UserFlags:   LogonInfoExtraSids | LogonInfoResourceGroups,
		LogonServer: "\\\\DC", LogonDomainName: "EXAMPLE",
		LogonDomainID: &domain, UserAccountControl: 0x200,
		ExtraSIDs:              []SIDAndAttributes{{SID: domain, Attributes: 7}},
		ResourceGroupDomainSID: &domain,
		ResourceGroupIDs:       []GroupMembership{{RelativeID: 515, Attributes: 7}},
		ResourceGroupCount:     99,
	}
	info.UserSessionKey = [16]byte{1, 2, 3}
	data, err := info.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data[:8], []byte{1, 0x10, 8, 0, 0xcc, 0xcc, 0xcc, 0xcc}) {
		t.Fatalf("NDR common header = %x", data[:8])
	}
	got, err := ParseLogonInfo(data)
	if err != nil {
		t.Fatal(err)
	}
	if got.EffectiveName != info.EffectiveName || got.UserID != info.UserID ||
		len(got.GroupIDs) != 1 || len(got.ExtraSIDs) != 1 ||
		got.ResourceGroupDomainSID == nil || got.ResourceGroupDomainSID.String() != domain.String() {
		t.Fatalf("logon info = %#v", got)
	}
}

func TestLogonInfoRejectsBadHeader(t *testing.T) {
	if _, err := ParseLogonInfo([]byte{1, 0x10, 8, 0}); err == nil {
		t.Fatal("accepted truncated NDR header")
	}
}

func TestLogonInfoConditionalSIDsFollowFlags(t *testing.T) {
	sid, err := ParseSID("S-1-5-21-1-2-3")
	if err != nil {
		t.Fatal(err)
	}
	info := LogonInfo{
		UserFlags:              0,
		SidCount:               1,
		ExtraSIDs:              []SIDAndAttributes{{SID: sid}},
		ResourceGroupDomainSID: &sid,
		ResourceGroupCount:     1,
		ResourceGroupIDs:       []GroupMembership{{RelativeID: 1}},
	}
	data, err := info.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseLogonInfo(data)
	if err != nil {
		t.Fatal(err)
	}
	if got.SidCount != 0 || len(got.ExtraSIDs) != 0 ||
		got.ResourceGroupDomainSID != nil || got.ResourceGroupCount != 0 ||
		len(got.ResourceGroupIDs) != 0 {
		t.Fatalf("conditional fields survived without flags: %#v", got)
	}
}

func TestLogonInfoMITSavedPACGolden(t *testing.T) {
	// This PAC is MIT's saved_pac fixture, copied from the Samba torture
	// regression suite and embedded in krb5/src/lib/krb5/krb/t_pac.c.
	data, err := os.ReadFile("testdata/mit-saved-logon-info.bin")
	if err != nil {
		t.Fatal(err)
	}
	info, err := ParseLogonInfo(data)
	if err != nil {
		t.Fatal(err)
	}
	if info.EffectiveName != "W2003FINAL$" ||
		info.LogonServer != "W2003FINAL" ||
		info.LogonDomainName != "WIN2K3THINK" ||
		info.UserID != 0x3ed {
		t.Fatalf("MIT logon-info identity = %#v", info)
	}
	if info.LogonDomainID == nil ||
		info.LogonDomainID.String() != "S-1-5-21-3048156945-3961193616-3706469200" {
		t.Fatalf("MIT logon domain SID = %#v", info.LogonDomainID)
	}
	if len(info.GroupIDs) != 1 || info.GroupIDs[0].RelativeID != 0x204 ||
		len(info.ExtraSIDs) != 1 || info.ExtraSIDs[0].SID.String() != "S-1-5-9" {
		t.Fatalf("MIT logon groups/SIDs = %#v", info)
	}
	pacData, err := os.ReadFile("testdata/mit-saved-pac.bin")
	if err != nil {
		t.Fatal(err)
	}
	p, err := Parse(pacData)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := p.Buffer(UPNDNSInfo); ok {
		t.Fatal("MIT saved PAC unexpectedly contains UPN_DNS_INFO")
	}
}
