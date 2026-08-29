package pac

import (
	"bytes"
	"testing"
)

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
		ResourceGroupCount:     1,
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
		ResourceGroupCount:    1,
		ResourceGroupIDs:      []GroupMembership{{RelativeID: 1}},
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
