package pac

import "testing"

func TestUPNDNSInfoRoundTrip(t *testing.T) {
	sid, err := ParseSID("S-1-5-21-111-222-333")
	if err != nil {
		t.Fatal(err)
	}
	want := UPNDNSInfoData{
		UPN: "alice@example.com", DNSDomainName: "example.com",
		SAMName: "alice", SID: &sid, Flags: UPNDNSInfoHasSAMNameAndSID,
	}
	data, err := want.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if got := int(data[2]); got%4 != 0 {
		t.Fatalf("UPN offset %d is not aligned", got)
	}
	got, err := ParseUPNDNSInfo(data)
	if err != nil {
		t.Fatal(err)
	}
	if got.UPN != want.UPN || got.DNSDomainName != want.DNSDomainName ||
		got.SAMName != want.SAMName || got.SID == nil || got.SID.String() != sid.String() {
		t.Fatalf("UPN_DNS_INFO = %#v, want %#v", got, want)
	}
}

func TestUPNDNSInfoBasicGolden(t *testing.T) {
	value := UPNDNSInfoData{UPN: "a@b", DNSDomainName: "b", Flags: UPNDNSInfoNoUPNSet}
	data, err := value.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	// Header is 12 bytes; aligned data begins at offset 12.
	if len(data) < 16 || data[2] != 12 || data[6] != 20 {
		t.Fatalf("unexpected UPN_DNS_INFO layout: %x", data)
	}
	got, err := ParseUPNDNSInfo(data)
	if err != nil || got.UPN != value.UPN || got.DNSDomainName != value.DNSDomainName {
		t.Fatalf("basic UPN_DNS_INFO = %#v, %v", got, err)
	}
}

func TestUPNDNSInfoExtendedRequiresSID(t *testing.T) {
	_, err := (UPNDNSInfoData{
		UPN: "alice@example.com", DNSDomainName: "example.com",
		SAMName: "alice", Flags: UPNDNSInfoHasSAMNameAndSID,
	}).MarshalBinary()
	if err == nil || err.Error() != "PAC: extended UPN_DNS_INFO requires a SID" {
		t.Fatal("extended UPN_DNS_INFO accepted without SID")
	}
}
