package pac

import "testing"

func TestSIDRoundTrip(t *testing.T) {
	want, err := ParseSID("S-1-5-21-111-222-333")
	if err != nil {
		t.Fatal(err)
	}
	data, err := want.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	got, used, err := ParseSIDBinary(data)
	if err != nil || used != len(data) {
		t.Fatalf("parse SID: %v, used %d", err, used)
	}
	if got.String() != want.String() {
		t.Fatalf("SID = %s, want %s", got, want)
	}
}
