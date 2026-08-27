package discovery

import (
	"context"
	"testing"
)

type fakeResolver struct {
	records []SRVRecord
	err     error
}

func (r fakeResolver) LookupSRV(context.Context, string, string, string) ([]SRVRecord, error) {
	return r.records, r.err
}

func TestDiscoverConfiguredAndDNSKDCs(t *testing.T) {
	got, err := Discover(context.Background(), fakeResolver{records: []SRVRecord{
		{Target: "kdc-a.test.", Port: 88, Priority: 10},
		{Target: "kdc-b.test.", Port: 88, Priority: 20},
	}}, "TEST.REALM")
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(got) != 2 || got[0].Host != "kdc-a.test." {
		t.Fatalf("KDCs = %#v", got)
	}
}

func TestDiscoverNoRecordsAndCancellation(t *testing.T) {
	if _, err := Discover(context.Background(), fakeResolver{}, "TEST.REALM"); err == nil {
		t.Fatal("no-record discovery unexpectedly succeeded")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Discover(ctx, fakeResolver{}, "TEST.REALM"); err == nil {
		t.Fatal("cancelled discovery unexpectedly succeeded")
	}
}
