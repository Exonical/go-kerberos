package discovery

import (
	"context"
	"testing"
)

type fakeResolver struct {
	records []SRVRecord
	err     error
	txt     map[string][]string
	txtErr  error
	uris    []URIRecord
	uriErr  error
	queries []string
}

func (r *fakeResolver) LookupSRV(_ context.Context, service, proto, name string) ([]SRVRecord, error) {
	r.queries = append(r.queries, service+"_"+proto+"."+name)
	return r.records, r.err
}

func (r *fakeResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	r.queries = append(r.queries, name)
	return r.txt[name], r.txtErr
}

func (r *fakeResolver) LookupURI(_ context.Context, name string) ([]URIRecord, error) {
	r.queries = append(r.queries, name)
	return r.uris, r.uriErr
}

func TestDiscoverConfiguredAndDNSKDCs(t *testing.T) {
	got, err := Discover(context.Background(), &fakeResolver{records: []SRVRecord{
		{Target: "kdc-a.test.", Port: 88, Priority: 10},
		{Target: "kdc-b.test.", Port: 88, Priority: 20},
	}}, "TEST.REALM")
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(got) != 2 || got[0].Host != "kdc-a.test" {
		t.Fatalf("KDCs = %#v", got)
	}
}

func TestDiscoverNoRecordsAndCancellation(t *testing.T) {
	if _, err := Discover(context.Background(), &fakeResolver{}, "TEST.REALM"); err == nil {
		t.Fatal("no-record discovery unexpectedly succeeded")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Discover(ctx, &fakeResolver{}, "TEST.REALM"); err == nil {
		t.Fatal("cancelled discovery unexpectedly succeeded")
	}
}

func TestLookupRealmTXTWalkAndGate(t *testing.T) {
	resolver := &fakeResolver{txt: map[string][]string{
		"_kerberos.host.example.test": {""},
		"_kerberos.example.test":      {"EXAMPLE.TEST."},
	}}
	got, ok, err := LookupRealmTXT(context.Background(), resolver, "host.example.test.")
	if err != nil || !ok || got != "EXAMPLE.TEST" {
		t.Fatalf("TXT result = %q, %v, %v", got, ok, err)
	}
	if len(resolver.queries) != 2 || resolver.queries[0] != "_kerberos.host.example.test" ||
		resolver.queries[1] != "_kerberos.example.test" {
		t.Fatalf("TXT queries = %#v", resolver.queries)
	}
	if got, ok, err := DiscoverRealmTXT(context.Background(), resolver, "host.example.test", false); err != nil || ok || got != "" {
		t.Fatalf("disabled TXT = %q, %v, %v", got, ok, err)
	}
}

func TestLookupRealmTXTNoResultAndNumeric(t *testing.T) {
	resolver := &fakeResolver{txt: map[string][]string{
		"_kerberos.host.example.test": {"", "."},
		"_kerberos.example.test":      nil,
	}}
	if got, ok, err := LookupRealmTXT(context.Background(), resolver, "host.example.test"); err != nil || ok || got != "" {
		t.Fatalf("empty TXT result = %q, %v, %v", got, ok, err)
	}
	before := len(resolver.queries)
	if got, ok, err := LookupRealmTXT(context.Background(), resolver, "192.0.2.1"); err != nil || ok || got != "" {
		t.Fatalf("numeric TXT result = %q, %v, %v", got, ok, err)
	}
	if len(resolver.queries) != before {
		t.Fatalf("numeric address was queried: %#v", resolver.queries[before:])
	}
}

func TestParseURIRecordAndPriority(t *testing.T) {
	for _, test := range []struct {
		record URIRecord
		want   KDC
		ok     bool
	}{
		{URIRecord{Target: "krb5srv:m:tcp:kdc.example:750"}, KDC{Host: "kdc.example", Port: 750, Transport: "tcp", Primary: true}, true},
		{URIRecord{Target: "krb5srv::udp:kdc.example"}, KDC{Host: "kdc.example", Port: 88, Transport: "udp"}, true},
		{URIRecord{Target: "krb5srv::kkdcp:https://proxy.example/KdcProxy"}, KDC{Host: "proxy.example", Port: 443, Transport: "kkdcp", URI: "https://proxy.example/KdcProxy"}, true},
		{URIRecord{Target: "krb5srv::bogus:kdc.example"}, KDC{}, false},
		{URIRecord{Target: "not-krb5srv::tcp:kdc.example"}, KDC{}, false},
	} {
		got, ok := ParseURIRecord(test.record)
		if ok != test.ok || (ok && got != test.want) {
			t.Errorf("ParseURIRecord(%q) = %#v, %v; want %#v, %v", test.record.Target, got, ok, test.want, test.ok)
		}
	}
	resolver := &fakeResolver{
		records: []SRVRecord{{Target: "srv.example", Port: 88}},
		uris: []URIRecord{
			{Target: "krb5srv::tcp:low.example", Priority: 20},
			{Target: "krb5srv::udp:high.example", Priority: 10},
			{Target: "malformed", Priority: 1},
		},
	}
	got, err := Discover(context.Background(), resolver, "EXAMPLE.TEST")
	if err != nil || len(got) != 2 || got[0].Host != "high.example" || got[1].Host != "low.example" {
		t.Fatalf("URI discovery = %#v, %v", got, err)
	}
	resolver.uris = []URIRecord{{Target: "krb5srv::tcp:ignored.example"}}
	got, err = DiscoverWithOptions(context.Background(), resolver, "EXAMPLE.TEST", false)
	if err != nil || len(got) != 1 || got[0].Host != "srv.example" {
		t.Fatalf("disabled URI fallback = %#v, %v", got, err)
	}
	if resolver.queries[len(resolver.queries)-2] != "_kerberos_udp.EXAMPLE.TEST" ||
		resolver.queries[len(resolver.queries)-1] != "_kerberos_tcp.EXAMPLE.TEST" {
		t.Fatalf("disabled URI queries = %#v", resolver.queries)
	}
	resolver.queries = nil
	resolver.uris = nil
	resolver.records = nil
	resolver.uriErr = context.DeadlineExceeded
	if _, err := Discover(context.Background(), resolver, "EXAMPLE.TEST"); err == nil {
		t.Fatal("URI and SRV errors unexpectedly produced KDCs")
	}
	if len(resolver.queries) != 3 || resolver.queries[0] != "_kerberos.EXAMPLE.TEST" {
		t.Fatalf("URI fallback query order = %#v", resolver.queries)
	}
}
