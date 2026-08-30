package kdc

import (
	"context"
	"encoding/hex"
	"testing"
	"time"

	"github.com/Exonical/go-kerberos/krb5/client"
	"github.com/Exonical/go-kerberos/krb5/principal"
)

func TestMITCVE20121014MalformedASRequests(t *testing.T) {
	server, client := testServer(t, time.Unix(2000000000, 0).UTC())
	x1 := mustHex(t, "6A5E305BA103020105A2030201")
	x2 := mustHex(t, "A44F304DA007030500FEDCBA90A10E300CA003020101A10530031B0141A2031B0141A30E300CA003020101A10530031B0141A511180F31393934303631303036303331375AA70302012AA8053003020101")
	for length := 0x0b; length <= 0x7f; length++ {
		_ = server.HandleMessage(append(append(append([]byte(nil), x1...), byte(length)), x2...))
	}
	assertKDCStillServesAS(t, client)
}

func TestMITCVE20121015MalformedASRequests(t *testing.T) {
	server, client := testServer(t, time.Unix(2000000000, 0).UTC())
	x1 := mustHex(t, "6A81A030819DA103020105A20302010AA30E300C300AA10402020095A2020400A48180307EA00703050000000000A120301EA003020101A11730151B066B72627467741B0B4B5242544553542E434F4DA20D1B0B4B5242544553542E434F4DA320301EA003020101A11730151B066B72627467741B0B4B5242544553542E434F4DA511180F31393934303631303036303331375AA7030201")
	x2 := mustHex(t, "A8083006020106020112")
	for length := 0; length <= 0x7f; length++ {
		_ = server.HandleMessage(append(append(append([]byte(nil), x1...), byte(length)), x2...))
	}
	assertKDCStillServesAS(t, client)
}

func TestMITCVE202136222EmptyEncryptedChallenge(t *testing.T) {
	server, client := testServer(t, time.Unix(2000000000, 0).UTC())
	request := mustHex(t, "6A8130819DA103020105A20302010AA30E300C300AA1040202008AA2020400A48180307EA00703050000000000A120301EA003020101A11730151B066B72627467741B0B4B5242544553542E434F4DA20D1B0B4B5242544553542E434F4DA320301EA003020101A11730151B066B72627467741B0B4B5242544553542E434F4DA511180F31393934303631303036303331375AA703020100A8083006020112020111")
	_ = server.HandleMessage(request)
	assertKDCStillServesAS(t, client)
}

func TestMITBogusKDCRequests(t *testing.T) {
	server, client := testServer(t, time.Unix(2000000000, 0).UTC())
	for _, request := range []string{"6AFF", "6CFF", "FFFF"} {
		_ = server.HandleMessage(mustHex(t, request))
		assertKDCStillServesAS(t, client)
	}
}

func TestMITCVE20131416MalformedServiceNames(t *testing.T) {
	_, client := testServer(t, time.Unix(2000000000, 0).UTC())
	user := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTPrincipal, Components: []string{"alice"}}
	tgt, err := client.ASExchange(context.Background(), user, "alice-password")
	if err != nil {
		t.Fatal(err)
	}
	for _, components := range [][]string{{"", "test"}, {"test", ""}, {"", ""}} {
		service := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTSrvInstance, Components: components}
		if _, err := client.TGSExchange(context.Background(), tgt, service); err == nil {
			t.Fatalf("malformed service %v unexpectedly succeeded", components)
		}
	}
	assertKDCStillServesAS(t, client)
}

func TestMITCVE20131417ServiceOptionFailure(t *testing.T) {
	_, client := testServer(t, time.Unix(2000000000, 0).UTC())
	user := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTPrincipal, Components: []string{"alice"}}
	tgt, err := client.ASExchange(context.Background(), user, "alice-password")
	if err != nil {
		t.Fatal(err)
	}
	service := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTSrvHst, Components: []string{"host", "example.com"}}
	if _, err := client.TGSExchange(context.Background(), tgt, service); err == nil {
		t.Fatal("unknown host/example.com unexpectedly succeeded")
	}
	assertKDCStillServesAS(t, client)
}

func assertKDCStillServesAS(t *testing.T, client *client.Client) {
	t.Helper()
	user := principal.Principal{Realm: "TEST.REALM", NameType: principal.NTPrincipal, Components: []string{"alice"}}
	if _, err := client.ASExchange(context.Background(), user, "alice-password"); err != nil {
		t.Fatalf("KDC unusable after malformed request: %v", err)
	}
}

func mustHex(t *testing.T, value string) []byte {
	t.Helper()
	data, err := hex.DecodeString(removeSpaces(value))
	if err != nil {
		t.Fatalf("decode test vector: %v", err)
	}
	return data
}

func removeSpaces(value string) string {
	result := make([]byte, 0, len(value))
	for _, char := range value {
		if char != ' ' && char != '\n' && char != '\t' {
			result = append(result, byte(char))
		}
	}
	return string(result)
}
