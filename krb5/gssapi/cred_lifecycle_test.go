package gssapi

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/Exonical/go-kerberos/krb5/authdata"
	"github.com/Exonical/go-kerberos/krb5/ccache"
	"github.com/Exonical/go-kerberos/krb5/client"
	"github.com/Exonical/go-kerberos/krb5/principal"
	"github.com/Exonical/go-kerberos/krb5/protocol"
)

type lifecycleAttributeModule struct {
	value []byte
}

func (*lifecycleAttributeModule) Name() string       { return "lifecycle" }
func (*lifecycleAttributeModule) Flags(int32) uint32 { return 0 }
func (m *lifecycleAttributeModule) ImportAuthData(protocol.AuthorizationData, bool, *principal.Principal) error {
	return nil
}
func (*lifecycleAttributeModule) ExportAuthData(uint32) (protocol.AuthorizationData, error) {
	return nil, nil
}
func (*lifecycleAttributeModule) AttributeTypes() []string { return []string{"urn:test:attribute"} }
func (m *lifecycleAttributeModule) GetAttribute(attribute string) ([]byte, []byte, bool, bool, error) {
	if attribute != "urn:test:attribute" || len(m.value) == 0 {
		return nil, nil, false, false, authdata.ErrAttributeNotFound
	}
	return append([]byte(nil), m.value...), append([]byte(nil), m.value...), true, true, nil
}
func (m *lifecycleAttributeModule) SetAttribute(attribute string, value []byte, _ bool) error {
	if attribute != "urn:test:attribute" {
		return authdata.ErrAttributeNotFound
	}
	m.value = append([]byte(nil), value...)
	return nil
}
func (m *lifecycleAttributeModule) DeleteAttribute(attribute string) error {
	if attribute != "urn:test:attribute" {
		return authdata.ErrAttributeNotFound
	}
	m.value = nil
	return nil
}

func testPrincipal(t *testing.T, value string) principal.Principal {
	t.Helper()
	parsed, err := principal.Parse(value)
	if err != nil {
		t.Fatal(err)
	}
	return *parsed
}

func testCredential(t *testing.T) *Credential {
	t.Helper()
	user := testPrincipal(t, "user@EXAMPLE.COM")
	tgt := &client.Credentials{
		Client: user, Server: testPrincipal(t, "krbtgt/EXAMPLE.COM@EXAMPLE.COM"),
		Key:    protocol.EncryptionKey{KeyType: 18, KeyValue: []byte("01234567890123456789012345678901")},
		Ticket: []byte("tgt"),
	}
	service := &client.Credentials{
		Client: user, Server: testPrincipal(t, "host/server.example.com@EXAMPLE.COM"),
		Key:    protocol.EncryptionKey{KeyType: 18, KeyValue: []byte("12345678901234567890123456789012")},
		Ticket: []byte("service"),
	}
	return &Credential{
		creds: service, tgt: tgt, name: &user, usage: CredentialInitiate,
	}
}

func TestCredStoreLookup(t *testing.T) {
	if _, ok, err := (CredStore{{Key: "unknown", Value: "ignored"}}).Lookup("ccache"); err != nil || ok {
		t.Fatalf("unknown lookup = %v, %v", ok, err)
	}
	_, _, err := (CredStore{{Key: "password"}, {Key: "password"}}).Lookup("password")
	if !errors.Is(err, ErrDuplicateStoreElement) {
		t.Fatalf("duplicate lookup error = %v", err)
	}
}

func TestCredentialStoreFileRoundTrip(t *testing.T) {
	credential := testCredential(t)
	path := filepath.Join(t.TempDir(), "ccache")
	if err := StoreCredentialInto(credential, CredentialInitiate, false, true,
		CredStore{{Key: "ccache", Value: "FILE:" + path}}); err != nil {
		t.Fatal(err)
	}
	loaded, err := AcquireCredentialFrom(t.Context(), &client.Client{}, credential.name,
		CredentialInitiate, CredStore{{Key: "ccache", Value: "FILE:" + path}})
	if err != nil {
		t.Fatal(err)
	}
	if loaded.tgt == nil || loaded.creds == nil || string(loaded.creds.Ticket) != "service" {
		t.Fatalf("loaded credential lost entries: %#v", loaded)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
}

func TestCredentialStoreDIRCollection(t *testing.T) {
	dir := t.TempDir()
	name := "DIR:" + dir
	credential := testCredential(t)
	if err := StoreCredentialInto(credential, CredentialInitiate, false, true,
		CredStore{{Key: "ccache", Value: name}}); err != nil {
		t.Fatal(err)
	}
	handle, err := ccache.Resolve(name)
	if err != nil {
		t.Fatal(err)
	}
	defer handle.Close()
	collection, err := handle.Collection()
	if err != nil || len(collection) != 1 {
		t.Fatalf("collection = %d, err=%v", len(collection), err)
	}
	if _, err := collection[0].Read(); err != nil {
		t.Fatal(err)
	}
	if err := StoreCredentialInto(credential, CredentialInitiate, false, false,
		CredStore{{Key: "ccache", Value: name}}); !errors.Is(err, ErrDuplicateStoreElement) {
		t.Fatalf("duplicate DIR store error = %v", err)
	}
	if err := StoreCredentialInto(credential, CredentialInitiate, true, true,
		CredStore{{Key: "ccache", Value: name}}); err != nil {
		t.Fatal(err)
	}
}

func TestCredentialExportImportRoundTrip(t *testing.T) {
	original := testCredential(t)
	data, err := original.Export()
	if err != nil {
		t.Fatal(err)
	}
	imported, err := ImportCredential(data)
	if err != nil {
		t.Fatal(err)
	}
	if imported.tgt == nil || imported.creds == nil ||
		imported.creds.Server.String() != original.creds.Server.String() {
		t.Fatalf("imported credential mismatch: %#v", imported)
	}
	for _, malformed := range [][]byte{
		[]byte(`["bad",[]]`),
		[]byte(`["K5C1",null]`),
		[]byte(`["K5C1",[1]]`),
		[]byte(`["K5C1",[1, null, null, false, false, null, null, null, null, false, 0, 0, null, null]] trailing`),
	} {
		if _, err := ImportCredential(malformed); err == nil {
			t.Fatalf("malformed token accepted: %s", malformed)
		}
	}
}

func TestNamingExtensionsComposite(t *testing.T) {
	module := &lifecycleAttributeModule{}
	attributes := authdata.NewContext(module)
	name := testPrincipal(t, "user@EXAMPLE.COM")
	peer := &NameAttributes{Principal: name, Context: attributes}
	if err := peer.SetNameAttribute("urn:test:attribute", []byte("hello"), true); err != nil {
		t.Fatal(err)
	}
	value, display, authenticated, complete, err := peer.GetNameAttribute("urn:test:attribute")
	if err != nil || string(value) != "hello" || string(display) != "hello" || !authenticated || !complete {
		t.Fatalf("attribute = %q/%q/%t/%t, err=%v", value, display, authenticated, complete, err)
	}
	types, err := peer.InquireName()
	if err != nil || len(types) != 1 || types[0] != "urn:test:attribute" {
		t.Fatalf("types = %#v, err=%v", types, err)
	}
	first, err := peer.ExportNameComposite()
	if err != nil {
		t.Fatal(err)
	}
	second, err := peer.ExportNameComposite()
	if err != nil || string(first) != string(second) || len(first) == 0 {
		t.Fatalf("composite unstable or empty: %x/%x, err=%v", first, second, err)
	}
	if err := peer.DeleteNameAttribute("urn:test:attribute"); err != nil {
		t.Fatal(err)
	}
}
