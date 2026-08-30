package kpasswd

import (
	"context"
	"testing"
	"time"

	"github.com/Exonical/go-kerberos/krb5/client"
	"github.com/Exonical/go-kerberos/krb5/config"
	"github.com/Exonical/go-kerberos/krb5/principal"
	"github.com/Exonical/go-kerberos/krb5/protocol"
)

func TestKpasswdClientValidationAndConfiguration(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	name := principal.Principal{Realm: "EXAMPLE.COM", Components: []string{"alice"}}
	for _, test := range []struct {
		name string
		call func() error
	}{
		{"change nil client", func() error { return (*Client)(nil).ChangePassword(context.Background(), name, "old", "new") }},
		{"change nil kerberos", func() error { return (&Client{}).ChangePassword(context.Background(), name, "old", "new") }},
		{"change canceled", func() error {
			return (&Client{Kerberos: &client.Client{}}).ChangePassword(ctx, name, "old", "new")
		}},
		{"change empty old", func() error {
			return (&Client{Kerberos: &client.Client{}}).ChangePassword(context.Background(), name, "", "new")
		}},
		{"change empty new", func() error {
			return (&Client{Kerberos: &client.Client{}}).ChangePassword(context.Background(), name, "old", "")
		}},
		{"set invalid target", func() error {
			return (&Client{Kerberos: &client.Client{}}).SetPassword(context.Background(), name, "admin", principal.Principal{}, "new")
		}},
		{"credentials missing", func() error {
			return (&Client{Kerberos: &client.Client{}}).ChangePasswordWithCredentials(context.Background(), nil, "new")
		}},
		{"set credentials missing", func() error {
			return (&Client{Kerberos: &client.Client{}}).SetPasswordWithCredentials(context.Background(), nil, name, "new")
		}},
		{"set empty new", func() error {
			return (&Client{Kerberos: &client.Client{}}).SetPasswordWithCredentials(context.Background(),
				&client.Credentials{Ticket: []byte{1}, Key: protocol.EncryptionKey{KeyValue: []byte{1}}}, name, "")
		}},
	} {
		if err := test.call(); err == nil {
			t.Errorf("%s unexpectedly succeeded", test.name)
		}
	}
	if err := validateTarget(principal.Principal{Realm: "EXAMPLE.COM", Components: []string{"bob"}}); err != nil {
		t.Fatal(err)
	}
	if (&Client{Port: 464}).port("EXAMPLE.COM") != 464 {
		t.Fatal("explicit port ignored")
	}
	kclient := &client.Client{Config: &config.Config{
		ClockSkew: 2 * time.Minute,
		RealmOptions: map[string]map[string][]string{
			"EXAMPLE.COM": {"kpasswd_port": {"8464"}},
		},
		Realms: map[string][]string{"EXAMPLE.COM": {"127.0.0.1:88"}},
	}}
	configured := &Client{Kerberos: kclient}
	if configured.port("example.com") != 8464 || configured.clockSkew() != 2*time.Minute {
		t.Fatal("profile options not applied")
	}
	if got, ok := configuredKDC(kclient.Config, "example.com"); !ok || got != "127.0.0.1:88" {
		t.Fatalf("case-insensitive lookup failed: %q/%v", got, ok)
	}
	if got, ok := configuredKDC(kclient.Config, "EXAMPLE.COM"); !ok || got != "127.0.0.1:88" {
		t.Fatalf("configured KDC = %q/%v", got, ok)
	}
	changepw := &client.Credentials{
		Client: name,
		Ticket: []byte{1},
		Key:    protocol.EncryptionKey{KeyType: 999, KeyValue: []byte{1}},
	}
	if err := configured.sendPasswordRequest(context.Background(), changepw, kpasswdVersion,
		[]byte("new"), "password change", kpasswdVersion); err == nil {
		t.Fatal("credential with missing server realm unexpectedly succeeded")
	}
	exchanged := &Client{Kerberos: &client.Client{
		Exchange: func(ctx context.Context, realm string, payload []byte) ([]byte, error) {
			if realm != "EXAMPLE.COM" || string(payload) != "payload" {
				t.Fatalf("exchange arguments = %q/%q", realm, payload)
			}
			return []byte("reply"), nil
		},
	}}
	if got, err := exchanged.passwordChangeRoundTrip(context.Background(), "EXAMPLE.COM", []byte("payload")); err != nil || string(got) != "reply" {
		t.Fatalf("exchange callback = %q/%v", got, err)
	}
	exchanged.Kerberos.Exchange = func(context.Context, string, []byte) ([]byte, error) {
		return nil, context.DeadlineExceeded
	}
	if _, err := exchanged.passwordChangeRoundTrip(context.Background(), "EXAMPLE.COM", nil); err == nil {
		t.Fatal("exchange error not returned")
	}
	if _, err := (&Client{Kerberos: &client.Client{Config: &config.Config{}}}).passwordChangeRoundTrip(
		context.Background(), "EXAMPLE.COM", nil); err == nil {
		t.Fatal("missing configured KDC not rejected")
	}
	if !kpasswdWithinSkew(time.Unix(10, 0), time.Unix(10, 0), time.Second) ||
		kpasswdWithinSkew(time.Unix(10, 0), time.Unix(10, 0), -time.Second) {
		t.Fatal("skew helper semantics incorrect")
	}
}
