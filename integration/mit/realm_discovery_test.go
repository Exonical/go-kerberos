//go:build integration

package mit_test

import (
	"os"
	"testing"

	"github.com/Exonical/go-kerberos/internal/testenv"
	"github.com/Exonical/go-kerberos/krb5/config"
)

func TestMITKDCConfigMatchesGoParser(t *testing.T) {
	realm := testenv.Start(t)
	data, err := os.ReadFile(realm.KDCConfig)
	if err != nil {
		t.Fatalf("read kdc.conf: %v", err)
	}
	profile, err := config.ParseKDCConf(data)
	if err != nil {
		t.Fatalf("ParseKDCConf: %v", err)
	}
	settings, ok := profile.Realm(testenv.RealmName)
	if !ok {
		t.Fatalf("realm %q not found in parsed kdc.conf", testenv.RealmName)
	}
	if len(settings.KDCPorts) != 1 || settings.KDCPorts[0] != realm.Port ||
		len(settings.KDCTCPPorts) != 1 || settings.KDCTCPPorts[0] != realm.Port {
		t.Fatalf("parsed listener ports = %#v, want %d", settings, realm.Port)
	}
}
