package iprop

import (
	"testing"

	"github.com/Exonical/go-kerberos/krb5/kdb"
	"github.com/Exonical/go-kerberos/krb5/principal"
)

func TestServicePrincipalValidation(t *testing.T) {
	realm := "EXAMPLE.COM"
	if !validIpropService(principal.Principal{
		Realm: realm, Components: []string{"kiprop", "master"},
	}, realm) {
		t.Fatal("valid iprop service rejected")
	}
	for _, service := range []principal.Principal{
		{Realm: realm, Components: []string{"kiprop"}},
		{Realm: realm, Components: []string{"host", "master"}},
		{Realm: "OTHER.COM", Components: []string{"kiprop", "master"}},
	} {
		if validIpropService(service, realm) {
			t.Fatalf("invalid iprop service accepted: %v", service)
		}
	}
}

func TestDispatchAuthorizationAndUpdates(t *testing.T) {
	db := kdb.NewDatabase("EXAMPLE.COM")
	if err := db.CreatePrincipal("host/replica@EXAMPLE.COM", "secret"); err != nil {
		t.Fatal(err)
	}
	replica, err := principal.Parse("host/replica@EXAMPLE.COM")
	if err != nil {
		t.Fatal(err)
	}
	server := NewServer(db, nil)
	server.Authorize = func(client principal.Principal) bool {
		return client.String() == replica.String()
	}

	denied, err := principal.Parse("host/other@EXAMPLE.COM")
	if err != nil {
		t.Fatal(err)
	}
	body := Last{}.MarshalXDR()
	result, err := UnmarshalIncrementalResult(server.dispatch(*denied, ProcGetUpdates, body))
	if err != nil {
		t.Fatal(err)
	}
	if result.Ret != UpdatePermDenied {
		t.Fatalf("denied status = %v, want permission denied", result.Ret)
	}

	result, err = UnmarshalIncrementalResult(server.dispatch(*replica, ProcGetUpdates, body))
	if err != nil {
		t.Fatal(err)
	}
	if result.Ret != UpdateOK || len(result.Updates) != 1 {
		t.Fatalf("initial cursor result = %#v, want initial update", result)
	}
	last, stamp := db.UpdateLog.Last()
	value := "value"
	if err := db.SetString(*replica, "x", &value); err != nil {
		t.Fatal(err)
	}
	result, err = UnmarshalIncrementalResult(server.dispatch(*replica, ProcGetUpdates,
		Last{LastSno: last, LastTime: timeValue(stamp)}.MarshalXDR()))
	if err != nil {
		t.Fatal(err)
	}
	if result.Ret != UpdateOK || len(result.Updates) != 1 || result.Updates[0].EntrySno != last+1 {
		t.Fatalf("incremental result = %#v", result)
	}
	last, stamp = db.UpdateLog.Last()
	result, err = UnmarshalIncrementalResult(server.dispatch(*replica, ProcGetUpdates,
		Last{LastSno: last, LastTime: timeValue(stamp)}.MarshalXDR()))
	if err != nil {
		t.Fatal(err)
	}
	if result.Ret != UpdateNil {
		t.Fatalf("current cursor status = %v, want nil", result.Ret)
	}
}

func TestDispatchFullResyncStatus(t *testing.T) {
	server := NewServer(kdb.NewDatabase("EXAMPLE.COM"), nil)
	server.AllowedReplicas = map[string]bool{"host/replica@EXAMPLE.COM": true}
	replica, err := principal.Parse("host/replica@EXAMPLE.COM")
	if err != nil {
		t.Fatal(err)
	}
	result, err := UnmarshalFullResyncResult(server.dispatch(*replica, ProcFullResync, nil))
	if err != nil {
		t.Fatal(err)
	}
	if result.Ret != UpdateOK {
		t.Fatalf("full resync status = %v, want OK", result.Ret)
	}
}

func TestDumpWithMasterKeyRequiresConfiguredKey(t *testing.T) {
	server := NewServer(kdb.NewDatabase("EXAMPLE.COM"), nil)
	if _, err := server.DumpWithMasterKey(); err == nil {
		t.Fatal("dump unexpectedly succeeded without master key")
	}
}
