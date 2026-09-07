package kadm5

import (
	"encoding/binary"
	"testing"

	"github.com/Exonical/go-kerberos/krb5/kdb"
	"github.com/Exonical/go-kerberos/krb5/principal"
)

func securityTestStatus(reply []byte) uint32 {
	if len(reply) < 8 {
		return ^uint32(0)
	}
	return binary.BigEndian.Uint32(reply[4:8])
}

func securityTestPrincipal(t *testing.T, name string) principal.Principal {
	t.Helper()
	p, err := principal.Parse(name)
	if err != nil {
		t.Fatal(err)
	}
	return *p
}

func lockdownTestServer(t *testing.T) (*Server, principal.Principal) {
	t.Helper()
	db := kdb.NewDatabase("TEST.REALM")
	if err := db.AddPrincipal("alice", "password"); err != nil {
		t.Fatal(err)
	}
	p := securityTestPrincipal(t, "alice@TEST.REALM")
	record, ok, err := db.Lookup(p)
	if err != nil || !ok {
		t.Fatalf("Lookup = %v, %v", ok, err)
	}
	record.Flags |= flagLockdownKeys
	record.Keys[18] = kdb.Key{Enctype: 18, KVNO: 1, Key: []byte{0x7a}}
	if err := db.UpdatePrincipal(record); err != nil {
		t.Fatal(err)
	}
	return NewServer(db, nil), p
}

func changepwTestService() principal.Principal {
	return principal.Principal{Realm: "TEST.REALM", Components: []string{"kadmin", "changepw"}}
}

func TestChangePasswordServiceAllowsOnlySelfGetAndOwnPolicy(t *testing.T) {
	server, self := lockdownTestServer(t)
	server.ACL = func(_ principal.Principal, operation string, _ principal.Principal) bool {
		return operation == "get-policy"
	}
	server.Database.(*kdb.Database).CreatePolicy(kdb.PolicyRecord{Name: "self"})
	record, _, _ := server.Database.Lookup(self)
	record.Policy = "self"
	if err := server.Database.UpdatePrincipal(record); err != nil {
		t.Fatal(err)
	}
	service := changepwTestService()

	get := xdrWriter{}
	get.u32(APIv4)
	get.principal(self)
	get.i32(KADM5KeyData)
	reply := server.dispatch(self, service, getPrincipal, get.bytes(), true)
	if got := securityTestStatus(reply); got != 0 {
		t.Fatalf("self GET_PRINCIPAL status = %d, want success", got)
	}
	other := securityTestPrincipal(t, "bob@TEST.REALM")
	get = xdrWriter{}
	get.u32(APIv4)
	get.principal(other)
	get.i32(KADM5KeyData)
	reply = server.dispatch(self, service, getPrincipal, get.bytes(), true)
	if got := securityTestStatus(reply); got != authGet {
		t.Fatalf("non-self GET_PRINCIPAL status = %d, want %d", got, authGet)
	}

	policy := xdrWriter{}
	policy.u32(APIv4)
	policy.nullString("self")
	reply = server.dispatch(self, service, getPolicy, policy.bytes(), true)
	if got := securityTestStatus(reply); got != 0 {
		t.Fatalf("self GET_POLICY status = %d, want success", got)
	}
}

func TestLockdownOperationSemantics(t *testing.T) {
	server, p := lockdownTestServer(t)
	server.ACL = func(_ principal.Principal, operation string, _ principal.Principal) bool {
		return operation == "change-password"
	}
	service := principal.Principal{}

	chpass := xdrWriter{}
	chpass.u32(APIv4)
	chpass.principal(p)
	chpass.nullString("new-password")
	if got := securityTestStatus(server.dispatch(p, service, chpassPrincipal, chpass.bytes(), true)); got != authChangePass {
		t.Fatalf("locked CHPASS status = %d, want %d", got, authChangePass)
	}

	setkey := xdrWriter{}
	setkey.u32(APIv4)
	setkey.principal(p)
	setkey.u32(0)
	if got := securityTestStatus(server.dispatch(p, service, setkeyPrincipal, setkey.bytes(), true)); got != authSetKey {
		t.Fatalf("locked SETKEY status = %d, want %d", got, authSetKey)
	}

	chrand := xdrWriter{}
	chrand.u32(APIv4)
	chrand.principal(p)
	reply := server.dispatch(p, service, chrandPrincipal, chrand.bytes(), true)
	if got := securityTestStatus(reply); got != 0 {
		t.Fatalf("locked CHRAND status = %d, want success", got)
	}
	if len(reply) < 12 || binary.BigEndian.Uint32(reply[8:12]) != 0 {
		t.Fatalf("locked CHRAND returned keys: %x", reply)
	}

	extract := xdrWriter{}
	extract.u32(APIv4)
	extract.principal(p)
	extract.u32(0)
	if got := securityTestStatus(server.dispatch(p, service, extractKeys, extract.bytes(), true)); got != authExtract {
		t.Fatalf("locked EXTRACT status = %d, want %d", got, authExtract)
	}

	del := xdrWriter{}
	del.u32(APIv4)
	del.principal(p)
	if got := securityTestStatus(server.dispatch(p, service, deletePrincipal, del.bytes(), true)); got != authDelete {
		t.Fatalf("locked DELETE status = %d, want %d", got, authDelete)
	}

	server, p = lockdownTestServer(t)
	server.ACL = func(_ principal.Principal, operation string, _ principal.Principal) bool {
		switch operation {
		case "modify", "delete", "create":
			return true
		default:
			return false
		}
	}
	modify := xdrWriter{}
	modify.u32(APIv4)
	writeEntry(&modify, PrincipalEntry{Principal: p}, KADM5Attributes)
	modify.i32(KADM5Attributes)
	if got := securityTestStatus(server.dispatch(p, service, modifyPrincipal, modify.bytes(), true)); got != authModify {
		t.Fatalf("locked MODIFY status = %d, want %d", got, authModify)
	}

	rename := xdrWriter{}
	rename.u32(APIv4)
	rename.principal(p)
	rename.principal(securityTestPrincipal(t, "alice-renamed@TEST.REALM"))
	if got := securityTestStatus(server.dispatch(p, service, renamePrincipal, rename.bytes(), true)); got != authDelete {
		t.Fatalf("locked RENAME status = %d, want %d", got, authDelete)
	}
}

func TestChangePasswordServiceOperationErrorCodes(t *testing.T) {
	server, p := lockdownTestServer(t)
	service := changepwTestService()

	create := xdrWriter{}
	create.u32(APIv4)
	if got := securityTestStatus(server.dispatch(p, service, createPrincipal, create.bytes(), true)); got != authAdd {
		t.Fatalf("CREATE status = %d, want %d", got, authAdd)
	}
	list := xdrWriter{}
	list.u32(APIv4)
	list.nullString("")
	if got := securityTestStatus(server.dispatch(p, service, getPrincs, list.bytes(), true)); got != authList {
		t.Fatalf("GET_PRINCS status = %d, want %d", got, authList)
	}
	if got := securityTestStatus(server.dispatch(p, service, getPolicies, list.bytes(), true)); got != authList {
		t.Fatalf("GET_POLICIES status = %d, want %d", got, authList)
	}
	setStringBody := xdrWriter{}
	setStringBody.u32(APIv4)
	if got := securityTestStatus(server.dispatch(p, service, setString, setStringBody.bytes(), true)); got != authModify {
		t.Fatalf("SET_STRING status = %d, want %d", got, authModify)
	}
	alias := xdrWriter{}
	alias.u32(APIv4)
	alias.principal(securityTestPrincipal(t, "alias@TEST.REALM"))
	alias.principal(p)
	if got := securityTestStatus(server.dispatch(p, service, createAlias, alias.bytes(), true)); got != authInsufficient {
		t.Fatalf("CREATE_ALIAS status = %d, want %d", got, authInsufficient)
	}
}
