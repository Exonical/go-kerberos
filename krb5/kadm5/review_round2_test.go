package kadm5

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/Exonical/go-kerberos/krb5/crypto"
	"github.com/Exonical/go-kerberos/krb5/kdb"
	"github.com/Exonical/go-kerberos/krb5/principal"
)

func reviewRound2Principal(t *testing.T, value string) principal.Principal {
	t.Helper()
	p, err := principal.Parse(value)
	if err != nil {
		t.Fatal(err)
	}
	return *p
}

func reviewRound2Status(reply []byte) uint32 {
	if len(reply) < 8 {
		return ^uint32(0)
	}
	return binary.BigEndian.Uint32(reply[4:8])
}

func reviewRound2Create3Body(p principal.Principal, tuples []KeySaltTuple) []byte {
	w := xdrWriter{}
	w.u32(APIv4)
	writeEntry(&w, PrincipalEntry{Principal: p}, 0)
	w.i32(0)
	writeKeySaltTuples(&w, tuples)
	w.nullString("password")
	return w.bytes()
}

func TestCreatePrincipal3RejectsConflictingKeySaltTuples(t *testing.T) {
	db := kdb.NewDatabase("TEST.REALM")
	server := NewServer(db, nil)
	server.AdminPrincipal = reviewRound2Principal(t, "admin@TEST.REALM")
	p := reviewRound2Principal(t, "new@TEST.REALM")
	body := reviewRound2Create3Body(p, []KeySaltTuple{
		{Enctype: crypto.EnctypeAES128SHA1, SaltType: 0},
		{Enctype: crypto.EnctypeAES128SHA1, SaltType: 2},
	})
	reply := server.dispatch(server.AdminPrincipal, createPrincipal3, body)
	if got := reviewRound2Status(reply); got != 43787578 {
		t.Fatalf("CREATE_PRINCIPAL3 status = %d, want %d", got, 43787578)
	}
	if _, ok, _ := db.Lookup(p); ok {
		t.Fatal("conflicting CREATE_PRINCIPAL3 created a principal")
	}
}

func TestChrandPrincipal3RejectsConflictingKeySaltTuples(t *testing.T) {
	db := kdb.NewDatabase("TEST.REALM")
	if err := db.AddPrincipal("alice", "password"); err != nil {
		t.Fatal(err)
	}
	server := NewServer(db, nil)
	server.AdminPrincipal = reviewRound2Principal(t, "admin@TEST.REALM")
	p := reviewRound2Principal(t, "alice@TEST.REALM")
	w := xdrWriter{}
	w.u32(APIv4)
	w.principal(p)
	w.boolean(false)
	writeKeySaltTuples(&w, []KeySaltTuple{
		{Enctype: crypto.EnctypeAES128SHA1, SaltType: 0},
		{Enctype: crypto.EnctypeAES128SHA1, SaltType: 2},
	})
	reply := server.dispatch(server.AdminPrincipal, chrandPrincipal3, w.bytes())
	if got := reviewRound2Status(reply); got != 43787578 {
		t.Fatalf("CHRAND_PRINCIPAL3 status = %d, want %d", got, 43787578)
	}
}

func TestCreateAliasAuthorizesAliasAndTarget(t *testing.T) {
	db := kdb.NewDatabase("TEST.REALM")
	if err := db.AddPrincipal("target", "password"); err != nil {
		t.Fatal(err)
	}
	server := NewServer(db, nil)
	server.ACL = func(_ principal.Principal, operation string, target principal.Principal) bool {
		return operation == "add-alias" && target.Components[0] == "alias"
	}
	w := xdrWriter{}
	w.u32(APIv4)
	w.principal(reviewRound2Principal(t, "alias@TEST.REALM"))
	w.principal(reviewRound2Principal(t, "target@TEST.REALM"))
	reply := server.dispatch(reviewRound2Principal(t, "client@TEST.REALM"), createAlias, w.bytes())
	if got := reviewRound2Status(reply); got != authAdd {
		t.Fatalf("CREATE_ALIAS status = %d, want %d", got, authAdd)
	}
}

func TestSelfRandKeyMinimumLifeAndKeepOldClamp(t *testing.T) {
	db := kdb.NewDatabase("TEST.REALM")
	if err := db.AddPrincipal("alice", "password"); err != nil {
		t.Fatal(err)
	}
	if err := db.CreatePolicy(kdb.PolicyRecord{Name: "self", MinLife: 60}); err != nil {
		t.Fatal(err)
	}
	p := reviewRound2Principal(t, "alice@TEST.REALM")
	record, ok, err := db.Lookup(p)
	if err != nil || !ok {
		t.Fatalf("Lookup = %v, %v", ok, err)
	}
	record.Policy = "self"
	record.LastPasswordChange = time.Unix(1000, 0).UTC()
	if err := db.UpdatePrincipal(record); err != nil {
		t.Fatal(err)
	}
	server := NewServer(db, nil)
	server.Now = func() time.Time { return time.Unix(1001, 0).UTC() }
	if got := server.checkSelfKeyChange(p, p); got != passTooSoon {
		t.Fatalf("self min-life status = %d, want %d", got, passTooSoon)
	}
	if !clampSelfKeepOld(p, p, true) {
		t.Fatal("self keepOld was not retained within the model's clamp")
	}
	if clampSelfKeepOld(p, p, false) {
		t.Fatal("false keepOld was changed by clamp")
	}
}
