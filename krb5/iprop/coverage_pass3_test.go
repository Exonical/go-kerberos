package iprop

import (
	"context"
	"testing"
	"time"

	"github.com/Exonical/go-kerberos/krb5/kdb"
	"github.com/Exonical/go-kerberos/krb5/principal"
)

func TestIPROPValueAndResultBoundaries(t *testing.T) {
	last := Last{LastSno: 9, LastTime: Time{Seconds: 10, Useconds: 20}}
	result := IncrementalResult{
		LastEntry: last,
		Updates: []Update{{
			PrincipalName: "alice@EXAMPLE.COM", EntrySno: 3,
			Time: Time{Seconds: 11}, Entry: Entry{{Type: ATAttrFlags, Uint32: 7}},
			Deleted: true, Commit: true, KDCSSeenBy: []string{"replica"},
			Futures: []byte{1, 2},
		}},
		Ret: UpdateBusy,
	}
	encoded := result.MarshalXDR()
	decoded, err := UnmarshalIncrementalResult(encoded)
	if err != nil || decoded.Ret != UpdateBusy || len(decoded.Updates) != 1 ||
		decoded.Updates[0].PrincipalName != "alice@EXAMPLE.COM" ||
		!decoded.Updates[0].Deleted || !decoded.Updates[0].Commit {
		t.Fatalf("incremental result = %#v/%v", decoded, err)
	}
	full, err := UnmarshalFullResyncResult((FullResyncResult{LastEntry: last, Ret: UpdateOK}).MarshalXDR())
	if err != nil || full.LastEntry.LastSno != 9 {
		t.Fatalf("full result = %#v/%v", full, err)
	}
	if got := last.LastTime.Time(); !got.Equal(time.Unix(10, 20*1000).UTC()) {
		t.Fatalf("last time = %v", got)
	}
	for _, malformed := range [][]byte{{}, {0, 1}, append(encoded, 1)} {
		if _, err := UnmarshalIncrementalResult(malformed); err == nil {
			t.Fatalf("malformed incremental result accepted: %x", malformed)
		}
	}
}

func TestIPROPReplicaValidationAndDispatchBoundaries(t *testing.T) {
	if _, err := (&Replica{}).KpropServer(nil, nil); err == nil {
		t.Fatal("incomplete kprop replica accepted")
	}
	if status, err := (&Replica{}).Poll(context.Background()); err == nil || status != UpdateError {
		t.Fatalf("incomplete replica poll = %v/%v", status, err)
	}
	db := kdb.NewDatabase("EXAMPLE.COM")
	server := NewServer(db, nil)
	name := principal.Principal{Realm: "EXAMPLE.COM", Components: []string{"alice"}}
	server.Authorize = func(principal.Principal) bool { return true }
	if got, err := UnmarshalIncrementalResult(server.dispatch(name, ProcGetUpdates, []byte{0})); err != nil || got.Ret != UpdateError {
		t.Fatalf("malformed update dispatch = %#v/%v", got, err)
	}
	if got, err := UnmarshalFullResyncResult(server.dispatch(name, ProcFullResyncExt, []byte{0})); err != nil || got.Ret != UpdateError {
		t.Fatalf("malformed full dispatch = %#v/%v", got, err)
	}
	if server.dispatch(name, ProcNull, []byte{1}) != nil {
		t.Fatal("nonempty NULL dispatch returned a body")
	}
	if err := db.AddPrincipal("replica", "password"); err != nil {
		t.Fatal(err)
	}
	updates, err := UnmarshalIncrementalResult(server.dispatch(name, ProcGetUpdates,
		(Last{}).MarshalXDR()))
	if err != nil || updates.Ret != UpdateOK || len(updates.Updates) == 0 {
		t.Fatalf("valid update dispatch = %#v/%v", updates, err)
	}
	full, err := UnmarshalFullResyncResult(server.dispatch(name, ProcFullResync, nil))
	if err != nil || full.Ret != UpdateOK {
		t.Fatalf("valid full dispatch = %#v/%v", full, err)
	}
}
