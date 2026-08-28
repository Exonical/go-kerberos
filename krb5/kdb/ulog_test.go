package kdb

import (
	"testing"
	"time"

	"github.com/Exonical/go-kerberos/krb5/principal"
)

func TestUpdateLogCursorAndRetention(t *testing.T) {
	log := NewUpdateLog(2)
	name, err := principal.Parse("host/master@EXAMPLE.COM")
	if err != nil {
		t.Fatal(err)
	}
	t0 := time.Unix(100, 0).UTC()
	for i := 0; i < 3; i++ {
		log.append(UpdateLogEntry{Name: *name, Time: t0.Add(time.Duration(i) * time.Second), Commit: true})
	}
	last, stamp := log.Last()
	if last != 3 || !stamp.Equal(t0.Add(2*time.Second)) {
		t.Fatalf("last cursor = %d/%v", last, stamp)
	}
	status, updates := log.Entries(1, t0)
	if status != 2 || updates != nil {
		t.Fatalf("expired cursor = %d/%v, want full resync", status, updates)
	}
	status, updates = log.Entries(2, t0.Add(time.Second))
	if status != 0 || len(updates) != 1 || updates[0].Serial != 3 {
		t.Fatalf("retained cursor = %d/%#v", status, updates)
	}
	status, _ = log.Entries(2, t0)
	if status != 2 {
		t.Fatalf("mismatched timestamp status = %d, want full resync", status)
	}
	status, _ = log.Entries(last, stamp)
	if status != 4 {
		t.Fatalf("current cursor status = %d, want nil", status)
	}
	log.Reset()
	status, _ = log.Entries(last, stamp)
	if status != 2 {
		t.Fatalf("reset cursor status = %d, want full resync", status)
	}
}

func TestUpdateLogAcceptsZeroCursorBeforeFirstUpdate(t *testing.T) {
	log := NewUpdateLog(2)
	name, err := principal.Parse("host/master@EXAMPLE.COM")
	if err != nil {
		t.Fatal(err)
	}
	log.append(UpdateLogEntry{Name: *name, Time: time.Unix(100, 0), Commit: true})

	status, updates := log.Entries(0, time.Time{})
	if status != 0 || len(updates) != 1 || updates[0].Serial != 1 {
		t.Fatalf("zero cursor = %d/%#v, want update", status, updates)
	}
}
