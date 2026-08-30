//go:build linux

package ccache

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestKeyringCacheReadWrite(t *testing.T) {
	name := fmt.Sprintf("go-keyring-test-%d", time.Now().UnixNano())
	cache := resolveKeyringForTest(t, "process:"+name)
	defer cache.Destroy()
	value := testCache()
	if err := cache.Write(value); err != nil {
		t.Fatalf("Write: %v", err)
	}
	got, err := cache.Read()
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if got.DefaultPrincipal.String() != value.DefaultPrincipal.String() ||
		len(got.Credentials) != len(value.Credentials) {
		t.Fatalf("keyring cache = %#v, want %#v", got, value)
	}
	again := resolveKeyringForTest(t, "process:"+name)
	if shared, err := again.Read(); err != nil || len(shared.Credentials) != 1 {
		t.Fatalf("shared keyring read = %#v, %v", shared, err)
	}
}

func TestKeyringResidualPrimaryAndSubsidiary(t *testing.T) {
	name := fmt.Sprintf("go-keyring-residual-%d", time.Now().UnixNano())
	primary := resolveKeyringForTest(t, "process:"+name)
	defer primary.Destroy()
	if err := primary.Write(testCache()); err != nil {
		t.Fatalf("write primary: %v", err)
	}

	subsidiary := resolveKeyringForTest(t, "process:"+name+":sub")
	defer subsidiary.Destroy()
	if err := subsidiary.Write(&Cache{DefaultPrincipal: testCache().DefaultPrincipal}); err != nil {
		t.Fatalf("write subsidiary: %v", err)
	}

	resolvedPrimary := resolveKeyringForTest(t, "process:"+name)
	got, err := resolvedPrimary.Read()
	if err != nil {
		t.Fatalf("read preserved primary: %v", err)
	}
	if len(got.Credentials) != 1 {
		t.Fatalf("primary credentials after subsidiary resolve = %d, want 1", len(got.Credentials))
	}
}

func TestKeyringDestroyUnlinksCache(t *testing.T) {
	name := fmt.Sprintf("go-keyring-destroy-%d", time.Now().UnixNano())
	cache := resolveKeyringForTest(t, "process:"+name+":sub")
	oldID := cache.keyring.ring
	if err := cache.Write(testCache()); err != nil {
		t.Fatalf("write cache: %v", err)
	}
	if err := cache.Destroy(); err != nil {
		t.Fatalf("destroy cache: %v", err)
	}
	if cache.keyring.ring != 0 || cache.keyring.collection != 0 {
		t.Fatal("destroy did not invalidate the keyring handle")
	}

	recreated := resolveKeyringForTest(t, "process:"+name+":sub")
	defer recreated.Destroy()
	if recreated.keyring.ring == oldID {
		t.Fatal("destroyed cache keyring remained linked to collection")
	}
	got, err := recreated.Read()
	if err != nil {
		t.Fatalf("read recreated cache: %v", err)
	}
	if got.DefaultPrincipal.Realm != "" || len(got.DefaultPrincipal.Components) != 0 ||
		len(got.Credentials) != 0 {
		t.Fatalf("recreated cache was initialized: %#v", got)
	}
}

func resolveKeyringForTest(t *testing.T, residual string) *Handle {
	t.Helper()
	cache, err := Resolve("KEYRING:" + residual)
	if err == nil {
		return cache
	}
	if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) ||
		errors.Is(err, unix.ENOKEY) || errors.Is(err, unix.ENOSYS) ||
		errors.Is(err, unix.EINVAL) || errors.Is(err, unix.ENODEV) {
		t.Skipf("Linux keyring unavailable: %v", err)
	}
	t.Fatal(err)
	return nil
}
