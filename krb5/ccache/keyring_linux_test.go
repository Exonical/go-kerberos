//go:build linux

package ccache

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestKeyringCacheReadWrite(t *testing.T) {
	name := fmt.Sprintf("go-keyring-test-%d", time.Now().UnixNano())
	cache := resolveKeyringForTest(t, "process:"+name)
	defer cache.Destroy()
	value := testCache()
	if err := writeKeyringForTest(t, cache, value); err != nil {
		t.Fatalf("Write: %v", err)
	}
	got, err := readKeyringForTest(t, cache)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if got.DefaultPrincipal.String() != value.DefaultPrincipal.String() ||
		len(got.Credentials) != len(value.Credentials) {
		t.Fatalf("keyring cache = %#v, want %#v", got, value)
	}
	again := resolveKeyringForTest(t, "process:"+name)
	if shared, err := readKeyringForTest(t, again); err != nil || len(shared.Credentials) != 1 {
		t.Fatalf("shared keyring read = %#v, %v", shared, err)
	}
}

func TestKeyringStorePreservesConcurrentCredentials(t *testing.T) {
	name := fmt.Sprintf("go-keyring-store-%d", time.Now().UnixNano())
	first := resolveKeyringForTest(t, "process:"+name+":cache")
	defer first.Destroy()
	second := resolveKeyringForTest(t, "process:"+name+":cache")
	if err := writeKeyringForTest(t, first, &Cache{DefaultPrincipal: testCache().DefaultPrincipal}); err != nil {
		t.Fatal(err)
	}
	base := testCache().Credentials[0]
	firstCredential := base
	firstCredential.Server.Components = []string{"service", "one"}
	secondCredential := base
	secondCredential.Server.Components = []string{"service", "two"}
	secondCredential.Ticket = []byte("ticket-two")
	var wg sync.WaitGroup
	var errorsMu sync.Mutex
	var storeErrors []error
	for _, item := range []struct {
		cache *Handle
		value Credential
	}{{first, firstCredential}, {second, secondCredential}} {
		wg.Add(1)
		go func(item struct {
			cache *Handle
			value Credential
		}) {
			defer wg.Done()
			if err := item.cache.Store(item.value); err != nil {
				errorsMu.Lock()
				storeErrors = append(storeErrors, err)
				errorsMu.Unlock()
			}
		}(item)
	}
	wg.Wait()
	for _, err := range storeErrors {
		if isKeyringUnavailable(err) {
			t.Skipf("Linux keyring unavailable during concurrent store: %v", err)
		}
		t.Errorf("Store: %v", err)
	}
	if len(storeErrors) != 0 {
		return
	}
	cache, err := readKeyringForTest(t, first)
	if err != nil {
		t.Fatal(err)
	}
	if len(cache.Credentials) != 2 {
		t.Fatalf("stored credentials = %d, want 2", len(cache.Credentials))
	}
}

func TestKeyringFailedMarshalPreservesCache(t *testing.T) {
	name := fmt.Sprintf("go-keyring-marshal-%d", time.Now().UnixNano())
	cache := resolveKeyringForTest(t, "process:"+name+":cache")
	defer cache.Destroy()
	original := testCache()
	if err := writeKeyringForTest(t, cache, original); err != nil {
		t.Fatal(err)
	}
	bad := testCache()
	bad.Credentials[0].Enctype = -1
	if err := cache.Write(bad); err == nil {
		t.Fatal("invalid credential write unexpectedly succeeded")
	}
	got, err := readKeyringForTest(t, cache)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Credentials) != 1 || got.Credentials[0].Ticket[0] != 't' {
		t.Fatalf("cache after failed write = %#v", got)
	}
	if err := cache.Store(bad.Credentials[0]); err == nil {
		t.Fatal("invalid credential store unexpectedly succeeded")
	}
	got, err = readKeyringForTest(t, cache)
	if err != nil || len(got.Credentials) != 1 {
		t.Fatalf("cache after failed store = %#v, %v", got, err)
	}
}

func TestKeyringRetrieveMapsMITMatchFlags(t *testing.T) {
	name := fmt.Sprintf("go-keyring-match-%d", time.Now().UnixNano())
	cache := resolveKeyringForTest(t, "process:"+name+":cache")
	defer cache.Destroy()
	value := testCache().Credentials[0]
	if err := storeKeyringForTest(t, cache, value); err != nil {
		t.Fatal(err)
	}
	match := value
	match.Server.Realm = "OTHER.REALM"
	got, err := cache.Retrieve(match, MITMatchServerName)
	if err != nil {
		t.Fatalf("Retrieve with MIT server-name flag: %v", err)
	}
	if got.Server.Realm != value.Server.Realm {
		t.Fatalf("retrieved credential realm = %q, want %q", got.Server.Realm, value.Server.Realm)
	}
}

func TestKeyringRemoveUnlinksMatchingCredentials(t *testing.T) {
	name := fmt.Sprintf("go-keyring-remove-%d", time.Now().UnixNano())
	cache := resolveKeyringForTest(t, "process:"+name+":cache")
	defer cache.Destroy()
	base := testCache().Credentials[0]
	keep := base
	keep.Server.Components = []string{"service", "keep"}
	remove := base
	remove.Server.Components = []string{"service", "remove"}
	if err := storeKeyringForTest(t, cache, keep); err != nil {
		t.Fatal(err)
	}
	if err := storeKeyringForTest(t, cache, remove); err != nil {
		t.Fatal(err)
	}
	if err := cache.Remove(remove, 0); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	got, err := readKeyringForTest(t, cache)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Credentials) != 1 || got.Credentials[0].Server.Components[1] != "keep" {
		t.Fatalf("credentials after remove = %#v", got.Credentials)
	}
}

func TestKeyringCollectionEnumeratesPrimaryFirst(t *testing.T) {
	name := fmt.Sprintf("go-keyring-collection-%d", time.Now().UnixNano())
	primary := resolveKeyringForTest(t, "process:"+name)
	defer primary.Destroy()
	if err := writeKeyringForTest(t, primary, testCache()); err != nil {
		t.Fatal(err)
	}
	for _, subsidiaryName := range []string{"subsidiary-a", "subsidiary-b"} {
		cache := resolveKeyringForTest(t, "process:"+name+":"+subsidiaryName)
		defer cache.Destroy()
		if err := writeKeyringForTest(t, cache, testCache()); err != nil {
			t.Fatal(err)
		}
	}
	caches, err := primary.Collection()
	if err != nil {
		t.Fatal(err)
	}
	if len(caches) != 3 {
		t.Fatalf("collection length = %d, want 3", len(caches))
	}
	if caches[0].keyring.name != primary.keyring.name {
		t.Fatalf("primary cache = %q, want %q", caches[0].keyring.name, primary.keyring.name)
	}
	seen := make(map[string]bool)
	for _, cache := range caches {
		if seen[cache.Name()] {
			t.Fatalf("duplicate cache %q", cache.Name())
		}
		seen[cache.Name()] = true
	}
}

func TestKeyringRejectsInvalidNames(t *testing.T) {
	if _, err := Resolve("KEYRING:session:bad\x00name"); err == nil {
		t.Fatal("NUL collection name unexpectedly accepted")
	}
	oversized := strings.Repeat("x", keyringDescriptionLimit)
	if _, err := Resolve("KEYRING:session:" + oversized); err == nil {
		t.Fatal("oversized collection name unexpectedly accepted")
	}
	name := fmt.Sprintf("go-keyring-invalid-credential-%d", time.Now().UnixNano())
	cache := resolveKeyringForTest(t, "process:"+name+":cache")
	defer cache.Destroy()
	invalid := testCache().Credentials[0]
	invalid.Server.Components = []string{"service\x00name"}
	if err := cache.Store(invalid); err == nil {
		t.Fatal("NUL credential name unexpectedly accepted")
	}
	invalid.Server.Components = []string{strings.Repeat("x", keyringDescriptionLimit)}
	if err := cache.Store(invalid); err == nil {
		t.Fatal("oversized credential name unexpectedly accepted")
	}
}

func TestKeyringResidualPrimaryAndSubsidiary(t *testing.T) {
	name := fmt.Sprintf("go-keyring-residual-%d", time.Now().UnixNano())
	primary := resolveKeyringForTest(t, "process:"+name)
	defer primary.Destroy()
	if err := writeKeyringForTest(t, primary, testCache()); err != nil {
		t.Fatalf("write primary: %v", err)
	}

	subsidiary := resolveKeyringForTest(t, "process:"+name+":sub")
	defer subsidiary.Destroy()
	if err := writeKeyringForTest(t, subsidiary, &Cache{DefaultPrincipal: testCache().DefaultPrincipal}); err != nil {
		t.Fatalf("write subsidiary: %v", err)
	}

	resolvedPrimary := resolveKeyringForTest(t, "process:"+name)
	got, err := readKeyringForTest(t, resolvedPrimary)
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
	if err := writeKeyringForTest(t, cache, testCache()); err != nil {
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
	got, err := readKeyringForTest(t, recreated)
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
		probeName := fmt.Sprintf("go-keyring-probe-%d", time.Now().UnixNano())
		probeID, probeErr := unix.AddKey("user", probeName, []byte("probe"), cache.keyring.ring)
		if probeErr == nil {
			_, _ = unix.KeyctlInt(unix.KEYCTL_UNLINK, probeID, cache.keyring.ring, 0, 0)
		} else if isKeyringUnavailable(probeErr) {
			_ = cache.Destroy()
			t.Skipf("Linux keyring unavailable: %v", probeErr)
		} else {
			_ = cache.Destroy()
			t.Fatalf("probe KEYRING write: %v", probeErr)
		}
		bigProbeName := fmt.Sprintf("go-keyring-big-probe-%d", time.Now().UnixNano())
		bigProbeID, bigProbeErr := unix.AddKey("big_key", bigProbeName, []byte("probe"), cache.keyring.ring)
		if bigProbeErr == nil {
			_, _ = unix.KeyctlInt(unix.KEYCTL_UNLINK, bigProbeID, cache.keyring.ring, 0, 0)
		} else if !errors.Is(bigProbeErr, unix.EINVAL) && !errors.Is(bigProbeErr, unix.ENODEV) {
			if isKeyringUnavailable(bigProbeErr) {
				_ = cache.Destroy()
				t.Skipf("Linux big_key unavailable: %v", bigProbeErr)
			}
			_ = cache.Destroy()
			t.Fatalf("probe KEYRING big_key write: %v", bigProbeErr)
		}
		if _, listErr := keyringList(cache.keyring.ring); listErr != nil {
			if isKeyringUnavailable(listErr) {
				_ = cache.Destroy()
				t.Skipf("Linux keyring unavailable: %v", listErr)
			}
			_ = cache.Destroy()
			t.Fatalf("probe KEYRING read: %v", listErr)
		}
		return cache
	}
	if isKeyringUnavailable(err) {
		t.Skipf("Linux keyring unavailable: %v", err)
	}
	t.Fatal(err)
	return nil
}

func storeKeyringForTest(t *testing.T, cache *Handle, credential Credential) error {
	t.Helper()
	err := cache.Store(credential)
	if isKeyringUnavailable(err) {
		t.Skipf("Linux keyring unavailable during store: %v", err)
	}
	return err
}

func writeKeyringForTest(t *testing.T, cache *Handle, value *Cache) error {
	t.Helper()
	err := cache.Write(value)
	if isKeyringUnavailable(err) {
		t.Skipf("Linux keyring unavailable during write: %v", err)
	}
	return err
}

func readKeyringForTest(t *testing.T, cache *Handle) (*Cache, error) {
	t.Helper()
	value, err := cache.Read()
	if isKeyringUnavailable(err) {
		t.Skipf("Linux keyring unavailable during read: %v", err)
	}
	return value, err
}

func isKeyringUnavailable(err error) bool {
	return errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) ||
		errors.Is(err, unix.ENOKEY) || errors.Is(err, unix.ENOSYS) ||
		errors.Is(err, unix.EINVAL) || errors.Is(err, unix.ENODEV) ||
		errors.Is(err, unix.ENOSPC) || errors.Is(err, unix.EDQUOT)
}
