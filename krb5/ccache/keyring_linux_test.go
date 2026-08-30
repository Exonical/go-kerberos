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
	cache, err := Resolve("KEYRING:process:" + name)
	if err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) ||
			errors.Is(err, unix.ENOKEY) || errors.Is(err, unix.ENOSYS) ||
			errors.Is(err, unix.EINVAL) || errors.Is(err, unix.ENODEV) {
			t.Skipf("Linux keyring unavailable: %v", err)
		}
		t.Fatal(err)
	}
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
	again, err := Resolve("KEYRING:process:" + name)
	if err != nil {
		t.Fatal(err)
	}
	defer again.Destroy()
	if shared, err := again.Read(); err != nil || len(shared.Credentials) != 1 {
		t.Fatalf("shared keyring read = %#v, %v", shared, err)
	}
}
