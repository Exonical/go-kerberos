//go:build windows

package ccache

import "testing"

func TestMSLSAEnumeratesCurrentSession(t *testing.T) {
	handle, err := Resolve("MSLSA:")
	if err != nil {
		t.Skipf("MSLSA is unavailable: %v", err)
	}
	defer handle.Close()
	cache, err := handle.Read()
	if err != nil {
		t.Skipf("MSLSA LSA/Kerberos package is unavailable: %v", err)
	}
	if len(cache.Credentials) == 0 {
		t.Skip("MSLSA has no usable Kerberos tickets in the current logon session")
	}
}
