package ccache

import "testing"

func FuzzKCMDispatchPeer(f *testing.F) {
	f.Add(kcmRequest(kcmOpGetDefaultCache))
	f.Add(kcmRequest(kcmOpGetCacheUUIDList))
	f.Add(kcmRequest(kcmOpGetPrincipal, cstring("default")))
	f.Add(kcmRequest(kcmOpGetKDCOffset, cstring("default")))
	f.Fuzz(func(t *testing.T, input []byte) {
		server := NewKCMServer("")
		_, _ = server.dispatchPeer(input, 0)
	})
}
