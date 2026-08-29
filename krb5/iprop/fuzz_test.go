package iprop

import "testing"

func FuzzUnmarshalLast(f *testing.F) {
	f.Add(Last{LastSno: 1, LastTime: Time{Seconds: 2, Useconds: 3}}.MarshalXDR())
	f.Fuzz(func(t *testing.T, input []byte) {
		_, _ = UnmarshalLast(input)
	})
}

func FuzzUnmarshalIncrementalResult(f *testing.F) {
	f.Add((IncrementalResult{Ret: UpdateOK}).MarshalXDR())
	f.Fuzz(func(t *testing.T, input []byte) {
		_, _ = UnmarshalIncrementalResult(input)
	})
}

func FuzzUnmarshalFullResyncResult(f *testing.F) {
	f.Add((FullResyncResult{Ret: UpdateOK}).MarshalXDR())
	f.Fuzz(func(t *testing.T, input []byte) {
		_, _ = UnmarshalFullResyncResult(input)
	})
}
