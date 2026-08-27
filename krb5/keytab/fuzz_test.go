package keytab

import (
	"bytes"
	"testing"
)

func FuzzKeytab(f *testing.F) {
	data, err := syntheticKeytab()
	if err != nil {
		f.Fatalf("build seed: %v", err)
	}
	f.Add(data)
	f.Add([]byte{0x05, 0x02})
	f.Fuzz(func(t *testing.T, input []byte) {
		_, _ = Read(bytes.NewReader(input))
	})
}
