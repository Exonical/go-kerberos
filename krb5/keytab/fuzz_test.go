package keytab

import (
	"bytes"
	"testing"
)

func FuzzKeytab(f *testing.F) {
	f.Add(syntheticKeytab())
	f.Add([]byte{0x05, 0x02})
	f.Fuzz(func(t *testing.T, input []byte) {
		_, _ = Read(bytes.NewReader(input))
	})
}
