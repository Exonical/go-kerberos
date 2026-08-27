package keytab

import (
	"bytes"
	"os"
	"testing"
)

func FuzzKeytab(f *testing.F) {
	data, err := syntheticKeytab()
	if err != nil {
		f.Fatalf("build seed: %v", err)
	}
	f.Add(data)
	if fixture, err := os.ReadFile("../../testdata/keytabs/mit-multi-enctype.keytab"); err == nil {
		f.Add(fixture)
		if len(fixture) > 1 {
			f.Add(fixture[:len(fixture)-1])
		}
	}
	f.Add([]byte{0x05, 0x02})
	f.Fuzz(func(t *testing.T, input []byte) {
		_, _ = Read(bytes.NewReader(input))
	})
}
