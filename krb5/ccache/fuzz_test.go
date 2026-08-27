package ccache

import (
	"bytes"
	"testing"
)

func FuzzCCache(f *testing.F) {
	f.Add(syntheticCCache())
	f.Add([]byte{0x05, 0x04})
	f.Fuzz(func(t *testing.T, input []byte) {
		_, _ = Read(bytes.NewReader(input))
	})
}
