package ccache

import (
	"bytes"
	"testing"
)

func FuzzCCache(f *testing.F) {
	data, err := syntheticCCache()
	if err != nil {
		f.Fatalf("build seed: %v", err)
	}
	f.Add(data)
	f.Add([]byte{0x05, 0x04})
	f.Fuzz(func(t *testing.T, input []byte) {
		_, _ = Read(bytes.NewReader(input))
	})
}
