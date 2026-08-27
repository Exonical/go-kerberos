package ccache

import (
	"bytes"
	"os"
	"testing"
)

func FuzzCCache(f *testing.F) {
	data, err := syntheticCCache()
	if err != nil {
		f.Fatalf("build seed: %v", err)
	}
	f.Add(data)
	if fixture, err := os.ReadFile("../../testdata/ccaches/mit-alice.ccache"); err == nil {
		f.Add(fixture)
		if len(fixture) > 1 {
			f.Add(fixture[:len(fixture)-1])
		}
	}
	f.Add([]byte{0x05, 0x04})
	f.Fuzz(func(t *testing.T, input []byte) {
		_, _ = Read(bytes.NewReader(input))
	})
}
