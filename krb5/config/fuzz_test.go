package config

import "testing"

func FuzzConfig(f *testing.F) {
	f.Add([]byte(sampleConfig))
	f.Add([]byte("[broken"))
	f.Fuzz(func(t *testing.T, input []byte) {
		_, _ = Parse(input)
	})
}
