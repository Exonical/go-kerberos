package config

import (
	"os"
	"path/filepath"
	"testing"
)

func FuzzConfig(f *testing.F) {
	f.Add([]byte(sampleConfig))
	f.Add([]byte("[broken"))
	addMITFuzzSeeds(f, "FuzzConfig")
	f.Fuzz(func(t *testing.T, input []byte) {
		_, _ = Parse(input)
	})
}

func addMITFuzzSeeds(f *testing.F, target string) {
	dir := filepath.Join("..", "..", "testdata", "mit", "fuzz", target)
	entries, err := os.ReadDir(dir)
	if err != nil {
		f.Fatalf("read MIT fuzz seeds: %v", err)
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			f.Fatalf("read MIT fuzz seed %s: %v", entry.Name(), err)
		}
		f.Add(data)
	}
}
