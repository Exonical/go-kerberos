package crypto

import (
	"os"
	"path/filepath"
	"testing"
)

func FuzzDecryptAES128SHA1(f *testing.F) {
	fuzzDecrypt(f, EnctypeAES128SHA1, 16, "FuzzDecryptAES128SHA1")
}
func FuzzDecryptAES256SHA1(f *testing.F) {
	fuzzDecrypt(f, EnctypeAES256SHA1, 32, "FuzzDecryptAES256SHA1")
}
func FuzzDecryptAES128SHA256(f *testing.F) {
	fuzzDecrypt(f, EnctypeAES128SHA256, 16, "FuzzDecryptAES128SHA256")
}
func FuzzDecryptAES256SHA384(f *testing.F) {
	fuzzDecrypt(f, EnctypeAES256SHA384, 32, "FuzzDecryptAES256SHA384")
}

func fuzzDecrypt(f *testing.F, id int32, keySize int, target string) {
	f.Add(make([]byte, keySize), []byte{0})
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
		f.Add(make([]byte, keySize), data)
	}
	f.Fuzz(func(t *testing.T, key, ciphertext []byte) {
		etype, err := NewRegistry().Get(id)
		if err != nil {
			return
		}
		_, _ = etype.Decrypt(key, 1, ciphertext)
	})
}
