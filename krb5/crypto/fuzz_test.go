package crypto

import "testing"

func FuzzDecryptAES128SHA1(f *testing.F)   { fuzzDecrypt(f, EnctypeAES128SHA1, 16) }
func FuzzDecryptAES256SHA1(f *testing.F)   { fuzzDecrypt(f, EnctypeAES256SHA1, 32) }
func FuzzDecryptAES128SHA256(f *testing.F) { fuzzDecrypt(f, EnctypeAES128SHA256, 16) }
func FuzzDecryptAES256SHA384(f *testing.F) { fuzzDecrypt(f, EnctypeAES256SHA384, 32) }

func fuzzDecrypt(f *testing.F, id int32, keySize int) {
	f.Add(make([]byte, keySize), []byte{0})
	f.Fuzz(func(t *testing.T, key, ciphertext []byte) {
		etype, err := NewRegistry().Get(id)
		if err != nil {
			return
		}
		_, _ = etype.Decrypt(key, 1, ciphertext)
	})
}
