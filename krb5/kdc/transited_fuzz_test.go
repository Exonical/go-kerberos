package kdc

import "testing"

func FuzzTransitedDecoder(f *testing.F) {
	for _, seed := range []string{"", "EDU,MIT.", ",EDU,,MIT.", `/C=US/O=MIT,/OU=KRB`, `A\\,B`} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, contents []byte) {
		_, _ = decodeTransited(contents)
	})
}
