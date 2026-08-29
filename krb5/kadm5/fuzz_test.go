package kadm5

import (
	"testing"

	"github.com/Exonical/go-kerberos/krb5/principal"
)

func FuzzDecodeEntry(f *testing.F) {
	p, err := principal.Parse("alice@EXAMPLE.COM")
	if err != nil {
		f.Fatal(err)
	}
	w := xdrWriter{}
	writeEmptyEntry(&w, *p)
	f.Add(w.bytes())
	f.Add([]byte{0, 0, 0, 0})
	f.Fuzz(func(t *testing.T, input []byte) {
		_, _ = decodeEntry(&xdrReader{b: input}, APIv4)
	})
}

func FuzzParseRPCCall(f *testing.F) {
	w := xdrWriter{}
	w.u32(1)
	w.u32(msgCall)
	w.u32(rpcVersion)
	w.u32(Program)
	w.u32(Version)
	w.u32(getPrincipal)
	w.opaqueAuth(0, nil)
	w.opaqueAuth(0, nil)
	f.Add(w.bytes())
	f.Fuzz(func(t *testing.T, input []byte) {
		_, _ = parseRPCCall(input)
	})
}
