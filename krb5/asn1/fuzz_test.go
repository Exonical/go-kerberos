package asn1

import (
	"testing"

	"github.com/Exonical/go-kerberos/krb5/protocol"
)

func FuzzASN1Decode(f *testing.F) {
	f.Add([]byte{0x30, 0x00})
	f.Add([]byte{0x30, 0x01, 0x00})
	f.Fuzz(func(t *testing.T, input []byte) {
		var value protocol.PrincipalName
		_, _ = Marshal(value)
		_ = Unmarshal(input, &value)
	})
}

func FuzzKRBError(f *testing.F) {
	f.Add([]byte{0x7e, 0x00})
	f.Fuzz(func(t *testing.T, input []byte) {
		var value protocol.KRBError
		_ = Unmarshal(input, &value)
	})
}

func FuzzASRep(f *testing.F) {
	f.Add([]byte{0x6b, 0x00})
	f.Fuzz(func(t *testing.T, input []byte) {
		var value protocol.ASRep
		_ = Unmarshal(input, &value)
	})
}

func FuzzTGSRep(f *testing.F) {
	f.Add([]byte{0x6d, 0x00})
	f.Fuzz(func(t *testing.T, input []byte) {
		var value protocol.TGSRep
		_ = Unmarshal(input, &value)
	})
}

func FuzzAPReq(f *testing.F) {
	f.Add([]byte{0x6e, 0x00})
	f.Fuzz(func(t *testing.T, input []byte) {
		var value protocol.APReq
		_ = Unmarshal(input, &value)
	})
}
