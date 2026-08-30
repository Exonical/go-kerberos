package gssapi

import (
	"encoding/binary"
	"fmt"

	"github.com/Exonical/go-kerberos/krb5/crypto"
)

// GSS PRF key selectors from RFC 4402.
const (
	GSSPRFKeyFull    = 0
	GSSPRFKeyPartial = 1

	GSS_C_PRF_KEY_FULL    = GSSPRFKeyFull
	GSS_C_PRF_KEY_PARTIAL = GSSPRFKeyPartial
)

// PseudoRandom returns the RFC 4402 GSS pseudo-random function output.
// PRF_KEY_PARTIAL selects the context subkey; PRF_KEY_FULL selects the
// acceptor subkey when one was negotiated and otherwise the context subkey.
func (c *Context) PseudoRandom(keySelector int, input []byte, length int) ([]byte, error) {
	if c == nil {
		return nil, fmt.Errorf("GSS PRF: nil context")
	}
	if length < 0 {
		return nil, fmt.Errorf("GSS PRF: negative output length")
	}
	if keySelector != GSSPRFKeyFull && keySelector != GSSPRFKeyPartial {
		return nil, fmt.Errorf("GSS PRF: invalid key selector %d", keySelector)
	}
	key := c.key
	if keySelector == GSSPRFKeyPartial && len(c.prfPartial.KeyValue) != 0 {
		key = c.prfPartial
	}
	if keySelector == GSSPRFKeyFull && len(c.prfFull.KeyValue) != 0 {
		key = c.prfFull
	}
	etype, err := crypto.NewRegistry().Get(key.KeyType)
	if err != nil {
		return nil, err
	}
	if length == 0 {
		return []byte{}, nil
	}
	partLength := crypto.PRFOutputSize(etype)
	if partLength <= 0 {
		return nil, fmt.Errorf("GSS PRF: unsupported enctype %d", key.KeyType)
	}
	output := make([]byte, 0, length)
	counter := uint32(0)
	for len(output) < length {
		var prefix [4]byte
		binary.BigEndian.PutUint32(prefix[:], counter)
		prfInput := append(prefix[:], input...)
		part, err := crypto.PRF(etype, key.KeyValue, prfInput)
		if err != nil {
			return nil, err
		}
		output = append(output, part...)
		if counter == ^uint32(0) {
			return nil, fmt.Errorf("GSS PRF: output length too large")
		}
		counter++
	}
	return output[:length], nil
}

// PseudoRandom evaluates RFC 4402 using the established initiator context.
func (i *Initiator) PseudoRandom(keySelector int, input []byte, length int) ([]byte, error) {
	if i == nil || i.ctx == nil {
		return nil, fmt.Errorf("GSS PRF: context is not established")
	}
	return i.ctx.PseudoRandom(keySelector, input, length)
}
