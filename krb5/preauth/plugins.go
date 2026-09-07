package preauth

import (
	"context"
	"fmt"

	krberrors "github.com/Exonical/go-kerberos/krb5/errors"
	"github.com/Exonical/go-kerberos/krb5/principal"
	"github.com/Exonical/go-kerberos/krb5/protocol"
)

const (
	PAReal  = 0x00000001
	PAInfo  = 0x00000002
	PA_REAL = PAReal
	PA_INFO = PAInfo
)

type PAData = protocol.PAData

type ASReqInfo struct {
	Client        principal.Principal
	Request       protocol.ASReq
	RequestBody   []byte
	PreviousError *krberrors.KRBError
}

type ClientRequestContext struct {
	Client      principal.Principal
	Request     *protocol.ASReq
	RequestBody []byte
	EType       int32
	ArmorKey    *protocol.EncryptionKey
	State       map[string]any
	ASKey       protocol.EncryptionKey
	HasASKey    bool
}

func (c *ClientRequestContext) GetEType() int32 {
	if c == nil {
		return 0
	}
	return c.EType
}

func (c *ClientRequestContext) GetASKey() (protocol.EncryptionKey, error) {
	if c == nil || !c.HasASKey {
		return protocol.EncryptionKey{}, fmt.Errorf("preauth: AS key is unavailable")
	}
	return c.ASKey, nil
}

func (c *ClientRequestContext) SetASKey(key protocol.EncryptionKey) error {
	if c == nil || len(key.KeyValue) == 0 {
		return fmt.Errorf("preauth: invalid AS key")
	}
	c.ASKey = protocol.EncryptionKey{
		KeyType:  key.KeyType,
		KeyValue: append([]byte(nil), key.KeyValue...),
	}
	c.HasASKey = true
	return nil
}

func (c *ClientRequestContext) FastArmor() *protocol.EncryptionKey {
	if c == nil || c.ArmorKey == nil {
		return nil
	}
	return c.ArmorKey
}

type ClientPreauthModule interface {
	Name() string
	PATypes() []int32
	Flags(paType int32) int
	Process(ctx *ClientRequestContext, pa PAData, req ASReqInfo) ([]PAData, error)
}

// TryAgainer is exported for forward compatibility; the AS retry loop does
// not invoke it yet.
type TryAgainer interface {
	TryAgain(ctx context.Context, pa PAData, req ASReqInfo, cause error) ([]PAData, error)
}
