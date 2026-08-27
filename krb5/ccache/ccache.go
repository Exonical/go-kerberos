package ccache

import (
	"fmt"
	"io"

	krberrors "github.com/Exonical/go-kerberos/krb5/errors"
	"github.com/Exonical/go-kerberos/krb5/principal"
)

const Version uint16 = 0x0504

type Header struct {
	TimeOffset int32
	Usec       int32
}

type Credential struct {
	Client       principal.Principal
	Server       principal.Principal
	TicketFlags  uint32
	AuthTime     uint32
	StartTime    uint32
	EndTime      uint32
	RenewTill    uint32
	IsSKey       bool
	Addresses    []Address
	AuthData     []AuthData
	Ticket       []byte
	SecondTicket []byte
}

type Address struct {
	Type uint16
	Data []byte
}

type AuthData struct {
	Type uint16
	Data []byte
}

type Cache struct {
	Header           Header
	DefaultPrincipal principal.Principal
	Credentials      []Credential
}

func Read(r io.Reader) (*Cache, error) {
	_ = r
	return nil, fmt.Errorf("read ccache: %w", krberrors.ErrNotImplemented)
}

func Write(w io.Writer, cache *Cache) error {
	_, _ = w, cache
	return fmt.Errorf("write ccache: %w", krberrors.ErrNotImplemented)
}
