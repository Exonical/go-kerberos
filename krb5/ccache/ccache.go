package ccache

import (
	"fmt"
	"io"

	krberrors "github.com/Exonical/go-kerberos/krb5/errors"
)

const Version uint16 = 0x0504

type Header struct {
	TimeOffset int32
	Usec       int32
}

type Credential struct {
	Client       string
	Server       string
	TicketFlags  uint32
	Addresses    []string
	AuthData     []string
	Ticket       []byte
	SecondTicket []byte
}

type Cache struct {
	Header           Header
	DefaultPrincipal string
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
