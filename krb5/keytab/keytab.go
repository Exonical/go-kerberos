package keytab

import (
	"fmt"
	"io"

	krberrors "github.com/Exonical/go-kerberos/krb5/errors"
	"github.com/Exonical/go-kerberos/krb5/principal"
)

const Version uint16 = 0x0502

type Entry struct {
	Principal principal.Principal
	Timestamp int64
	KVNO      uint32
	Enctype   int32
	Key       []byte
}

type Keytab struct {
	Entries []Entry
}

func Read(r io.Reader) (*Keytab, error) {
	_ = r
	return nil, fmt.Errorf("read keytab: %w", krberrors.ErrNotImplemented)
}

func Write(w io.Writer, kt *Keytab) error {
	_, _ = w, kt
	return fmt.Errorf("write keytab: %w", krberrors.ErrNotImplemented)
}

func (kt *Keytab) LookupPrincipal(name principal.Principal) ([]Entry, error) {
	_ = name
	return nil, fmt.Errorf("lookup keytab principal: %w", krberrors.ErrNotImplemented)
}

func (kt *Keytab) LookupEnctype(enctype int32) ([]Entry, error) {
	_ = enctype
	return nil, fmt.Errorf("lookup keytab enctype: %w", krberrors.ErrNotImplemented)
}

func (kt *Keytab) LookupKVNO(kvno uint32) ([]Entry, error) {
	_ = kvno
	return nil, fmt.Errorf("lookup keytab kvno: %w", krberrors.ErrNotImplemented)
}
