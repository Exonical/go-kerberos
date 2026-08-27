package discovery

import (
	"context"
	"fmt"

	krberrors "github.com/Exonical/go-kerberos/krb5/errors"
)

type SRVRecord struct {
	Target   string
	Port     uint16
	Priority uint16
	Weight   uint16
}

type Resolver interface {
	LookupSRV(ctx context.Context, service, proto, name string) ([]SRVRecord, error)
}

type KDC struct {
	Host string
	Port uint16
}

func Discover(ctx context.Context, resolver Resolver, realm string) ([]KDC, error) {
	_, _, _ = ctx, resolver, realm
	return nil, fmt.Errorf("discover KDC: %w", krberrors.ErrNotImplemented)
}
