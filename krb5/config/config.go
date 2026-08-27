package config

import (
	"fmt"
	"time"

	krberrors "github.com/Exonical/go-kerberos/krb5/errors"
)

type Config struct {
	DefaultRealm            string
	DNSLookupKDC            bool
	DNSLookupRealm          bool
	RDNS                    bool
	Canonicalize            bool
	ClockSkew               time.Duration
	TicketLifetime          time.Duration
	RenewLifetime           time.Duration
	Forwardable             bool
	Proxiable               bool
	DefaultCCacheName       string
	DefaultKeytabName       string
	DefaultClientKeytabName string
	UDPPreferenceLimit      int
	PermittedEnctypes       []int32
	DefaultTKTEnctypes      []int32
	DefaultTGSEnctypes      []int32
	Realms                  map[string][]string
	DomainRealm             map[string]string
	Capaths                 map[string][]string
}

func Parse(data []byte) (*Config, error) {
	_ = data
	return nil, fmt.Errorf("parse krb5.conf: %w", krberrors.ErrNotImplemented)
}

func ParseDuration(value string) (time.Duration, error) {
	_ = value
	return 0, fmt.Errorf("parse MIT duration: %w", krberrors.ErrNotImplemented)
}
