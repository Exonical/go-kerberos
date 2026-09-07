package client

import (
	"context"
	"errors"
	"fmt"

	"github.com/Exonical/go-kerberos/krb5/config"
	"github.com/Exonical/go-kerberos/krb5/hostrealm"
	"github.com/Exonical/go-kerberos/krb5/krberr"
	"github.com/Exonical/go-kerberos/krb5/principal"
	"github.com/Exonical/go-kerberos/krb5/protocol"
)

// ServiceRealm resolves the target realm for a service principal. The bool
// reports whether the realm came from the principal or an explicit mapping;
// the configured default realm is a fallback for unmapped host services.
func ServiceRealm(cfg *config.Config, service principal.Principal) (string, bool) {
	if service.Realm != "" {
		return service.Realm, true
	}
	if cfg != nil && len(service.Components) > 1 {
		if realm, ok := cfg.RealmForHost(service.Components[1]); ok {
			return realm, true
		}
	}
	if cfg != nil && cfg.DefaultRealm != "" {
		return cfg.DefaultRealm, false
	}
	return "", false
}

func (c *Client) resolveServiceRealm(ctx context.Context, service principal.Principal) (string, bool, error) {
	if service.Realm != "" {
		return service.Realm, true, nil
	}
	if service.NameType == principal.NTSrvHst && len(service.Components) > 1 {
		realm, authoritative, err := hostrealm.HostRealm(ctx, c.Config, service.Components[1], hostrealm.Options{})
		if err != nil {
			return "", false, err
		}
		if realm != "" {
			return realm, authoritative, nil
		}
	}
	realm, mapped := ServiceRealm(c.Config, service)
	return realm, mapped, nil
}

func (c *Client) serviceCandidates(ctx context.Context, service principal.Principal) ([]principal.Principal, error) {
	if c == nil {
		return nil, fmt.Errorf("client: nil client")
	}
	if service.NameType == 0 {
		service.NameType = principal.NTSrvInstance
	}
	candidates, err := hostrealm.CanonicalizePrincipalCandidates(ctx, c.Config, service, hostrealm.Options{})
	if err != nil {
		return nil, err
	}
	return candidates, nil
}

func isUnknownServiceError(err error) bool {
	var kerberosError *krberr.KRBError
	return errors.As(err, &kerberosError) &&
		kerberosError.Code == krberr.KDCErrSPrincipalUnknown
}

func isReferralPrincipal(value protocol.PrincipalName, requested principal.Principal) bool {
	if len(value.NameString) != 2 || value.NameString[0] != "krbtgt" {
		return false
	}
	return requested.Realm == "" || value.NameString[1] != requested.Realm
}
