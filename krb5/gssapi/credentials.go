package gssapi

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/Exonical/go-kerberos/krb5/client"
	"github.com/Exonical/go-kerberos/krb5/keytab"
	"github.com/Exonical/go-kerberos/krb5/principal"
)

// CredentialUsage describes the operations for which a GSS credential is
// usable.
type CredentialUsage uint32

const (
	CredentialInitiate      CredentialUsage = 1
	CredentialAccept        CredentialUsage = 2
	CredentialBoth          CredentialUsage = CredentialInitiate | CredentialAccept
	CredentialUsageInitiate                 = CredentialInitiate
	CredentialUsageAccept                   = CredentialAccept
	CredentialUsageBoth                     = CredentialBoth
)

// Credential is a reusable GSS credential acquired for initiation, accepting,
// or both. Initiator credentials retain the TGT used to obtain service
// credentials so they can also be used for S4U acquisition.
type Credential struct {
	client *client.Client
	creds  *client.Credentials
	tgt    *client.Credentials
	keytab *keytab.Keytab
	name   *principal.Principal
	usage  CredentialUsage
}

// AcquireInitiatorCredentialWithPassword obtains initial credentials using an
// AS exchange and a password. The resulting credential is immediately usable
// with NewInitiatorForCredential.
func AcquireInitiatorCredentialWithPassword(ctx context.Context, kclient *client.Client, name principal.Principal, password string) (*Credential, error) {
	if kclient == nil {
		return nil, fmt.Errorf("GSS acquire initiator credential: nil client")
	}
	if len(name.Components) == 0 || name.Realm == "" {
		return nil, fmt.Errorf("GSS acquire initiator credential: invalid principal")
	}
	creds, err := kclient.ASExchange(ctx, name, password)
	if err != nil {
		return nil, fmt.Errorf("GSS acquire initiator credential: %w", err)
	}
	return &Credential{
		client: kclient, creds: creds, tgt: creds, name: clonePrincipal(&name),
		usage: CredentialInitiate,
	}, nil
}

// AcquireInitiatorCredential is an alias for password-based initiator
// acquisition.
func AcquireInitiatorCredential(ctx context.Context, kclient *client.Client, name principal.Principal, password string) (*Credential, error) {
	return AcquireInitiatorCredentialWithPassword(ctx, kclient, name, password)
}

// AcquireAcceptorCredential creates an acceptor credential from an explicit
// keytab. An unspecified name accepts any service principal present in it.
func AcquireAcceptorCredential(kt *keytab.Keytab, name *principal.Principal) (*Credential, error) {
	if kt == nil || len(kt.Entries) == 0 {
		return nil, fmt.Errorf("GSS acquire acceptor credential: keytab unavailable")
	}
	if name != nil && !keytabContainsPrincipal(kt, *name) {
		return nil, fmt.Errorf("GSS acquire acceptor credential: principal not found")
	}
	return &Credential{keytab: kt, name: clonePrincipal(name), usage: CredentialAccept}, nil
}

// AcquireAcceptorCredentialFromFile opens an acceptor keytab by path.
// MEMORY:name paths use the process-local named keytab registry.
func AcquireAcceptorCredentialFromFile(path string, name *principal.Principal) (*Credential, error) {
	if path == "" {
		return nil, fmt.Errorf("GSS acquire acceptor credential: empty keytab path")
	}
	if strings.HasPrefix(path, "MEMORY:") {
		kt, err := keytab.Resolve(path)
		if err != nil {
			return nil, fmt.Errorf("GSS acquire acceptor credential: %w", err)
		}
		return AcquireAcceptorCredential(kt, name)
	}
	if strings.HasPrefix(path, "FILE:") {
		path = strings.TrimPrefix(path, "FILE:")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("GSS acquire acceptor credential: %w", err)
	}
	defer file.Close()
	kt, err := keytab.Read(file)
	if err != nil {
		return nil, fmt.Errorf("GSS acquire acceptor credential: %w", err)
	}
	return AcquireAcceptorCredential(kt, name)
}

// AcquireDefaultAcceptorCredential opens KRB5_KTNAME or the conventional
// /etc/krb5.keytab.
func AcquireDefaultAcceptorCredential(name *principal.Principal) (*Credential, error) {
	path := os.Getenv("KRB5_KTNAME")
	if path == "" {
		path = "/etc/krb5.keytab"
	}
	return AcquireAcceptorCredentialFromFile(path, name)
}

// AcquireImpersonatedCredential obtains S4U2Self credentials using an
// initiator credential's service TGT.
func AcquireImpersonatedCredential(ctx context.Context, impersonator *Credential, user principal.Principal) (*Credential, error) {
	if impersonator == nil || impersonator.client == nil || impersonator.tgt == nil ||
		impersonator.usage&CredentialInitiate == 0 {
		return nil, fmt.Errorf("GSS acquire impersonated credential: incomplete impersonator")
	}
	creds, err := impersonator.client.S4U2Self(ctx, impersonator.tgt, user)
	if err != nil {
		return nil, fmt.Errorf("GSS acquire impersonated credential: %w", err)
	}
	return &Credential{
		client: impersonator.client, creds: creds, tgt: impersonator.tgt,
		name: clonePrincipal(&user), usage: CredentialInitiate,
	}, nil
}

// AcquireCredImpersonateName is a descriptive alias matching the GSS API
// operation name.
func AcquireCredImpersonateName(ctx context.Context, impersonator *Credential, user principal.Principal) (*Credential, error) {
	return AcquireImpersonatedCredential(ctx, impersonator, user)
}

// NewInitiatorForCredential creates an initiator from an acquired credential.
func (c *Credential) NewInitiatorForCredential(flags uint32) (*Initiator, error) {
	if c == nil || c.usage&CredentialInitiate == 0 || c.creds == nil {
		return nil, fmt.Errorf("GSS credential: not usable for initiation")
	}
	return NewInitiator(c.creds, flags)
}

// NewInitiatorForService obtains a service ticket from this credential's TGT
// and creates an initiator for that service. This is the GSS equivalent of
// resolving an acquired initiator credential during InitSecContext.
func (c *Credential) NewInitiatorForService(ctx context.Context, service principal.Principal, flags uint32) (*Initiator, error) {
	if c == nil || c.client == nil || c.tgt == nil ||
		c.usage&CredentialInitiate == 0 {
		return nil, fmt.Errorf("GSS credential: not usable for service initiation")
	}
	serviceCreds, err := c.client.TGSExchange(ctx, c.tgt, service)
	if err != nil {
		return nil, fmt.Errorf("GSS credential service acquisition: %w", err)
	}
	if flags&GSSDelegFlag != 0 {
		return NewInitiatorWithDelegationClient(serviceCreds, c.tgt, c.client, flags)
	}
	return NewInitiator(serviceCreds, flags)
}

// InitSecContext resolves the requested service and returns an initiator
// ready to produce its initial GSS token.
func (c *Credential) InitSecContext(ctx context.Context, service principal.Principal, flags uint32) (*Initiator, error) {
	return c.NewInitiatorForService(ctx, service, flags)
}

// Initiator is a shorthand for NewInitiatorForCredential.
func (c *Credential) Initiator(flags uint32) (*Initiator, error) {
	return c.NewInitiatorForCredential(flags)
}

// NewInitiator is the concise method form for acquired credentials.
func (c *Credential) NewInitiator(flags uint32) (*Initiator, error) {
	return c.NewInitiatorForCredential(flags)
}

// NewAcceptorForCredential creates an acceptor from an acquired keytab
// credential.
func (c *Credential) NewAcceptorForCredential() (*Acceptor, error) {
	if c == nil || c.usage&CredentialAccept == 0 || c.keytab == nil {
		return nil, fmt.Errorf("GSS credential: not usable for acceptance")
	}
	return NewAcceptorWithPrincipal(c.keytab, c.name), nil
}

// Acceptor is a shorthand for NewAcceptorForCredential.
func (c *Credential) Acceptor() (*Acceptor, error) {
	return c.NewAcceptorForCredential()
}

// NewAcceptor is the concise method form for acquired credentials.
func (c *Credential) NewAcceptor() (*Acceptor, error) {
	return c.NewAcceptorForCredential()
}

// S4U2Proxy obtains a service credential on behalf of this credential's
// impersonated client using the retained impersonator TGT.
func (c *Credential) S4U2Proxy(ctx context.Context, service principal.Principal) (*Credential, error) {
	if c == nil || c.client == nil || c.tgt == nil || c.creds == nil ||
		c.usage&CredentialInitiate == 0 {
		return nil, fmt.Errorf("GSS credential: not usable for S4U2Proxy")
	}
	creds, err := c.client.S4U2Proxy(ctx, c.tgt, c.creds, service)
	if err != nil {
		return nil, fmt.Errorf("GSS credential S4U2Proxy: %w", err)
	}
	return &Credential{
		client: c.client, creds: creds, tgt: c.tgt,
		name: clonePrincipal(&creds.Client), usage: CredentialInitiate,
	}, nil
}

func clonePrincipal(value *principal.Principal) *principal.Principal {
	if value == nil {
		return nil
	}
	copyValue := *value
	copyValue.Components = append([]string(nil), value.Components...)
	return &copyValue
}

func keytabContainsPrincipal(kt *keytab.Keytab, wanted principal.Principal) bool {
	for _, entry := range kt.Entries {
		if gssPrincipalEqual(entry.Principal, wanted) {
			return true
		}
	}
	return false
}
