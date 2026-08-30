package client

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Exonical/go-kerberos/krb5/asn1"
	"github.com/Exonical/go-kerberos/krb5/crypto"
	krberrors "github.com/Exonical/go-kerberos/krb5/errors"
	"github.com/Exonical/go-kerberos/krb5/keytab"
	"github.com/Exonical/go-kerberos/krb5/principal"
	"github.com/Exonical/go-kerberos/krb5/protocol"
	"github.com/Exonical/go-kerberos/krb5/types"
)

// VerifyInitCredsOptions controls VerifyInitCreds.
type VerifyInitCredsOptions struct {
	// Server selects the service principal to use for verification. When nil,
	// VerifyInitCreds tries each distinct principal in the keytab.
	Server *principal.Principal
	// NoFail controls whether an unavailable or unreadable keytab is fatal.
	NoFail bool
	// NoFailSet distinguishes an explicit NoFail value from the configuration
	// default, matching verify_ap_req_nofail.
	NoFailSet bool
}

// ASExchangeOptions controls optional post-AS verification.
type ASExchangeOptions struct {
	// Keytab supplies service keys for VerifyInitCreds.
	Keytab *keytab.Keytab
	// VerifyInitCreds enables MIT-compatible verification after the AS
	// exchange. A nil value leaves the normal AS exchange unchanged.
	VerifyInitCreds *VerifyInitCredsOptions
}

// ASExchangeWithOptions obtains initial credentials and optionally verifies
// them against a service keytab before returning them.
func (c *Client) ASExchangeWithOptions(ctx context.Context, clientPrincipal principal.Principal,
	password string, options ASExchangeOptions) (*Credentials, error) {
	creds, err := c.ASExchange(ctx, clientPrincipal, password)
	if err != nil || options.VerifyInitCreds == nil {
		return creds, err
	}
	if err := c.VerifyInitCreds(ctx, creds, options.Keytab, *options.VerifyInitCreds); err != nil {
		return nil, err
	}
	return creds, nil
}

// VerifyInitCreds verifies that a KDC knows a service key from the keytab.
//
// The service ticket is obtained with the supplied initial credentials and
// decrypted using a matching keytab entry. If no keytab key is available,
// verification succeeds by default, as in MIT krb5; set NoFailSet and NoFail
// (or verify_ap_req_nofail in the client configuration) to require it.
func (c *Client) VerifyInitCreds(ctx context.Context, creds *Credentials,
	kt *keytab.Keytab, options VerifyInitCredsOptions) error {
	if c == nil {
		return fmt.Errorf("verify initial credentials: nil client")
	}
	if ctx == nil {
		return fmt.Errorf("verify initial credentials: nil context")
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("verify initial credentials: %w", err)
	}
	if creds == nil || len(creds.Ticket) == 0 || len(creds.Key.KeyValue) == 0 {
		return fmt.Errorf("verify initial credentials: incomplete credentials")
	}

	nofail := options.NoFail
	if !options.NoFailSet {
		nofail = c.verifyInitCredsNoFail(creds.Client.Realm)
	}
	if kt == nil || len(kt.Entries) == 0 {
		if nofail {
			return fmt.Errorf("verify initial credentials: keytab unavailable")
		}
		return nil
	}

	servers := verifyInitCredsPrincipals(kt, options.Server)
	if len(servers) == 0 {
		if nofail {
			return fmt.Errorf("verify initial credentials: no usable keytab entries")
		}
		return nil
	}

	var lastErr error
	for _, server := range servers {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("verify initial credentials: %w", err)
		}
		entries := keytabEntriesForPrincipal(kt, server)
		if len(entries) == 0 {
			lastErr = fmt.Errorf("verify initial credentials: principal %s has no keytab entry", server)
			if options.Server != nil && !nofail {
				return nil
			}
			continue
		}
		candidate := creds
		if !sameClientPrincipal(creds.Server, server) {
			var err error
			candidate, err = c.TGSExchange(ctx, creds, server)
			if err != nil {
				lastErr = fmt.Errorf("verify initial credentials: obtain %s: %w", server, err)
				continue
			}
		}
		if err := verifyInitCredsTicket(candidate, server, entries, c.now(), c.clockSkew()); err == nil {
			return nil
		} else {
			lastErr = err
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("verify initial credentials: no service principal verified")
	}
	return lastErr
}

func (c *Client) verifyInitCredsNoFail(realm string) bool {
	if c.Config == nil {
		return false
	}
	values := c.Config.LibDefaultValues(realm, "verify_ap_req_nofail")
	if len(values) == 0 {
		return false
	}
	value := strings.ToLower(strings.TrimSpace(values[len(values)-1]))
	switch value {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func verifyInitCredsPrincipals(kt *keytab.Keytab, explicit *principal.Principal) []principal.Principal {
	if explicit != nil {
		return []principal.Principal{*explicit}
	}
	servers := make([]principal.Principal, 0, len(kt.Entries))
	for _, entry := range kt.Entries {
		if len(entry.Principal.Components) == 0 {
			continue
		}
		found := false
		for _, server := range servers {
			if sameClientPrincipal(server, entry.Principal) {
				found = true
				break
			}
		}
		if !found {
			servers = append(servers, entry.Principal)
		}
	}
	return servers
}

func keytabEntriesForPrincipal(kt *keytab.Keytab, server principal.Principal) []keytab.Entry {
	entries := make([]keytab.Entry, 0)
	for _, entry := range kt.Entries {
		if sameClientPrincipal(entry.Principal, server) {
			entries = append(entries, entry)
		}
	}
	return entries
}

func verifyInitCredsTicket(creds *Credentials, server principal.Principal,
	entries []keytab.Entry, now time.Time, skew time.Duration) error {
	if creds == nil || len(creds.Ticket) == 0 {
		return fmt.Errorf("verify initial credentials: missing service ticket")
	}
	var ticket protocol.Ticket
	if err := asn1.Unmarshal(creds.Ticket, &ticket); err != nil {
		return fmt.Errorf("verify initial credentials: decode service ticket: %w", err)
	}
	ticketServer := principal.Principal{
		Realm:      ticket.Realm,
		NameType:   principal.NameType(ticket.SName.NameType),
		Components: append([]string(nil), ticket.SName.NameString...),
	}
	if !sameClientPrincipal(ticketServer, server) {
		return fmt.Errorf("verify initial credentials: service principal mismatch: got %s, want %s",
			ticketServer, server)
	}
	etype, err := crypto.NewRegistry().Get(ticket.EncPart.EType)
	if err != nil {
		return fmt.Errorf("verify initial credentials: ticket enctype %d: %w",
			ticket.EncPart.EType, err)
	}
	var lastErr error
	for _, entry := range entries {
		if entry.Enctype != ticket.EncPart.EType {
			continue
		}
		if ticket.EncPart.KVNO != nil && entry.KVNO != 0 && entry.KVNO != *ticket.EncPart.KVNO {
			continue
		}
		plaintext, err := etype.Decrypt(entry.Key, 2, ticket.EncPart.Cipher)
		if err != nil {
			lastErr = err
			continue
		}
		var part protocol.EncTicketPart
		if err := asn1.Unmarshal(plaintext, &part); err != nil {
			lastErr = err
			continue
		}
		if part.CRealm != creds.Client.Realm ||
			!sameProtocolPrincipal(part.CName, creds.Client) {
			lastErr = errors.New("decrypted ticket client principal mismatch")
			continue
		}
		if part.Flags&types.TicketInvalid != 0 {
			lastErr = krberrors.ErrTicketInvalid
			continue
		}
		if !verifyInitCredsTicketValid(part, now, skew) {
			lastErr = krberrors.ErrTicketExpired
			continue
		}
		return nil
	}
	if lastErr == nil {
		lastErr = krberrors.ErrIntegrity
	}
	return fmt.Errorf("verify initial credentials: decrypt service ticket: %w", lastErr)
}

func (c *Client) now() time.Time {
	now := time.Now().UTC()
	if c.Now != nil {
		now = c.Now().UTC()
	}
	return now
}

func verifyInitCredsTicketValid(part protocol.EncTicketPart, now time.Time, skew time.Duration) bool {
	if skew < 0 {
		skew = -skew
	}
	if !part.EndTime.Present || part.EndTime.Time.Before(now.Add(-skew)) {
		return false
	}
	if part.StartTime != nil && part.StartTime.Present &&
		part.StartTime.Time.After(now.Add(skew)) {
		return false
	}
	return true
}

func sameClientPrincipal(a, b principal.Principal) bool {
	if !strings.EqualFold(a.Realm, b.Realm) || len(a.Components) != len(b.Components) {
		return false
	}
	for i := range a.Components {
		if a.Components[i] != b.Components[i] {
			return false
		}
	}
	return true
}
