package gssapi

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Exonical/go-kerberos/krb5/ccache"
	"github.com/Exonical/go-kerberos/krb5/client"
	"github.com/Exonical/go-kerberos/krb5/config"
	"github.com/Exonical/go-kerberos/krb5/keytab"
	"github.com/Exonical/go-kerberos/krb5/principal"
	"github.com/Exonical/go-kerberos/krb5/protocol"
	"github.com/Exonical/go-kerberos/krb5/types"
)

// CredStoreElement is one MIT GSS credential-store element.
type CredStoreElement struct {
	Key   string
	Value string
}

// CredStore is an ordered collection of credential-store elements.
type CredStore []CredStoreElement

var (
	ErrDuplicateStoreElement = errors.New("GSS credential store: duplicate element")
	ErrUnsupportedStore      = errors.New("GSS credential store: unsupported operation")
)

// Lookup returns the value for key. Unknown keys are intentionally ignored,
// matching MIT's kg_value_from_cred_store behavior.
func (s CredStore) Lookup(key string) (string, bool, error) {
	var value string
	found := false
	for _, element := range s {
		if element.Key != key {
			continue
		}
		if found {
			return "", false, fmt.Errorf("%w %q", ErrDuplicateStoreElement, key)
		}
		value, found = element.Value, true
	}
	return value, found, nil
}

func (s CredStore) values() (map[string]string, error) {
	result := make(map[string]string)
	for _, key := range []string{"ccache", "client_keytab", "keytab", "rcache", "password", "verify"} {
		value, ok, err := s.Lookup(key)
		if err != nil {
			return nil, err
		}
		if ok {
			result[key] = value
		}
	}
	return result, nil
}

// AcquireCredentialFrom acquires an initiator or acceptor credential using
// MIT-style credential-store elements. Unknown elements are ignored.
func AcquireCredentialFrom(ctx context.Context, kclient *client.Client, name *principal.Principal,
	usage CredentialUsage, store CredStore) (*Credential, error) {
	values, err := store.values()
	if err != nil {
		return nil, err
	}
	if usage&CredentialInitiate != 0 {
		if kclient == nil {
			return nil, fmt.Errorf("GSS acquire credential: nil client")
		}
		if cacheName := values["ccache"]; cacheName != "" {
			return acquireInitiatorFromCache(kclient, name, cacheName)
		}
		if password, ok := values["password"]; ok {
			if name == nil {
				return nil, fmt.Errorf("GSS acquire credential: password acquisition requires a name")
			}
			options := client.ASExchangeOptions{}
			if truthy(values["verify"]) {
				path := values["keytab"]
				kt, err := keytab.ResolveWithConfig(path, kclient.Config)
				if err != nil {
					return nil, fmt.Errorf("GSS acquire credential verify keytab: %w", err)
				}
				options.Keytab = kt
				options.VerifyInitCreds = &client.VerifyInitCredsOptions{}
			}
			creds, err := kclient.ASExchangeWithOptions(ctx, *name, password, options)
			if err != nil {
				return nil, fmt.Errorf("GSS acquire credential password: %w", err)
			}
			return &Credential{
				client: kclient, creds: creds, tgt: creds, name: clonePrincipal(name),
				usage: CredentialInitiate, password: password,
			}, nil
		}
		if path, ok := values["client_keytab"]; ok || values["keytab"] != "" {
			if name == nil {
				return nil, fmt.Errorf("GSS acquire credential: keytab acquisition requires a name")
			}
			if !ok {
				path = values["keytab"]
			}
			kt, err := keytab.ResolveClientWithConfig(path, kclient.Config)
			if err != nil {
				return nil, fmt.Errorf("GSS acquire credential client keytab: %w", err)
			}
			entries, err := kt.LookupPrincipal(*name)
			if err != nil || len(entries) == 0 {
				return nil, fmt.Errorf("GSS acquire credential client keytab: principal not found")
			}
			service := principal.Principal{
				Realm: name.Realm, NameType: principal.NTSrvInstance,
				Components: []string{"krbtgt", name.Realm},
			}
			creds, err := kclient.ASExchangeServiceWithKey(ctx, *name, entries[0], service)
			if err != nil {
				return nil, fmt.Errorf("GSS acquire credential client keytab: %w", err)
			}
			return &Credential{
				client: kclient, creds: creds, tgt: creds, name: clonePrincipal(name),
				usage: CredentialInitiate, keytab: kt, clientKeytabName: path,
			}, nil
		}
	}
	if usage&CredentialAccept != 0 {
		path := values["keytab"]
		var cfg *config.Config
		if kclient != nil {
			cfg = kclient.Config
		}
		kt, err := keytab.ResolveWithConfig(path, cfg)
		if err != nil {
			return nil, fmt.Errorf("GSS acquire credential acceptor keytab: %w", err)
		}
		cred, err := AcquireAcceptorCredential(kt, name)
		if err != nil {
			return nil, err
		}
		cred.keytabName = path
		cred.rcacheName = values["rcache"]
		cred.usage = usage
		return cred, nil
	}
	return nil, fmt.Errorf("GSS acquire credential: invalid usage")
}

// StoreCredentialInto stores initiator credentials in a named cache.
func StoreCredentialInto(cred *Credential, usage CredentialUsage, overwrite, defaultCred bool,
	store CredStore) error {
	if usage&CredentialAccept != 0 {
		return fmt.Errorf("GSS store credential: acceptor credentials are unsupported")
	}
	if cred == nil || cred.creds == nil || cred.usage&CredentialInitiate == 0 {
		return fmt.Errorf("GSS store credential: credential has no initiator credentials")
	}
	values, err := store.values()
	if err != nil {
		return err
	}
	name := values["ccache"]
	if name == "" {
		name = cred.cacheName
	}
	if name == "" {
		name = os.Getenv("KRB5CCNAME")
	}
	if name == "" {
		owner := os.Getenv("USER")
		if owner == "" {
			owner = os.Getenv("USERNAME")
		}
		if owner == "" {
			owner = "default"
		}
		name = "FILE:" + filepath.Join(os.TempDir(), "krb5cc_"+owner)
	}
	var cfg *config.Config
	if cred.client != nil {
		cfg = cred.client.Config
	}
	target, err := ccache.ResolveWithConfig(name, cfg)
	if err != nil {
		return fmt.Errorf("GSS store credential: %w", err)
	}
	defer target.Close()

	cacheValue := credentialCache(cred)
	if target.Type() == ccache.TypeDir || target.Type() == ccache.TypeKCM ||
		target.Type() == ccache.TypeKeyring {
		caches, err := target.Collection()
		if err != nil {
			return err
		}
		var selected *ccache.Handle
		for _, candidate := range caches {
			current, readErr := candidate.Read()
			if readErr != nil {
				continue
			}
			if gssPrincipalEqual(current.DefaultPrincipal, cred.creds.Client) {
				selected = candidate
				if !overwrite {
					return fmt.Errorf("%w for %s", ErrDuplicateStoreElement, cred.creds.Client.String())
				}
				break
			}
			_ = candidate.Close()
		}
		if selected == nil {
			selected, err = target.New()
			if err != nil {
				return err
			}
		}
		defer selected.Close()
		if err := selected.Write(cacheValue); err != nil {
			return err
		}
		if defaultCred {
			return selected.SetPrimary()
		}
		return nil
	}
	existing, readErr := target.Read()
	if readErr == nil && len(existing.DefaultPrincipal.Components) != 0 &&
		!overwrite {
		return fmt.Errorf("%w for %s", ErrDuplicateStoreElement, cred.creds.Client.String())
	}
	if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
		return readErr
	}
	return target.Write(cacheValue)
}

// StoreCredential stores an initiator credential in the default cache.
func StoreCredential(cred *Credential, usage CredentialUsage, overwrite, defaultCred bool) error {
	return StoreCredentialInto(cred, usage, overwrite, defaultCred, nil)
}

func acquireInitiatorFromCache(kclient *client.Client, name *principal.Principal,
	cacheName string) (*Credential, error) {
	handle, err := ccache.ResolveWithConfig(cacheName, kclient.Config)
	if err != nil {
		return nil, err
	}
	defer handle.Close()
	cache, err := handle.Read()
	if err != nil {
		return nil, fmt.Errorf("GSS acquire credential ccache: %w", err)
	}
	if name != nil && !gssPrincipalEqual(cache.DefaultPrincipal, *name) {
		return nil, fmt.Errorf("GSS acquire credential ccache: principal mismatch")
	}
	var tgt, service *client.Credentials
	for _, entry := range cache.Credentials {
		converted := fromCCacheCredential(entry)
		if isTGT(entry.Server) {
			if tgt == nil {
				tgt = converted
			}
		} else if service == nil {
			service = converted
		}
	}
	if tgt == nil && service == nil {
		return nil, fmt.Errorf("GSS acquire credential ccache: no credentials")
	}
	if tgt == nil {
		tgt = service
	}
	if service == nil {
		service = tgt
	}
	return &Credential{
		client: kclient, creds: service, tgt: tgt, name: clonePrincipal(&cache.DefaultPrincipal),
		usage: CredentialInitiate, cache: cache, cacheName: handle.Name(),
	}, nil
}

func credentialCache(cred *Credential) *ccache.Cache {
	var result ccache.Cache
	if cred.cache != nil {
		result = *cloneCCache(cred.cache)
	}
	result.DefaultPrincipal = cred.creds.Client
	entries := make([]ccache.Credential, 0, 2)
	if cred.tgt != nil {
		entries = append(entries, cred.tgt.ToCCacheCredential())
	}
	if cred.creds != nil && (cred.tgt == nil || !gssPrincipalEqual(cred.creds.Server, cred.tgt.Server)) {
		entries = append(entries, cred.creds.ToCCacheCredential())
	}
	result.Credentials = entries
	return &result
}

func cloneCCache(value *ccache.Cache) *ccache.Cache {
	if value == nil {
		return &ccache.Cache{}
	}
	result := *value
	result.Credentials = append([]ccache.Credential(nil), value.Credentials...)
	for i := range result.Credentials {
		result.Credentials[i].Key = append([]byte(nil), value.Credentials[i].Key...)
		result.Credentials[i].Ticket = append([]byte(nil), value.Credentials[i].Ticket...)
		result.Credentials[i].SecondTicket = append([]byte(nil), value.Credentials[i].SecondTicket...)
	}
	return &result
}

func fromCCacheCredential(value ccache.Credential) *client.Credentials {
	result := &client.Credentials{
		Client: value.Client, Server: value.Server,
		Key:   protocol.EncryptionKey{KeyType: value.Enctype, KeyValue: append([]byte(nil), value.Key...)},
		Flags: types.TicketFlags(value.TicketFlags), IsSKey: value.IsSKey,
		AuthTime: kerberosTime(value.AuthTime), EndTime: kerberosTime(value.EndTime),
		Ticket: append([]byte(nil), value.Ticket...), SecondTicket: append([]byte(nil), value.SecondTicket...),
	}
	if value.StartTime != 0 {
		start := kerberosTime(value.StartTime)
		result.StartTime = &start
	}
	if value.RenewTill != 0 {
		renew := kerberosTime(value.RenewTill)
		result.RenewTill = &renew
	}
	return result
}

func kerberosTime(value uint32) types.KerberosTime {
	if value == 0 {
		return types.KerberosTime{}
	}
	return types.KerberosTime{Time: time.Unix(int64(value), 0).UTC(), Present: true}
}

func isTGT(value principal.Principal) bool {
	return len(value.Components) == 2 && value.Components[0] == "krbtgt" && value.Components[1] == value.Realm
}

func truthy(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return false
	}
	if parsed, err := strconv.ParseBool(value); err == nil {
		return parsed
	}
	return value == "yes" || value == "on" || value == "enabled"
}
