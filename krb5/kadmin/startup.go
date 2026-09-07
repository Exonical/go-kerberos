package kadmin

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Exonical/go-kerberos/krb5/ccache"
	"github.com/Exonical/go-kerberos/krb5/client"
	"github.com/Exonical/go-kerberos/krb5/config"
	"github.com/Exonical/go-kerberos/krb5/kadm5"
	"github.com/Exonical/go-kerberos/krb5/kdb"
	"github.com/Exonical/go-kerberos/krb5/kdb/mitdump"
	"github.com/Exonical/go-kerberos/krb5/keytab"
	"github.com/Exonical/go-kerberos/krb5/principal"
	"github.com/Exonical/go-kerberos/krb5/protocol"
	"github.com/Exonical/go-kerberos/krb5/types"
)

// StartupOptions contains the common command-line startup state.
type StartupOptions struct {
	Realm, Principal, Query, Password, KeySalts string
	Server, CCache, Keytab, Dump                string
	KeytabAuth, MasterPassword                  bool
	Command                                     []string
}

// ParseStartup parses the supported MIT kadmin startup options.
func ParseStartup(args []string, local bool) (StartupOptions, error) {
	var o StartupOptions
	fs := flag.NewFlagSet("gokadmin", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.StringVar(&o.Realm, "r", "", "realm")
	fs.StringVar(&o.Principal, "p", "", "principal")
	fs.StringVar(&o.Query, "q", "", "query")
	fs.StringVar(&o.Password, "w", "", "password")
	fs.StringVar(&o.KeySalts, "e", "", "keysalts")
	if local {
		fs.StringVar(&o.Dump, "d", "", "dump file")
		fs.BoolVar(&o.MasterPassword, "m", false, "master password")
	} else {
		fs.StringVar(&o.Server, "s", "", "admin server")
		fs.StringVar(&o.CCache, "c", "", "ccache")
		fs.BoolVar(&o.KeytabAuth, "k", false, "keytab authentication")
		fs.StringVar(&o.Keytab, "t", "", "keytab")
	}
	for _, unsupported := range []string{"n", "O", "N", "x"} {
		fs.Bool(unsupported, false, "unsupported")
	}
	if err := fs.Parse(args); err != nil {
		return o, err
	}
	if fs.Lookup("n") != nil {
		for _, name := range []string{"n", "O", "N", "x"} {
			if value := fs.Lookup(name); value != nil && value.Value.String() != "false" {
				return o, fmt.Errorf("-%s: not supported", name)
			}
		}
	}
	if !local && o.CCache != "" && o.KeytabAuth {
		return o, errors.New("-c and -k are mutually exclusive")
	}
	if !local && o.Keytab != "" && !o.KeytabAuth {
		return o, errors.New("-t requires -k")
	}
	o.Command = fs.Args()
	return o, nil
}

// LoadLocalDatabase loads a MIT dump into a mutable database.
func LoadLocalDatabase(path, realm, password string) (*kdb.Database, error) {
	db, _, err := loadLocalDatabase(path, realm, password)
	return db, err
}

func loadLocalDatabase(path, realm, password string) (*kdb.Database, *mitdump.FileStore, error) {
	var store *mitdump.FileStore
	var err error
	if path == "" {
		return kdb.NewDatabase(realm), nil, nil
	}
	if password != "" {
		store, err = mitdump.LoadWithMasterPassword(path, password)
	} else {
		store, err = mitdump.Load(path)
		if err != nil {
			stash, stashErr := resolveStashFile(realm)
			if stashErr == nil {
				store, err = mitdump.LoadWithStash(path, stash)
			}
		}
	}
	if err != nil {
		return nil, nil, err
	}
	if realm == "" {
		realm = store.Realm
	}
	db := kdb.NewDatabase(realm)
	for _, policy := range store.Policies() {
		if err := db.CreatePolicy(policy); err != nil {
			return nil, nil, err
		}
	}
	for _, record := range store.Records() {
		if err := db.ImportPrincipal(record); err != nil {
			return nil, nil, err
		}
	}
	return db, store, nil
}

func resolveStashFile(realm string) (string, error) {
	path := os.Getenv("KRB5_KDC_PROFILE")
	if path == "" {
		path = "/etc/krb5kdc/kdc.conf"
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	profile, err := config.ParseKDCConf(data)
	if err != nil {
		return "", err
	}
	settings, ok := profile.Realm(realm)
	if !ok {
		return "", fmt.Errorf("realm %s is not configured in %s", realm, path)
	}
	for key, values := range settings.Values {
		if strings.EqualFold(key, "key_stash_file") && len(values) > 0 {
			return strings.TrimSpace(values[0]), nil
		}
	}
	return "", fmt.Errorf("realm %s has no key_stash_file", realm)
}

// RunLocal starts a local command engine using the supplied startup options.
func RunLocal(ctx context.Context, opts StartupOptions, in io.Reader, out, errOut *os.File) error {
	realm := opts.Realm
	db, store, err := loadLocalDatabase(opts.Dump, realm, opts.Password)
	if err != nil {
		return err
	}
	if realm == "" {
		realm = db.GetRealm()
	}
	cfg := Config{Ops: NewLocal(db), Local: true, Realm: realm, DefaultKeySalts: opts.KeySalts,
		Stdin: in, Stdout: out, Stderr: errOut}
	if opts.Dump != "" {
		cfg.AfterMutation = func() error {
			if store == nil || store.MasterEnctype == 0 || len(store.MasterKey) == 0 {
				return errors.New("cannot persist MIT dump without a master key")
			}
			return rewriteLocalDump(opts.Dump, db, store.MasterEnctype, store.MasterKey)
		}
	}
	engine := New(cfg)
	if opts.Query != "" {
		_, err = engine.Execute(opts.Query)
		return err
	}
	return engine.RunInteractive("", opts.Command, "gokadmin.local:  ")
}

func rewriteLocalDump(path string, db *kdb.Database, enctype int32, key []byte) error {
	dir := filepath.Dir(path)
	mode := os.FileMode(0o600)
	if info, err := os.Stat(path); err == nil {
		mode = info.Mode().Perm()
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := mitdump.WriteWithMasterKey(tmp, db, enctype, key); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// RunRemote obtains administrative credentials and starts a remote engine.
func RunRemote(ctx context.Context, opts StartupOptions, in io.Reader, out, errOut *os.File) error {
	realm := opts.Realm
	var cache *ccache.Cache
	var err error
	if opts.CCache != "" {
		cache, err = ccache.ReadName(opts.CCache)
		if err != nil {
			return err
		}
		if opts.Principal == "" {
			opts.Principal = cache.DefaultPrincipal.String()
		}
		if realm == "" {
			realm = cache.DefaultPrincipal.Realm
		}
	}
	cfg, err := loadClientConfig()
	if err != nil {
		return err
	}
	if realm == "" {
		realm = cfg.DefaultRealm
	}
	name := opts.Principal
	if name == "" && opts.KeytabAuth {
		host, hostErr := os.Hostname()
		if hostErr != nil {
			return hostErr
		}
		name = "host/" + host
	} else if name == "" {
		name = os.Getenv("USER")
		if name == "" {
			name = "admin"
		}
		name += "/admin"
	}
	admin, err := ParsePrincipalDefault(name, realm)
	if err != nil {
		return err
	}
	if realm == "" {
		realm = admin.Realm
	}
	kerberos := &client.Client{Config: cfg}
	var creds *client.Credentials
	service, parseErr := principal.Parse("kadmin/admin@" + realm)
	if parseErr != nil {
		return parseErr
	}
	if opts.KeytabAuth {
		keytabName := opts.Keytab
		if keytabName == "" {
			keytabName = os.Getenv("KRB5_CLIENT_KTNAME")
		}
		if keytabName == "" {
			keytabName = cfg.DefaultClientKeytabName
		}
		if keytabName == "" {
			keytabName = cfg.DefaultKeytabName
		}
		if keytabName == "" {
			keytabName = "/etc/krb5.keytab"
		}
		kt, keytabErr := keytab.Resolve(keytabName)
		if keytabErr != nil {
			return keytabErr
		}
		var entry keytab.Entry
		found := false
		for _, candidate := range kt.Entries() {
			if candidate.Principal.Realm != admin.Realm ||
				candidate.Principal.NameType != admin.NameType ||
				len(candidate.Principal.Components) != len(admin.Components) {
				continue
			}
			matches := true
			for i := range admin.Components {
				if candidate.Principal.Components[i] != admin.Components[i] {
					matches = false
					break
				}
			}
			if !matches {
				continue
			}
			if !found || candidate.KVNO > entry.KVNO {
				entry = candidate
				found = true
			}
		}
		if !found {
			return fmt.Errorf("keytab %s has no entry for %s", keytabName, admin)
		}
		creds, err = kerberos.ASExchangeServiceWithKey(ctx, admin, entry, *service)
		if err != nil {
			return err
		}
	} else if opts.CCache != "" {
		if len(cache.Credentials) == 0 {
			return errors.New("ccache contains no credentials")
		}
		found := false
		for _, candidate := range cache.Credentials {
			if candidate.Server.String() == service.String() {
				creds = fromCCache(candidate)
				found = true
				break
			}
		}
		if !found {
			for _, candidate := range cache.Credentials {
				if len(candidate.Server.Components) == 2 &&
					candidate.Server.Components[0] == "krbtgt" &&
					strings.EqualFold(candidate.Server.Components[1], realm) {
					creds = fromCCache(candidate)
					found = true
					break
				}
			}
			if !found {
				return errors.New("ccache has no kadmin/admin credential or realm TGT")
			}
			creds, err = kerberos.TGSExchange(ctx, creds, *service)
			if err != nil {
				return err
			}
		}
	} else {
		if opts.Password == "" {
			fmt.Fprint(errOut, "Password for "+admin.String()+": ")
			if _, err := fmt.Fscanln(in, &opts.Password); err != nil {
				return err
			}
		}
		creds, err = kerberos.ASExchangeService(ctx, admin, opts.Password, *service)
		if err != nil {
			return err
		}
	}
	address := opts.Server
	if address == "" {
		address = configuredAdminServer(cfg, realm)
		if address == "" {
			return fmt.Errorf("no admin_server configured for realm %s", realm)
		}
	} else if _, _, err := net.SplitHostPort(address); err != nil {
		address += ":749"
	}
	rpc, err := kadm5.Dial(ctx, kerberos, admin, creds, address)
	if err != nil {
		return err
	}
	defer rpc.Close()
	engine := New(Config{Ops: NewRemote(rpc, realm), Realm: realm, DefaultKeySalts: opts.KeySalts,
		Stdin: in, Stdout: out, Stderr: errOut, Password: opts.Password})
	return engine.RunInteractive(opts.Query, opts.Command, "gokadmin:  ")
}

func loadClientConfig() (*config.Config, error) {
	path := os.Getenv("KRB5_CONFIG")
	if path == "" {
		return config.ParseDefault(false)
	}
	return config.ParseFile(path)
}

func configuredAdminServer(cfg *config.Config, realm string) string {
	if cfg == nil {
		return ""
	}
	for name, values := range cfg.RealmOptions {
		if !strings.EqualFold(name, realm) {
			continue
		}
		for key, candidates := range values {
			if strings.EqualFold(key, "admin_server") && len(candidates) > 0 {
				address := strings.TrimSpace(candidates[0])
				if _, _, err := net.SplitHostPort(address); err != nil {
					address += ":749"
				}
				return address
			}
		}
	}
	return ""
}

func fromCCache(value ccache.Credential) *client.Credentials {
	return &client.Credentials{
		Client: value.Client, Server: value.Server,
		Key:      protocol.EncryptionKey{KeyType: value.Enctype, KeyValue: append([]byte(nil), value.Key...)},
		Ticket:   append([]byte(nil), value.Ticket...),
		AuthTime: types.KerberosTime{Time: time.Unix(int64(value.AuthTime), 0), Present: value.AuthTime != 0},
	}
}

// ParsePrincipalDefault applies the kadmin default-realm rule.
func ParsePrincipalDefault(value, realm string) (principal.Principal, error) {
	if !strings.Contains(value, "@") {
		value += "@" + realm
	}
	parsed, err := principal.Parse(value)
	if err != nil {
		return principal.Principal{}, err
	}
	return *parsed, nil
}
