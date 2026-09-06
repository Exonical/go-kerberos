package kadmin

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/Exonical/go-kerberos/krb5/ccache"
	"github.com/Exonical/go-kerberos/krb5/client"
	"github.com/Exonical/go-kerberos/krb5/config"
	"github.com/Exonical/go-kerberos/krb5/kadm5"
	"github.com/Exonical/go-kerberos/krb5/kdb"
	"github.com/Exonical/go-kerberos/krb5/kdb/mitdump"
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
	var store *mitdump.FileStore
	var err error
	if path == "" {
		return kdb.NewDatabase(realm), nil
	}
	if password != "" {
		store, err = mitdump.LoadWithMasterPassword(path, password)
	} else {
		store, err = mitdump.Load(path)
		if err != nil {
			stash := os.Getenv("KRB5_KDC_STASH")
			if stash == "" {
				stash = "/etc/krb5kdc/stash"
			}
			if _, statErr := os.Stat(stash); statErr == nil {
				store, err = mitdump.LoadWithStash(path, stash)
			}
		}
	}
	if err != nil {
		return nil, err
	}
	if realm == "" {
		realm = store.Realm
	}
	db := kdb.NewDatabase(realm)
	for _, record := range store.Records() {
		if err := db.ImportPrincipal(record); err != nil {
			return nil, err
		}
	}
	return db, nil
}

// RunLocal starts a local command engine using the supplied startup options.
func RunLocal(ctx context.Context, opts StartupOptions, in *bufio.Reader, out, errOut *os.File) error {
	realm := opts.Realm
	db, err := LoadLocalDatabase(opts.Dump, realm, opts.Password)
	if err != nil {
		return err
	}
	if realm == "" {
		realm = db.GetRealm()
	}
	engine := New(Config{Ops: NewLocal(db), Local: true, Realm: realm, Stdin: in, Stdout: out, Stderr: errOut})
	if opts.Query != "" {
		_, err = engine.Execute(opts.Query)
		return err
	}
	return engine.RunInteractive("", opts.Command, "gokadmin.local:  ")
}

// RunRemote obtains administrative credentials and starts a remote engine.
func RunRemote(ctx context.Context, opts StartupOptions, in *bufio.Reader, out, errOut *os.File) error {
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
	name := opts.Principal
	if name == "" {
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
	cfg, err := config.ParseFile("/etc/krb5.conf")
	if err != nil {
		cfg = &config.Config{}
	}
	kerberos := &client.Client{Config: cfg}
	var creds *client.Credentials
	if opts.KeytabAuth {
		return errors.New("-k keytab authentication is not supported by the current client API")
	}
	if opts.CCache != "" {
		if len(cache.Credentials) == 0 {
			return errors.New("ccache contains no credentials")
		}
		base := cache.Credentials[0]
		creds = fromCCache(base)
		if !strings.Contains(base.Server.String(), "krbtgt/") {
			creds = fromCCache(base)
		} else {
			service, parseErr := principal.Parse("kadmin/admin@" + realm)
			if parseErr != nil {
				return parseErr
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
		service, parseErr := principal.Parse("kadmin/admin@" + realm)
		if parseErr != nil {
			return parseErr
		}
		creds, err = kerberos.ASExchangeService(ctx, admin, opts.Password, *service)
		if err != nil {
			return err
		}
	}
	address := opts.Server
	if address == "" {
		address = "127.0.0.1:749"
	} else if _, _, err := net.SplitHostPort(address); err != nil {
		address += ":749"
	}
	rpc, err := kadm5.Dial(ctx, kerberos, admin, creds, address)
	if err != nil {
		return err
	}
	defer rpc.Close()
	engine := New(Config{Ops: NewRemote(rpc, realm), Realm: realm, Stdin: in, Stdout: out, Stderr: errOut, Password: opts.Password})
	return engine.RunInteractive(opts.Query, opts.Command, "gokadmin:  ")
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
