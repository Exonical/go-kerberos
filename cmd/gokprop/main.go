// Command gokprop sends an MIT-compatible KDC database dump to a replica.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Exonical/go-kerberos/krb5/client"
	"github.com/Exonical/go-kerberos/krb5/config"
	"github.com/Exonical/go-kerberos/krb5/keytab"
	"github.com/Exonical/go-kerberos/krb5/kprop"
	"github.com/Exonical/go-kerberos/krb5/principal"
)

const defaultKPropFile = "/var/lib/krb5kdc/replica_datatrans"

type propOptions struct {
	Realm       string
	File        string
	Debug       bool
	Port        string
	Keytab      string
	ReplicaHost string
}

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "gokprop: %v\n", err)
		os.Exit(1)
	}
}

func parsePropArgs(args []string) (propOptions, error) {
	options := propOptions{File: defaultKPropFile, Port: strconv.Itoa(kprop.DefaultPort)}
	fs := flag.NewFlagSet("gokprop", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&options.Realm, "r", "", "realm")
	fs.StringVar(&options.File, "f", options.File, "database dump")
	fs.BoolVar(&options.Debug, "d", false, "debug")
	fs.StringVar(&options.Port, "P", options.Port, "port")
	fs.StringVar(&options.Keytab, "s", "", "keytab")
	if err := fs.Parse(args); err != nil {
		return propOptions{}, err
	}
	if fs.NArg() != 1 {
		return propOptions{}, errors.New("usage: gokprop [-r realm] [-f file] [-d] [-P port] [-s keytab] replica_host")
	}
	options.ReplicaHost = fs.Arg(0)
	if options.ReplicaHost == "" {
		return propOptions{}, errors.New("replica host is required")
	}
	if _, err := net.LookupPort("tcp", options.Port); err != nil {
		return propOptions{}, fmt.Errorf("invalid port %q: %w", options.Port, err)
	}
	return options, nil
}

func run(args []string, out, errOut io.Writer) error {
	options, err := parsePropArgs(args)
	if err != nil {
		return err
	}
	cfg, err := loadProfile()
	if err != nil {
		return fmt.Errorf("while loading configuration: %w", err)
	}
	realm := configuredRealm(cfg, options.Realm)
	if realm == "" {
		return errors.New("realm is not configured; use -r")
	}
	if options.File == defaultKPropFile {
		options.File = defaultDumpPath(cfg, realm, options.File)
	}
	file, err := os.Open(options.File)
	if err != nil {
		return fmt.Errorf("open dump %q: %w", options.File, err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("stat dump %q: %w", options.File, err)
	}
	kt, err := keytab.ResolveWithConfig(options.Keytab, cfg)
	if err != nil {
		return fmt.Errorf("resolve keytab: %w", err)
	}
	master, entry, err := localHostKey(kt, realm)
	if err != nil {
		return err
	}
	service := principal.Principal{
		Realm: realm, NameType: principal.NTSrvHst,
		Components: []string{"host", options.ReplicaHost},
	}
	kerberos := &client.Client{Config: cfg}
	credentials, err := kerberos.ASExchangeServiceWithKey(context.Background(), master, entry, service)
	if err != nil {
		return fmt.Errorf("get propagation credentials: %w", err)
	}
	address := net.JoinHostPort(options.ReplicaHost, options.Port)
	if options.Debug {
		fmt.Fprintf(errOut, "sending %d bytes to %s as %s\n", info.Size(), address, master)
	}
	if err := kprop.DialAndSend(context.Background(), address, credentials, file, uint64(info.Size())); err != nil {
		return err
	}
	if err := touchLastProp(options.File); err != nil {
		return err
	}
	fmt.Fprintf(out, "Database propagation to %s: SUCCEEDED\n", options.ReplicaHost)
	return nil
}

func loadProfile() (*config.Config, error) {
	if path := os.Getenv("KRB5_CONFIG"); path != "" {
		return config.ParseFile(path)
	}
	return config.ParseDefault(false)
}

func configuredRealm(cfg *config.Config, explicit string) string {
	if explicit != "" {
		return explicit
	}
	if cfg != nil && cfg.DefaultRealm != "" {
		return cfg.DefaultRealm
	}
	if realm := strings.TrimSpace(os.Getenv("KRB5_REALM")); realm != "" {
		return realm
	}
	return strings.TrimSpace(os.Getenv("KRB5_DEFAULT_REALM"))
}

func defaultDumpPath(cfg *config.Config, realm, fallback string) string {
	if path := os.Getenv("KRB5_KDC_PROFILE"); path != "" {
		if data, err := os.ReadFile(path); err == nil {
			if profile, err := config.ParseKDCConf(data); err == nil {
				values := profile.Defaults
				if settings, ok := profile.Realm(realm); ok {
					values = settings.Values
				}
				if database := strings.TrimSpace(strings.Join(values["database_name"], " ")); database != "" {
					return filepath.Join(filepath.Dir(database), "replica_datatrans")
				}
			}
		}
	}
	return fallback
}

func localHostKey(kt *keytab.Keytab, realm string) (principal.Principal, keytab.Entry, error) {
	if kt == nil {
		return principal.Principal{}, keytab.Entry{}, errors.New("keytab is nil")
	}
	host, err := os.Hostname()
	if err != nil {
		return principal.Principal{}, keytab.Entry{}, fmt.Errorf("get local hostname: %w", err)
	}
	want := principal.Principal{Realm: realm, NameType: principal.NTSrvHst, Components: []string{"host", host}}
	for _, entry := range kt.EntriesSnapshot() {
		if entry.Principal.String() == want.String() {
			return entry.Principal, entry, nil
		}
	}
	for _, entry := range kt.EntriesSnapshot() {
		if entry.Principal.Realm == realm && len(entry.Principal.Components) == 2 &&
			entry.Principal.Components[0] == "host" {
			return entry.Principal, entry, nil
		}
	}
	return principal.Principal{}, keytab.Entry{}, fmt.Errorf("no host key for realm %s in keytab", realm)
}

func touchLastProp(path string) error {
	last := path + ".last_prop"
	file, err := os.OpenFile(last, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("create last propagation file %q: %w", last, err)
	}
	if _, err := file.Write([]byte{0}); err != nil {
		_ = file.Close()
		return fmt.Errorf("write last propagation file %q: %w", last, err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close last propagation file %q: %w", last, err)
	}
	return nil
}
