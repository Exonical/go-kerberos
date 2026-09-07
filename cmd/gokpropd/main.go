// Command gokpropd receives MIT-compatible KDC database dumps.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Exonical/go-kerberos/krb5/config"
	"github.com/Exonical/go-kerberos/krb5/kdb/mitdump"
	"github.com/Exonical/go-kerberos/krb5/keytab"
	"github.com/Exonical/go-kerberos/krb5/kprop"
	"github.com/Exonical/go-kerberos/krb5/principal"
)

const (
	defaultKPropdFile = "/var/lib/krb5kdc/from_master"
	defaultKPropdACL  = "/var/lib/krb5kdc/kpropd.acl"
)

type propdOptions struct {
	Realm       string
	Keytab      string
	Stash       string
	Debug       bool
	NoDaemon    bool
	Standalone  bool
	ReplicaFile string
	Database    string
	KDBUtil     string
	DBArgs      []string
	Port        string
	ACL         string
	AdminServer string
	PIDFile     string
	RunOnce     bool
}

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "gokpropd: %v\n", err)
		os.Exit(1)
	}
}

func parsePropdArgs(args []string) (propdOptions, error) {
	options := propdOptions{
		ReplicaFile: defaultKPropdFile,
		KDBUtil:     "",
		Port:        strconv.Itoa(kprop.DefaultPort),
		ACL:         defaultKPropdACL,
	}
	fs := flag.NewFlagSet("gokpropd", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&options.Realm, "r", "", "realm")
	fs.StringVar(&options.Keytab, "s", "", "keytab")
	fs.StringVar(&options.Stash, "sf", "", "master-key stash file")
	fs.StringVar(&options.Stash, "stash-file", "", "master-key stash file")
	fs.BoolVar(&options.Debug, "d", false, "debug")
	fs.BoolVar(&options.NoDaemon, "D", false, "do not daemonize")
	fs.BoolVar(&options.Standalone, "S", false, "standalone mode")
	fs.StringVar(&options.ReplicaFile, "f", options.ReplicaFile, "replica dump file")
	fs.StringVar(&options.Database, "F", "", "database file")
	fs.StringVar(&options.KDBUtil, "p", options.KDBUtil, "kdb5_util pathname")
	fs.Var((*stringList)(&options.DBArgs), "x", "database argument")
	fs.StringVar(&options.Port, "P", options.Port, "port")
	fs.StringVar(&options.ACL, "a", options.ACL, "ACL file")
	fs.StringVar(&options.AdminServer, "A", "", "admin server for incremental iprop")
	fs.StringVar(&options.PIDFile, "pid-file", "", "pid file")
	fs.BoolVar(&options.RunOnce, "t", false, "run once")
	if err := fs.Parse(args); err != nil {
		return propdOptions{}, err
	}
	if fs.NArg() != 0 {
		return propdOptions{}, errors.New("usage: gokpropd [-r realm] [-s keytab] [-sf stash_file] [-d] [-D] [-S] [-f replica_file] [-F kerberos_db_file] [-p kdb5_util_pathname] [-x db_args] [-P port] [-a acl_file] [-A admin_server] [--pid-file=pid_file] [-t]")
	}
	if _, err := net.LookupPort("tcp", options.Port); err != nil {
		return propdOptions{}, fmt.Errorf("invalid port %q: %w", options.Port, err)
	}
	return options, nil
}

type stringList []string

func (s *stringList) String() string { return strings.Join(*s, " ") }

func (s *stringList) Set(value string) error {
	*s = append(*s, value)
	return nil
}

func run(args []string, out, errOut io.Writer) error {
	options, err := parsePropdArgs(args)
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
	if options.ReplicaFile == defaultKPropdFile {
		options.ReplicaFile = defaultDumpPath(cfg, realm, options.ReplicaFile)
	}
	if options.Database == "" {
		options.Database = defaultDatabasePath(cfg, realm)
	}
	kt, err := keytab.ResolveWithConfig(options.Keytab, cfg)
	if err != nil {
		return fmt.Errorf("resolve keytab: %w", err)
	}
	authorize, err := loadACL(options.ACL)
	if err != nil {
		return err
	}
	if options.PIDFile != "" {
		if err := writePID(options.PIDFile); err != nil {
			return err
		}
	}
	if options.AdminServer != "" || profileIpropEnabled(realm) {
		return runIncremental(context.Background(), options, cfg, realm, kt,
			authorize, out, errOut)
	}
	listener, err := net.Listen("tcp", net.JoinHostPort("", options.Port))
	if err != nil {
		return fmt.Errorf("listen on port %s: %w", options.Port, err)
	}
	defer listener.Close()
	server := &kprop.Server{
		Keytab: kt, Realm: realm, Authorize: authorize,
		Load: func(reader io.Reader, size uint64) error {
			return loadReceivedDump(reader, size, options)
		},
		ErrorLog: func(err error) {
			if options.Debug {
				fmt.Fprintln(errOut, err)
			}
		},
	}
	if options.Debug {
		fmt.Fprintf(errOut, "listening on %s\n", listener.Addr())
	}
	if options.RunOnce {
		return serveOne(listener, server)
	}
	return server.Serve(listener)
}

func serveOne(listener net.Listener, server *kprop.Server) error {
	conn, err := listener.Accept()
	if err != nil {
		return err
	}
	return server.ServeConn(context.Background(), conn)
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
					return filepath.Join(filepath.Dir(database), "from_master")
				}
			}
		}
	}
	_ = cfg
	return fallback
}

func defaultDatabasePath(cfg *config.Config, realm string) string {
	if path := os.Getenv("KRB5_KDC_PROFILE"); path != "" {
		if data, err := os.ReadFile(path); err == nil {
			if profile, err := config.ParseKDCConf(data); err == nil {
				values := profile.Defaults
				if settings, ok := profile.Realm(realm); ok {
					values = settings.Values
				}
				if database := strings.TrimSpace(strings.Join(values["database_name"], " ")); database != "" {
					return database
				}
			}
		}
	}
	_ = cfg
	return filepath.Join("/var/lib/krb5kdc", "principal")
}

func loadACL(path string) (func(principal.Principal) error, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read ACL %q: %w", path, err)
	}
	allowed := make(map[string]bool)
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) > 0 {
			allowed[fields[0]] = true
		}
	}
	return func(client principal.Principal) error {
		if !allowed[client.String()] {
			return fmt.Errorf("principal %s is not authorized", client)
		}
		return nil
	}, nil
}

func loadReceivedDump(reader io.Reader, size uint64, options propdOptions) error {
	data, err := io.ReadAll(io.LimitReader(reader, int64(size)+1))
	if err != nil {
		return fmt.Errorf("read received dump: %w", err)
	}
	if uint64(len(data)) != size {
		return fmt.Errorf("received dump size %d, want %d", len(data), size)
	}
	if _, err := mitdump.Parse(data); err != nil {
		return fmt.Errorf("parse received dump: %w", err)
	}
	if err := writeFileAtomic(options.ReplicaFile, data); err != nil {
		return err
	}
	if options.KDBUtil == "" {
		return writeFileAtomic(options.Database, data)
	}
	args := buildLoadArgs(options)
	command := exec.Command(options.KDBUtil, args...) // nosemgrep: tmp.opengrep-rules.go.lang.security.audit.dangerous-exec-command -- -p intentionally selects an administrator-configured kdb5_util-compatible loader
	if output, err := command.CombinedOutput(); err != nil {
		return fmt.Errorf("%s load: %w: %s", options.KDBUtil, err, strings.TrimSpace(string(output)))
	}
	return nil
}

func buildLoadArgs(options propdOptions) []string {
	var args []string
	if options.Realm != "" {
		args = append(args, "-r", options.Realm)
	}
	args = append(args, "load", "-d", options.Database)
	for _, value := range options.DBArgs {
		args = append(args, "-x", value)
	}
	return append(args, options.ReplicaFile)
}

func writePID(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil { // nosemgrep: tmp.opengrep-rules.go.lang.correctness.permissions.incorrect-default-permission -- 0700 directory is intentionally restrictive
		return fmt.Errorf("create pid directory: %w", err)
	}
	if err := os.WriteFile(path, []byte(strconv.Itoa(os.Getpid())+"\n"), 0o600); err != nil {
		return fmt.Errorf("write pid file %q: %w", path, err)
	}
	return nil
}

func writeFileAtomic(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil { // nosemgrep: tmp.opengrep-rules.go.lang.correctness.permissions.incorrect-default-permission -- 0700 directory is intentionally restrictive
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
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
	return os.Rename(name, path)
}
