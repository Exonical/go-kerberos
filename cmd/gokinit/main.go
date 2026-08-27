package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/Exonical/go-kerberos/krb5/ccache"
	"github.com/Exonical/go-kerberos/krb5/client"
	"github.com/Exonical/go-kerberos/krb5/config"
	"github.com/Exonical/go-kerberos/krb5/principal"
)

func main() {
	if err := runInit(os.Args[1:], os.Stdin, os.Stdout, os.Stderr, isTerminal(os.Stdin)); err != nil {
		fmt.Fprintf(os.Stderr, "gokinit: %v\n", err)
		os.Exit(1)
	}
}

type initOptions struct {
	CachePath string
	Lifetime  time.Duration
	Principal string
}

func parseInitArgs(args []string) (initOptions, error) {
	options := initOptions{}
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-c":
			if i+1 >= len(args) {
				return initOptions{}, fmt.Errorf("-c requires a cache path")
			}
			i++
			options.CachePath = args[i]
		case "-l":
			if i+1 >= len(args) {
				return initOptions{}, fmt.Errorf("-l requires a lifetime")
			}
			i++
			value, err := config.ParseDuration(args[i])
			if err != nil {
				return initOptions{}, err
			}
			options.Lifetime = value
		case "":
			return initOptions{}, fmt.Errorf("empty argument")
		default:
			if strings.HasPrefix(args[i], "-") {
				return initOptions{}, fmt.Errorf("unknown option %s", args[i])
			}
			if options.Principal != "" {
				return initOptions{}, fmt.Errorf("expected one principal")
			}
			options.Principal = args[i]
		}
	}
	if options.Principal == "" {
		return initOptions{}, fmt.Errorf("principal is required")
	}
	return options, nil
}

func principalFromArgument(value string, cfg *config.Config) (principal.Principal, error) {
	if !strings.Contains(value, "@") {
		if cfg == nil || cfg.DefaultRealm == "" {
			return principal.Principal{}, fmt.Errorf("principal has no realm and no default realm is configured")
		}
		value += "@" + cfg.DefaultRealm
	}
	result, err := principal.Parse(value)
	if err != nil {
		return principal.Principal{}, err
	}
	return *result, nil
}

func resolveCachePath(explicit string, getenv func(string) string, uid int) string {
	path := explicit
	if path == "" {
		path = getenv("KRB5CCNAME")
	}
	if path == "" {
		path = fmt.Sprintf("/tmp/krb5cc_%d", uid)
	}
	return strings.TrimPrefix(path, "FILE:")
}

func runInit(args []string, stdin io.Reader, _ io.Writer, stderr io.Writer, interactive bool) error {
	options, err := parseInitArgs(args)
	if err != nil {
		return err
	}
	cfg, err := loadInitConfig(os.Getenv)
	if err != nil {
		return err
	}
	clientPrincipal, err := principalFromArgument(options.Principal, cfg)
	if err != nil {
		return err
	}
	if interactive {
		fmt.Fprintf(stderr, "Password for %s: ", clientPrincipal.String())
	}
	password, err := bufio.NewReader(stdin).ReadString('\n')
	if err != nil && err != io.EOF {
		return fmt.Errorf("read password: %w", err)
	}
	password = strings.TrimSuffix(strings.TrimSuffix(password, "\n"), "\r")
	if password == "" {
		return fmt.Errorf("empty password")
	}
	if options.Lifetime > 0 {
		cfg.TicketLifetime = options.Lifetime
	}
	credentials, err := (&client.Client{Config: cfg}).ASExchange(context.Background(), clientPrincipal, password)
	if err != nil {
		return err
	}
	cachePath := resolveCachePath(options.CachePath, os.Getenv, os.Getuid())
	cache := &ccache.Cache{
		DefaultPrincipal: clientPrincipal,
		Credentials:      []ccache.Credential{credentials.ToCCacheCredential()},
	}
	file, err := os.OpenFile(cachePath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("open cache: %w", err)
	}
	if err := ccache.Write(file, cache); err != nil {
		_ = file.Close()
		return fmt.Errorf("write cache: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close cache: %w", err)
	}
	return nil
}

func loadInitConfig(getenv func(string) string) (*config.Config, error) {
	path := getenv("KRB5_CONFIG")
	if path == "" {
		path = "/etc/krb5.conf"
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read configuration: %w", err)
	}
	cfg, err := config.Parse(data)
	if err != nil {
		return nil, err
	}
	return cfg, nil
}

func isTerminal(file *os.File) bool {
	info, err := file.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}
