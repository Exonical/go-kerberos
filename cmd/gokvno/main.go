package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/Exonical/go-kerberos/krb5/asn1"
	"github.com/Exonical/go-kerberos/krb5/ccache"
	"github.com/Exonical/go-kerberos/krb5/client"
	"github.com/Exonical/go-kerberos/krb5/config"
	"github.com/Exonical/go-kerberos/krb5/principal"
	"github.com/Exonical/go-kerberos/krb5/protocol"
	"github.com/Exonical/go-kerberos/krb5/types"
)

func main() {
	if err := runVNO(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "gokvno: %v\n", err)
		os.Exit(1)
	}
}

type vnoOptions struct {
	CachePath string
	Services  []string
}

func parseVNOArgs(args []string) (vnoOptions, error) {
	options := vnoOptions{}
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-c":
			if i+1 >= len(args) || args[i+1] == "" {
				return vnoOptions{}, fmt.Errorf("-c requires a cache path")
			}
			i++
			options.CachePath = args[i]
		default:
			if strings.HasPrefix(args[i], "-") {
				return vnoOptions{}, fmt.Errorf("unknown option %s", args[i])
			}
			options.Services = append(options.Services, args[i])
		}
	}
	if len(options.Services) == 0 {
		return vnoOptions{}, fmt.Errorf("at least one service is required")
	}
	return options, nil
}

func servicePrincipal(value string, cfg *config.Config) (principal.Principal, error) {
	if !strings.Contains(value, "@") {
		if cfg == nil || cfg.DefaultRealm == "" {
			return principal.Principal{}, fmt.Errorf("service has no realm and no default realm is configured")
		}
		value += "@" + cfg.DefaultRealm
	}
	parsed, err := principal.Parse(value)
	if err != nil {
		return principal.Principal{}, err
	}
	parsed.NameType = principal.NTSrvHst
	return *parsed, nil
}

func runVNO(args []string, stdout io.Writer) error {
	options, err := parseVNOArgs(args)
	if err != nil {
		return err
	}
	cfg, err := loadVNOConfig()
	if err != nil {
		return err
	}
	cachePath := options.CachePath
	if cachePath == "" {
		cachePath, err = configuredVNOCacheName(os.Getenv, os.Getuid(), cfg)
		if err != nil {
			return err
		}
	} else {
		cachePath = strings.TrimPrefix(cachePath, "FILE:")
	}
	cache, err := ccache.ReadName(cachePath)
	if err != nil {
		return fmt.Errorf("read cache: %w", err)
	}
	tgtIndex := findTGT(cache)
	if tgtIndex < 0 {
		return fmt.Errorf("cache does not contain a TGT")
	}
	tgt := credentialsFromCCache(cache.Credentials[tgtIndex])
	kclient := &client.Client{Config: cfg}
	for _, value := range options.Services {
		service, err := servicePrincipal(value, cfg)
		if err != nil {
			return err
		}
		credential, err := kclient.TGSExchange(context.Background(), &tgt, service)
		if err != nil {
			return err
		}
		cache.Credentials = append(cache.Credentials, credential.ToCCacheCredential())
		kvno, err := ticketKVNO(credential.Ticket)
		if err != nil {
			return err
		}
		fmt.Fprintf(stdout, "%s: kvno = %d\n", service.String(), kvno)
	}
	if err := ccache.WriteName(cachePath, cache); err != nil {
		return fmt.Errorf("write cache: %w", err)
	}
	return nil
}

func resolveVNOCachePath(value string, uid int) string {
	if value == "" {
		return fmt.Sprintf("/tmp/krb5cc_%d", uid)
	}
	return strings.TrimPrefix(value, "FILE:")
}

func loadVNOConfig() (*config.Config, error) {
	path := os.Getenv("KRB5_CONFIG")
	if path == "" {
		path = "/etc/krb5.conf"
	}
	cfg, err := config.ParseFile(path)
	if err != nil {
		return nil, err
	}
	return cfg, nil
}

func configuredVNOCacheName(getenv func(string) string, uid int, cfg *config.Config) (string, error) {
	if value := getenv("KRB5CCNAME"); value != "" {
		return value, nil
	}
	if cfg != nil && cfg.DefaultCCacheName != "" {
		return config.ExpandPathTokens(cfg.DefaultCCacheName)
	}
	return fmt.Sprintf("/tmp/krb5cc_%d", uid), nil
}

func findTGT(cache *ccache.Cache) int {
	if cache == nil {
		return -1
	}
	for i, credential := range cache.Credentials {
		if len(credential.Server.Components) == 2 &&
			credential.Server.Components[0] == "krbtgt" &&
			credential.Server.Components[1] == credential.Server.Realm {
			return i
		}
	}
	return -1
}

func credentialsFromCCache(value ccache.Credential) client.Credentials {
	toTime := func(seconds uint32) *types.KerberosTime {
		if seconds == 0 {
			return nil
		}
		return &types.KerberosTime{Time: time.Unix(int64(seconds), 0).UTC(), Present: true}
	}
	return client.Credentials{
		Client: value.Client, Server: value.Server,
		Key:       protocol.EncryptionKey{KeyType: value.Enctype, KeyValue: append([]byte(nil), value.Key...)},
		Flags:     types.TicketFlags(value.TicketFlags),
		AuthTime:  types.KerberosTime{Time: time.Unix(int64(value.AuthTime), 0).UTC(), Present: value.AuthTime != 0},
		StartTime: toTime(value.StartTime), EndTime: types.KerberosTime{Time: time.Unix(int64(value.EndTime), 0).UTC(), Present: value.EndTime != 0},
		RenewTill: toTime(value.RenewTill), Ticket: append([]byte(nil), value.Ticket...),
	}
}

func ticketKVNO(der []byte) (uint32, error) {
	var ticket protocol.Ticket
	if err := asn1.Unmarshal(der, &ticket); err != nil {
		return 0, fmt.Errorf("decode service ticket: %w", err)
	}
	if ticket.EncPart.KVNO == nil {
		return 0, nil
	}
	return *ticket.EncPart.KVNO, nil
}
