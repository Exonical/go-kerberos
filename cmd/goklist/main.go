package main

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/Exonical/go-kerberos/krb5/ccache"
	"github.com/Exonical/go-kerberos/krb5/keytab"
)

func main() {
	if err := runList(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "goklist: %v\n", err)
		os.Exit(1)
	}
}

type listOptions struct {
	CachePath  string
	KeytabPath string
	ShowEtypes bool
}

func parseListArgs(args []string) (listOptions, error) {
	options := listOptions{}
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-e":
			options.ShowEtypes = true
		case "-c", "-k":
			if i+1 >= len(args) {
				return listOptions{}, fmt.Errorf("%s requires a path", args[i])
			}
			i++
			if args[i] == "" {
				return listOptions{}, fmt.Errorf("%s requires a path", args[i-1])
			}
			if args[i-1] == "-c" {
				options.CachePath = args[i]
			} else {
				options.KeytabPath = args[i]
			}
		default:
			return listOptions{}, fmt.Errorf("unexpected argument %s", args[i])
		}
	}
	return options, nil
}

func runList(args []string, stdout io.Writer) error {
	options, err := parseListArgs(args)
	if err != nil {
		return err
	}
	if options.KeytabPath != "" {
		return listKeytab(strings.TrimPrefix(options.KeytabPath, "FILE:"), options.ShowEtypes, stdout)
	}
	cachePath := options.CachePath
	if cachePath == "" {
		cachePath = resolveListCachePath(os.Getenv("KRB5CCNAME"), os.Getuid())
	} else {
		cachePath = strings.TrimPrefix(cachePath, "FILE:")
	}
	return listCache(cachePath, options.ShowEtypes, stdout)
}

func resolveListCachePath(value string, uid int) string {
	if value == "" {
		return fmt.Sprintf("/tmp/krb5cc_%d", uid)
	}
	return strings.TrimPrefix(value, "FILE:")
}

func listCache(path string, showEtypes bool, stdout io.Writer) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open cache: %w", err)
	}
	defer file.Close()
	cache, err := ccache.Read(file)
	if err != nil {
		return fmt.Errorf("read cache: %w", err)
	}
	fmt.Fprintf(stdout, "Ticket cache: FILE:%s\n", path)
	fmt.Fprintf(stdout, "Default principal: %s\n\n", cache.DefaultPrincipal.String())
	fmt.Fprintln(stdout, "Valid starting       Expires              Service principal")
	for _, credential := range cache.Credentials {
		if strings.HasPrefix(credential.Server.String(), "X-CACHECONF:") {
			continue
		}
		fmt.Fprintf(stdout, "%-20s %-20s %s\n",
			formatKlistTime(time.Unix(int64(credential.StartTime), 0)),
			formatKlistTime(time.Unix(int64(credential.EndTime), 0)),
			credential.Server.String())
		if showEtypes {
			fmt.Fprintf(stdout, "\tEtype (skey): %s\n", enctypeName(credential.Enctype))
		}
	}
	return nil
}

func listKeytab(path string, showEtypes bool, stdout io.Writer) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open keytab: %w", err)
	}
	defer file.Close()
	kt, err := keytab.Read(file)
	if err != nil {
		return fmt.Errorf("read keytab: %w", err)
	}
	fmt.Fprintf(stdout, "Keytab name: FILE:%s\n", path)
	fmt.Fprintln(stdout, "KVNO Principal")
	for _, entry := range kt.Entries {
		fmt.Fprintf(stdout, "%4d %s\n", entry.KVNO, entry.Principal.String())
		if showEtypes {
			fmt.Fprintf(stdout, "\tEtype: %s\n", enctypeName(entry.Enctype))
		}
	}
	return nil
}

func formatKlistTime(value time.Time) string {
	return value.UTC().Format("01/02/06 15:04:05")
}

func enctypeName(value int32) string {
	switch value {
	case 17:
		return "aes128-cts-hmac-sha1-96"
	case 18:
		return "aes256-cts-hmac-sha1-96"
	case 19:
		return "aes128-cts-hmac-sha256-128"
	case 20:
		return "aes256-cts-hmac-sha384-192"
	default:
		return fmt.Sprintf("etype-%d", value)
	}
}
