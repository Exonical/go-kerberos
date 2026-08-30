package main

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/Exonical/go-kerberos/krb5/ccache"
	"github.com/Exonical/go-kerberos/krb5/principal"
)

type switchOptions struct {
	Cache     string
	Principal string
}

func main() {
	if err := runSwitch(os.Args[1:], os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "gokswitch: %v\n", err)
		os.Exit(1)
	}
}

func parseSwitchArgs(args []string) (switchOptions, error) {
	var options switchOptions
	for i := 0; i < len(args); i++ {
		if args[i] != "-c" && args[i] != "-p" {
			return switchOptions{}, fmt.Errorf("unexpected argument %s", args[i])
		}
		if i+1 >= len(args) || args[i+1] == "" {
			return switchOptions{}, fmt.Errorf("%s requires a value", args[i])
		}
		if options.Cache != "" || options.Principal != "" {
			return switchOptions{}, errors.New("only one -c or -p option allowed")
		}
		i++
		if args[i-1] == "-c" {
			options.Cache = args[i]
		} else {
			options.Principal = args[i]
		}
	}
	if options.Cache == "" && options.Principal == "" {
		return switchOptions{}, errors.New("one of -c or -p must be specified")
	}
	return options, nil
}

func runSwitch(args []string, stderr io.Writer) error {
	options, err := parseSwitchArgs(args)
	if err != nil {
		return err
	}
	name := os.Getenv("KRB5CCNAME")
	if name == "" {
		name = fmt.Sprintf("FILE:/tmp/krb5cc_%d", os.Getuid())
	}
	resolved, err := ccache.Resolve(name)
	if err != nil {
		return err
	}
	defer resolved.Close()
	target := resolved
	if options.Cache != "" {
		target, err = ccache.Resolve(options.Cache)
		if err != nil {
			return fmt.Errorf("while resolving %s: %w", options.Cache, err)
		}
		defer target.Close()
	} else {
		p, err := principal.Parse(options.Principal)
		if err != nil {
			return fmt.Errorf("while parsing principal name %s: %w", options.Principal, err)
		}
		caches, err := resolved.Collection()
		if err != nil {
			return err
		}
		found := false
		for _, cache := range caches {
			value, readErr := cache.Read()
			if readErr == nil && value.DefaultPrincipal.String() == p.String() {
				target = cache
				found = true
				break
			}
			_ = cache.Close()
		}
		if !found {
			return fmt.Errorf("while searching for ccache for %s", p.String())
		}
		defer target.Close()
	}
	if err := target.SetPrimary(); err != nil {
		fmt.Fprintf(stderr, "while switching to credential cache: %v\n", err)
		return err
	}
	return nil
}
