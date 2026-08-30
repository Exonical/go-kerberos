package main

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/Exonical/go-kerberos/krb5/ccache"
	"github.com/Exonical/go-kerberos/krb5/principal"
)

type destroyOptions struct {
	Cache     string
	Principal string
	All       bool
	Quiet     bool
}

func main() {
	if err := runDestroy(os.Args[1:], os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "gokdestroy: %v\n", err)
		os.Exit(1)
	}
}

func parseDestroyArgs(args []string) (destroyOptions, error) {
	var options destroyOptions
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-A":
			options.All = true
		case "-q":
			options.Quiet = true
		case "-c", "-p":
			if i+1 >= len(args) || args[i+1] == "" {
				return destroyOptions{}, fmt.Errorf("%s requires a value", args[i])
			}
			i++
			if args[i-1] == "-c" {
				if options.Cache != "" {
					return destroyOptions{}, errors.New("only one -c option allowed")
				}
				options.Cache = args[i]
			} else {
				if options.Principal != "" {
					return destroyOptions{}, errors.New("only one -p option allowed")
				}
				options.Principal = args[i]
			}
		default:
			return destroyOptions{}, fmt.Errorf("unexpected argument %s", args[i])
		}
	}
	if options.All && options.Principal != "" {
		return destroyOptions{}, errors.New("-A option is exclusive with -p option")
	}
	return options, nil
}

func runDestroy(args []string, stderr io.Writer) error {
	options, err := parseDestroyArgs(args)
	if err != nil {
		return err
	}
	name := options.Cache
	if name == "" {
		name = os.Getenv("KRB5CCNAME")
	}
	if name == "" {
		name = fmt.Sprintf("FILE:/tmp/krb5cc_%d", os.Getuid())
	}
	resolved, err := ccache.Resolve(name)
	if err != nil {
		if options.Quiet && errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	defer resolved.Close()

	if options.All {
		caches, err := resolved.Collection()
		if err != nil {
			return err
		}
		for _, cache := range caches {
			err := cache.Destroy()
			_ = cache.Close()
			if err != nil && !(options.Quiet && errors.Is(err, os.ErrNotExist)) {
				fmt.Fprintf(stderr, "while destroying cache %s: %v\n", cache.Name(), err)
			}
		}
		return nil
	}
	if options.Principal != "" {
		target, err := principal.Parse(options.Principal)
		if err != nil {
			return fmt.Errorf("while parsing principal name %s: %w", options.Principal, err)
		}
		caches, err := resolved.Collection()
		if err != nil {
			return err
		}
		for _, cache := range caches {
			value, readErr := cache.Read()
			if readErr == nil && value.DefaultPrincipal.String() == target.String() {
				err = cache.Destroy()
				_ = cache.Close()
				if err != nil && options.Quiet && errors.Is(err, os.ErrNotExist) {
					return nil
				}
				return err
			}
			_ = cache.Close()
		}
		return fmt.Errorf("while finding cache for %s", target.String())
	}
	err = resolved.Destroy()
	if options.Quiet && errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}
