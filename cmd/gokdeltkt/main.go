package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"

	"github.com/Exonical/go-kerberos/cmd/internal/ccacheutil"
	"github.com/Exonical/go-kerberos/krb5/ccache"
	"github.com/Exonical/go-kerberos/krb5/principal"
)

type deleteOptions struct {
	Cache    string
	Etype    string
	Flags    uint32
	Quiet    bool
	Services []string
}

var errDeleteFailures = errors.New("one or more tickets could not be deleted")

func main() {
	if err := runDelete(os.Args[1:], os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "gokdeltkt: %v\n", err)
		os.Exit(1)
	}
}

func parseDeleteArgs(args []string) (deleteOptions, error) {
	var options deleteOptions
	for i := 0; i < len(args); i++ {
		if args[i] == "" {
			return deleteOptions{}, errors.New("empty argument")
		}
		switch args[i] {
		case "-c", "-e", "-f":
			if i+1 >= len(args) || args[i+1] == "" {
				return deleteOptions{}, fmt.Errorf("%s requires a value", args[i])
			}
			i++
			switch args[i-1] {
			case "-c":
				options.Cache = args[i]
			case "-e":
				options.Etype = args[i]
			case "-f":
				value, err := strconv.ParseUint(args[i], 0, 32)
				if err != nil {
					return deleteOptions{}, fmt.Errorf("invalid flags: %w", err)
				}
				options.Flags = uint32(value)
			}
		case "-q":
			options.Quiet = true
		case "-h":
			return deleteOptions{}, errors.New("usage: gokdeltkt [-c ccache] [-e etype] [-f flags] [-q] service1 service2 ...")
		default:
			if args[i][0] == '-' {
				return deleteOptions{}, fmt.Errorf("unknown option %s", args[i])
			}
			options.Services = append(options.Services, args[i])
		}
	}
	if len(options.Services) == 0 {
		return deleteOptions{}, errors.New("usage: gokdeltkt [-c ccache] [-e etype] [-f flags] [-q] service1 service2 ...")
	}
	return options, nil
}

func runDelete(args []string, stderr io.Writer) error {
	options, err := parseDeleteArgs(args)
	if err != nil {
		return err
	}
	etype, err := parseDeleteEnctype(options.Etype)
	if err != nil {
		return err
	}
	cfg, err := ccacheutil.LoadConfig()
	if err != nil {
		return fmt.Errorf("while loading configuration: %w", err)
	}
	cache, err := ccache.ResolveWithConfig(options.Cache, cfg)
	if err != nil {
		return fmt.Errorf("while opening cache: %w", err)
	}
	defer cache.Close()
	value, err := cache.Read()
	if err != nil {
		return fmt.Errorf("while reading cache: %w", err)
	}

	flags := ccache.MITMatchServerName
	if options.Etype != "" {
		flags |= ccache.MITMatchSupportedKTypes
	}
	match := ccache.Credential{Client: value.DefaultPrincipal}
	var failures int
	for _, serviceName := range options.Services {
		service, parseErr := principal.Parse(serviceName)
		if parseErr != nil {
			if !options.Quiet {
				fmt.Fprintf(stderr, "%s: %v while parsing principal name\n", serviceName, parseErr)
			}
			failures++
			continue
		}
		match.Server = *service
		match.Enctype = etype
		credential, retrieveErr := cache.Retrieve(match, flags)
		if retrieveErr != nil {
			fmt.Fprintf(stderr, "%s: %v while retrieving credentials\n", serviceName, retrieveErr)
			failures++
			continue
		}
		if removeErr := cache.Remove(credential, options.Flags); removeErr != nil {
			fmt.Fprintf(stderr, "%s: %v while removing credentials\n", serviceName, removeErr)
			failures++
		}
	}
	if failures != 0 {
		return errDeleteFailures
	}
	return nil
}

func parseDeleteEnctype(value string) (int32, error) {
	if value == "" {
		return 0, nil
	}
	return ccacheutil.ParseEnctype(value)
}
