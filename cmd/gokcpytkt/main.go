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

type copyOptions struct {
	From     string
	Etype    string
	Flags    uint32
	Quiet    bool
	Dest     string
	Services []string
}

var errCopyFailures = errors.New("one or more tickets could not be copied")

func main() {
	if err := runCopy(os.Args[1:], os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "gokcpytkt: %v\n", err)
		os.Exit(1)
	}
}

func parseCopyArgs(args []string) (copyOptions, error) {
	var options copyOptions
	for i := 0; i < len(args); i++ {
		if args[i] == "" {
			return copyOptions{}, errors.New("empty argument")
		}
		switch args[i] {
		case "-c", "-e", "-f":
			if i+1 >= len(args) || args[i+1] == "" {
				return copyOptions{}, fmt.Errorf("%s requires a value", args[i])
			}
			i++
			switch args[i-1] {
			case "-c":
				options.From = args[i]
			case "-e":
				options.Etype = args[i]
			case "-f":
				value, err := strconv.ParseUint(args[i], 0, 32)
				if err != nil {
					return copyOptions{}, fmt.Errorf("invalid flags: %w", err)
				}
				options.Flags = uint32(value)
			}
		case "-q":
			options.Quiet = true
		case "-h":
			return copyOptions{}, errors.New("usage: gokcpytkt [-c from_ccache] [-e etype] [-f flags] [-q] dest_ccache service1 service2 ...")
		default:
			if args[i][0] == '-' {
				return copyOptions{}, fmt.Errorf("unknown option %s", args[i])
			}
			if options.Dest == "" {
				options.Dest = args[i]
			} else {
				options.Services = append(options.Services, args[i])
			}
		}
	}
	if options.Dest == "" || len(options.Services) == 0 {
		return copyOptions{}, errors.New("usage: gokcpytkt [-c from_ccache] [-e etype] [-f flags] [-q] dest_ccache service1 service2 ...")
	}
	return options, nil
}

func runCopy(args []string, stderr io.Writer) error {
	options, err := parseCopyArgs(args)
	if err != nil {
		return err
	}
	etype, err := parseOptionalEnctype(options.Etype)
	if err != nil {
		return err
	}
	cfg, err := ccacheutil.LoadConfig()
	if err != nil {
		return fmt.Errorf("while loading configuration: %w", err)
	}
	source, err := ccache.ResolveWithConfig(options.From, cfg)
	if err != nil {
		return fmt.Errorf("while opening source cache: %w", err)
	}
	defer source.Close()
	sourceCache, err := source.Read()
	if err != nil {
		return fmt.Errorf("while reading source cache: %w", err)
	}
	destination, err := ccache.ResolveWithConfig(options.Dest, cfg)
	if err != nil {
		return fmt.Errorf("while opening destination cache: %w", err)
	}
	defer destination.Close()

	flags := ccache.MITMatchServerName
	if options.Etype != "" {
		flags |= ccache.MITMatchSupportedKTypes
	}
	match := ccache.Credential{Client: sourceCache.DefaultPrincipal}
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
		credential, retrieveErr := source.Retrieve(match, flags)
		if retrieveErr != nil {
			fmt.Fprintf(stderr, "%s: %v while retrieving credentials\n", serviceName, retrieveErr)
			failures++
			continue
		}
		if storeErr := destination.Store(credential); storeErr != nil {
			fmt.Fprintf(stderr, "%s: %v while storing credentials\n", serviceName, storeErr)
			failures++
		}
	}
	if failures != 0 {
		return errCopyFailures
	}
	return nil
}

func parseOptionalEnctype(value string) (int32, error) {
	if value == "" {
		return 0, nil
	}
	return ccacheutil.ParseEnctype(value)
}
