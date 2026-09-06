package main

import (
	"context"
	"fmt"
	"os"

	"github.com/Exonical/go-kerberos/krb5/kadmin"
	"golang.org/x/term"
)

func main() {
	opts, err := kadmin.ParseStartup(os.Args[1:], true)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if opts.MasterPassword && opts.Password == "" {
		fmt.Fprint(os.Stderr, "Enter KDC database master password: ")
		if term.IsTerminal(int(os.Stdin.Fd())) {
			value, readErr := term.ReadPassword(int(os.Stdin.Fd()))
			fmt.Fprintln(os.Stderr)
			if readErr != nil {
				fmt.Fprintln(os.Stderr, readErr)
				os.Exit(1)
			}
			opts.Password = string(value)
		} else {
			_, _ = fmt.Fscanln(os.Stdin, &opts.Password)
		}
	}
	if err := kadmin.RunLocal(context.Background(), opts, os.Stdin, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
