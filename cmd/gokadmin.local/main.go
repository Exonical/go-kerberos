package main

import (
	"bufio"
	"context"
	"fmt"
	"os"

	"github.com/Exonical/go-kerberos/krb5/kadmin"
)

func main() {
	opts, err := kadmin.ParseStartup(os.Args[1:], true)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if opts.MasterPassword && opts.Password == "" {
		fmt.Fprint(os.Stderr, "Enter KDC database master password: ")
		_, _ = fmt.Fscanln(os.Stdin, &opts.Password)
	}
	if err := kadmin.RunLocal(context.Background(), opts, bufio.NewReader(os.Stdin), os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
