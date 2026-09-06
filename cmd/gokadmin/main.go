package main

import (
	"context"
	"fmt"
	"os"

	"github.com/Exonical/go-kerberos/krb5/kadmin"
)

func main() {
	opts, err := kadmin.ParseStartup(os.Args[1:], false)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if err := kadmin.RunRemote(context.Background(), opts, os.Stdin, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
