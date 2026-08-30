package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/user"
	"strings"

	"github.com/Exonical/go-kerberos/krb5/ccache"
	"github.com/Exonical/go-kerberos/krb5/client"
	"github.com/Exonical/go-kerberos/krb5/config"
	"github.com/Exonical/go-kerberos/krb5/kpasswd"
	"github.com/Exonical/go-kerberos/krb5/principal"
)

func main() {
	if err := runPasswd(os.Args[1:], os.Stdin, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "gokpasswd: %v\n", err)
		os.Exit(1)
	}
}

func runPasswd(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	if len(args) > 1 {
		return fmt.Errorf("usage: gokpasswd [principal]")
	}
	cfg, err := loadPasswdConfig()
	if err != nil {
		return err
	}
	var target principal.Principal
	if len(args) == 1 {
		target, err = parsePasswdPrincipal(args[0], cfg)
	} else {
		target, err = defaultPasswdPrincipal(cfg)
	}
	if err != nil {
		return err
	}
	reader := bufio.NewReader(stdin)
	current, err := promptPassword(reader, stderr, fmt.Sprintf("Password for %s: ", target.String()))
	if err != nil {
		return err
	}
	newPassword, err := promptPassword(reader, stderr, "Enter new password: ")
	if err != nil {
		return err
	}
	again, err := promptPassword(reader, stderr, "Enter it again: ")
	if err != nil {
		return err
	}
	if err := validatePasswordConfirmation(newPassword, again); err != nil {
		return err
	}
	kerberos := &client.Client{Config: cfg}
	if err := (&kpasswd.Client{Kerberos: kerberos}).ChangePassword(
		context.Background(), target, current, newPassword); err != nil {
		return err
	}
	fmt.Fprintln(stdout, "Password changed.")
	return nil
}

func validatePasswordConfirmation(password, confirmation string) error {
	if password == "" {
		return fmt.Errorf("empty password")
	}
	if password != confirmation {
		return fmt.Errorf("passwords do not match")
	}
	return nil
}

func loadPasswdConfig() (*config.Config, error) {
	path := os.Getenv("KRB5_CONFIG")
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

func parsePasswdPrincipal(value string, cfg *config.Config) (principal.Principal, error) {
	if !strings.Contains(value, "@") {
		if cfg == nil || cfg.DefaultRealm == "" {
			return principal.Principal{}, fmt.Errorf("principal has no realm and no default realm is configured")
		}
		value += "@" + cfg.DefaultRealm
	}
	p, err := principal.Parse(value)
	if err != nil {
		return principal.Principal{}, fmt.Errorf("parsing client name: %w", err)
	}
	return *p, nil
}

func defaultPasswdPrincipal(cfg *config.Config) (principal.Principal, error) {
	name := os.Getenv("KRB5CCNAME")
	if name == "" {
		name = fmt.Sprintf("FILE:/tmp/krb5cc_%d", os.Getuid())
	}
	if cache, err := ccache.ReadName(name); err == nil {
		return cache.DefaultPrincipal, nil
	}
	current, err := user.Current()
	if err != nil || current.Username == "" {
		return principal.Principal{}, fmt.Errorf("unable to identify user from password file")
	}
	return parsePasswdPrincipal(current.Username, cfg)
}

func promptPassword(reader *bufio.Reader, stderr io.Writer, prompt string) (string, error) {
	fmt.Fprint(stderr, prompt)
	value, err := reader.ReadString('\n')
	if err != nil && err != io.EOF {
		return "", fmt.Errorf("reading password: %w", err)
	}
	value = strings.TrimSuffix(strings.TrimSuffix(value, "\n"), "\r")
	if value == "" {
		return "", fmt.Errorf("empty password")
	}
	return value, nil
}
