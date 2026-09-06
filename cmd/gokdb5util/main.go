// Command gokdb5util provides the supported kdb5_util database lifecycle
// operations backed by the Go MIT dump store.
package main

import (
	"bufio"
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/Exonical/go-kerberos/krb5/kdb"
	"github.com/Exonical/go-kerberos/krb5/kdb/mitdump"
	"golang.org/x/term"
)

type options struct {
	realm       string
	db          string
	stash       string
	pass        string
	prompt      bool
	force       bool
	stashCreate bool
}

func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string, in io.Reader, out, errOut io.Writer) error {
	opts, command, rest, err := parseOptions(args)
	if err != nil {
		return err
	}
	if opts.db == "" {
		opts.db = filepath.Join("/var/lib/krb5kdc", "principal")
	}
	in = newInputReader(in)
	switch command {
	case "create":
		for _, arg := range rest {
			if arg == "-s" {
				opts.stashCreate = true
			}
		}
		if opts.stashCreate && opts.stash == "" {
			opts.stash = opts.db + ".stash"
		}
		return createDB(opts, in, out, errOut)
	case "destroy":
		for _, arg := range rest {
			if arg == "-f" {
				opts.force = true
			}
		}
		return destroyDB(opts, in, out)
	case "stash":
		return stashDB(opts, in)
	case "dump":
		rest = commandArgs(rest, "-verbose")
		return dumpDB(opts, rest, out)
	case "load":
		rest = commandArgs(rest, "-verbose")
		return loadDB(opts, rest)
	default:
		return fmt.Errorf("unsupported command %q (supported: create destroy stash dump load)", command)
	}
}

func commandArgs(args []string, ignored ...string) []string {
	var out []string
	for _, arg := range args {
		skip := false
		for _, value := range ignored {
			if arg == value {
				skip = true
				break
			}
		}
		if !skip {
			out = append(out, arg)
		}
	}
	return out
}

func parseOptions(args []string) (options, string, []string, error) {
	var opts options
	fs := flag.NewFlagSet("gokdb5util", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&opts.realm, "r", "", "realm")
	fs.StringVar(&opts.db, "d", "", "database dump")
	fs.StringVar(&opts.stash, "sf", "", "stash file")
	fs.StringVar(&opts.pass, "P", "", "master password")
	fs.BoolVar(&opts.prompt, "m", false, "prompt for master password")
	fs.BoolVar(&opts.force, "f", false, "force")
	fs.BoolVar(&opts.stashCreate, "s", false, "write stash during create")
	if err := fs.Parse(args); err != nil {
		return opts, "", nil, err
	}
	if fs.NArg() == 0 {
		return opts, "", nil, errors.New("usage: gokdb5util [options] create|destroy|stash|dump|load")
	}
	return opts, fs.Arg(0), fs.Args()[1:], nil
}

type inputReader struct {
	*bufio.Reader
	file *os.File
}

func newInputReader(in io.Reader) *inputReader {
	if reader, ok := in.(*inputReader); ok {
		return reader
	}
	reader := &inputReader{Reader: bufio.NewReader(in)}
	if file, ok := in.(*os.File); ok {
		reader.file = file
	}
	return reader
}

func readPassword(in io.Reader, out io.Writer, prompt string) (string, error) {
	reader := newInputReader(in)
	if reader.file != nil && term.IsTerminal(int(reader.file.Fd())) {
		fmt.Fprint(out, prompt)
		value, err := term.ReadPassword(int(reader.file.Fd()))
		fmt.Fprintln(out)
		return string(value), err
	}
	fmt.Fprint(out, prompt)
	value, err := reader.ReadString('\n')
	if err != nil && err != io.EOF {
		return "", err
	}
	return strings.TrimSpace(value), nil
}

func masterPassword(opts options, in io.Reader, out io.Writer, confirm bool) (string, error) {
	if opts.pass != "" {
		return opts.pass, nil
	}
	value, err := readPassword(in, out, "Enter KDC database master password: ")
	if err != nil {
		return "", err
	}
	if !confirm {
		return value, nil
	}
	again, err := readPassword(in, out, "Re-enter KDC database master password: ")
	if err != nil {
		return "", err
	}
	if value == "" || value != again {
		return "", errors.New("master passwords do not match")
	}
	return value, nil
}

func createDB(opts options, in io.Reader, out, errOut io.Writer) error {
	if opts.realm == "" {
		return errors.New("create requires -r realm")
	}
	password, err := masterPassword(opts, in, errOut, true)
	if err != nil {
		return err
	}
	db := kdb.NewDatabase(opts.realm)
	for _, name := range []string{
		"K/M@" + opts.realm,
		"krbtgt/" + opts.realm + "@" + opts.realm,
		"kadmin/admin@" + opts.realm,
		"kadmin/changepw@" + opts.realm,
		"kadmin/history@" + opts.realm,
	} {
		if err := db.CreatePrincipal(name, password); err != nil {
			return fmt.Errorf("create %s: %w", name, err)
		}
	}
	if err := writeDump(opts.db, db, password); err != nil {
		return err
	}
	if opts.stash != "" {
		store, err := mitdump.LoadWithMasterPassword(opts.db, password)
		if err != nil {
			return err
		}
		if err := mitdump.WriteStashFile(opts.stash, opts.realm, store.MasterEnctype, 1, store.MasterKey); err != nil {
			return err
		}
	}
	fmt.Fprintf(out, "Initializing database '%s' for realm '%s'\n", opts.db, opts.realm)
	return nil
}

func writeDump(path string, db *kdb.Database, password string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := mitdump.WriteWithMasterPassword(tmp, db, password); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

func destroyDB(opts options, in io.Reader, out io.Writer) error {
	if !opts.force {
		fmt.Fprintf(out, "Deleting KDC database stored in '%s', are you sure? ", opts.db)
		reader := newInputReader(in)
		var answer string
		if _, err := fmt.Fscanln(reader, &answer); err != nil {
			return err
		}
		if !strings.EqualFold(answer, "yes") {
			return errors.New("database not deleted")
		}
	}
	if err := os.Remove(opts.db); err != nil && !os.IsNotExist(err) {
		return err
	}
	if opts.stash != "" {
		if err := os.Remove(opts.stash); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

func stashDB(opts options, in io.Reader) error {
	if opts.stash == "" {
		return errors.New("stash requires -sf stash file")
	}
	password, err := masterPassword(opts, in, os.Stderr, false)
	if err != nil {
		return err
	}
	store, err := mitdump.LoadWithMasterPassword(opts.db, password)
	if err != nil {
		return err
	}
	return mitdump.WriteStashFile(opts.stash, store.Realm, store.MasterEnctype, 1, store.MasterKey)
}

func dumpDB(opts options, rest []string, out io.Writer) error {
	data, err := os.ReadFile(opts.db)
	if err != nil {
		return err
	}
	if len(rest) == 0 {
		_, err = io.Copy(out, bytes.NewReader(data))
		return err
	}
	return os.WriteFile(rest[0], data, 0o600)
}

func loadDB(opts options, rest []string) error {
	if len(rest) != 1 {
		return errors.New("load requires a dump filename")
	}
	data, err := os.ReadFile(rest[0])
	if err != nil {
		return err
	}
	if _, err := mitdump.Parse(data); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(opts.db), 0o700); err != nil {
		return err
	}
	return os.WriteFile(opts.db, data, 0o600)
}
