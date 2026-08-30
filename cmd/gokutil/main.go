package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Exonical/go-kerberos/krb5/crypto"
	"github.com/Exonical/go-kerberos/krb5/keytab"
	"github.com/Exonical/go-kerberos/krb5/principal"
)

type utilOptions struct {
	Keytab       string
	Principal    string
	KVNO         uint64
	Enctype      string
	PasswordMode bool
	Key          string
	Slot         int
}

func main() {
	if err := runUtil(os.Args[1:], os.Stdout, os.Stdin); err != nil {
		fmt.Fprintf(os.Stderr, "gokutil: %v\n", err)
		os.Exit(1)
	}
}

func runUtil(args []string, stdout io.Writer, stdin io.Reader) error {
	if len(args) == 0 {
		return errors.New("command is required")
	}
	command := args[0]
	options, err := parseUtilArgs(args[1:])
	if err != nil {
		return err
	}
	switch command {
	case "list", "read_kt":
		return listUtilKeytab(options.Keytab, stdout)
	case "write_kt":
		kt, err := loadUtilKeytab(options.Keytab)
		if err != nil {
			return err
		}
		return writeUtilKeytab(options.Keytab, kt)
	case "addent":
		return addUtilEntry(options, stdin)
	case "delent":
		return deleteUtilEntry(options)
	default:
		return fmt.Errorf("unknown command %s", command)
	}
}

func parseUtilArgs(args []string) (utilOptions, error) {
	var options utilOptions
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-k":
			if i+1 >= len(args) {
				return utilOptions{}, errors.New("-k requires a keytab path")
			}
			i++
			options.Keytab = args[i]
		case "-p":
			if i+1 >= len(args) {
				return utilOptions{}, errors.New("-p requires a principal")
			}
			i++
			options.Principal = args[i]
		case "-kvno":
			if i+1 >= len(args) {
				return utilOptions{}, errors.New("-kvno requires a value")
			}
			i++
			value, err := strconv.ParseUint(args[i], 10, 32)
			if err != nil {
				return utilOptions{}, fmt.Errorf("invalid kvno: %w", err)
			}
			options.KVNO = value
		case "-e":
			if i+1 >= len(args) {
				return utilOptions{}, errors.New("-e requires an enctype")
			}
			i++
			options.Enctype = args[i]
		case "-password":
			options.PasswordMode = true
		case "-key":
			if i+1 >= len(args) {
				return utilOptions{}, errors.New("-key requires hex data")
			}
			i++
			options.Key = args[i]
		case "-slot":
			if i+1 >= len(args) {
				return utilOptions{}, errors.New("-slot requires a value")
			}
			i++
			value, err := strconv.Atoi(args[i])
			if err != nil || value < 1 {
				return utilOptions{}, errors.New("invalid keytab slot")
			}
			options.Slot = value
		default:
			return utilOptions{}, fmt.Errorf("unexpected argument %s", args[i])
		}
	}
	if options.Keytab == "" {
		return utilOptions{}, errors.New("-k is required")
	}
	return options, nil
}

func loadUtilKeytab(path string) (*keytab.Keytab, error) {
	kt, err := keytab.Resolve(path)
	if err == nil {
		return kt, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return &keytab.Keytab{}, nil
}

func listUtilKeytab(path string, stdout io.Writer) error {
	kt, err := keytab.Resolve(path)
	if err != nil {
		return err
	}
	fmt.Fprintln(stdout, "Keytab name:", path)
	fmt.Fprintln(stdout, "KVNO Principal")
	for i, entry := range kt.EntriesSnapshot() {
		fmt.Fprintf(stdout, "%d %d %s (%s)\n", i+1, entry.KVNO,
			entry.Principal.String(), utilEnctypeName(entry.Enctype))
	}
	return nil
}

func writeUtilKeytab(path string, kt *keytab.Keytab) error {
	file, err := os.OpenFile(strings.TrimPrefix(path, "FILE:"),
		os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	if err := keytab.Write(file, kt); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

func addUtilEntry(options utilOptions, stdin io.Reader) error {
	if options.Principal == "" || options.Enctype == "" {
		return errors.New("addent requires -p and -e")
	}
	if options.PasswordMode && options.Key != "" {
		return errors.New("-password and -key are mutually exclusive")
	}
	p, err := principal.Parse(options.Principal)
	if err != nil {
		return err
	}
	enctype, err := parseUtilEnctype(options.Enctype)
	if err != nil {
		return err
	}
	var key []byte
	if options.Key != "" {
		key, err = hex.DecodeString(options.Key)
		if err != nil {
			return fmt.Errorf("decode key: %w", err)
		}
	} else {
		fmt.Fprint(os.Stderr, "Password: ")
		line, readErr := io.ReadAll(stdin)
		if readErr != nil {
			return readErr
		}
		password := strings.TrimSpace(string(line))
		if password == "" {
			return errors.New("password is required")
		}
		etype, err := crypto.NewRegistry().Get(enctype)
		if err != nil {
			return err
		}
		key, err = etype.StringToKey([]byte(password),
			[]byte(p.Realm+strings.Join(p.Components, "")), nil)
		if err != nil {
			return err
		}
	}
	kt, err := loadUtilKeytab(options.Keytab)
	if err != nil {
		return err
	}
	if options.KVNO > uint64(^uint32(0)) {
		return errors.New("kvno exceeds uint32")
	}
	etype, err := crypto.NewRegistry().Get(enctype)
	if err != nil {
		return err
	}
	if len(key) != etype.KeySize() {
		return fmt.Errorf("key length %d does not match enctype %s (%d bytes)",
			len(key), options.Enctype, etype.KeySize())
	}
	if err := kt.AddEntry(keytab.Entry{Principal: *p, Timestamp: time.Now().Unix(),
		KVNO: uint32(options.KVNO), Enctype: enctype, Key: key}); err != nil {
		return err
	}
	return writeUtilKeytab(options.Keytab, kt)
}

func deleteUtilEntry(options utilOptions) error {
	if options.Slot < 1 {
		return errors.New("delent requires -slot")
	}
	kt, err := keytab.Resolve(options.Keytab)
	if err != nil {
		return err
	}
	entries := kt.EntriesSnapshot()
	if options.Slot > len(entries) {
		return errors.New("keytab slot does not exist")
	}
	entries = append(entries[:options.Slot-1], entries[options.Slot:]...)
	replacement := &keytab.Keytab{}
	for _, entry := range entries {
		if err := replacement.AddEntry(entry); err != nil {
			return err
		}
	}
	file, err := os.OpenFile(strings.TrimPrefix(options.Keytab, "FILE:"),
		os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	if err := keytab.Write(file, replacement); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

func parseUtilEnctype(value string) (int32, error) {
	names := map[string]int32{
		"aes128-cts-hmac-sha1-96": 17, "aes256-cts-hmac-sha1-96": 18,
		"aes128-cts-hmac-sha256-128": 19, "aes256-cts-hmac-sha384-192": 20,
		"camellia128-cts-cmac": 25, "camellia256-cts-cmac": 26,
		"camellia128-cts": 25, "camellia256-cts": 26,
		"17": 17, "18": 18, "19": 19, "20": 20, "25": 25, "26": 26,
	}
	if enctype, ok := names[strings.ToLower(value)]; ok {
		return enctype, nil
	}
	return 0, fmt.Errorf("unsupported enctype %s", value)
}

func utilEnctypeName(value int32) string {
	switch value {
	case 17:
		return "aes128-cts-hmac-sha1-96"
	case 18:
		return "aes256-cts-hmac-sha1-96"
	case 19:
		return "aes128-cts-hmac-sha256-128"
	case 20:
		return "aes256-cts-hmac-sha384-192"
	case 25:
		return "camellia128-cts-cmac"
	case 26:
		return "camellia256-cts-cmac"
	default:
		return fmt.Sprintf("etype-%d", value)
	}
}
