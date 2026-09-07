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
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Exonical/go-kerberos/krb5/config"
	"github.com/Exonical/go-kerberos/krb5/crypto"
	"github.com/Exonical/go-kerberos/krb5/kdb"
	"github.com/Exonical/go-kerberos/krb5/kdb/mitdump"
	"github.com/Exonical/go-kerberos/krb5/principal"
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
			opts.stash = defaultStashPath(opts.realm)
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
	case "add_mkey":
		return addMKey(opts, rest, in, out, errOut)
	case "use_mkey":
		return useMKey(opts, rest, in, out, errOut)
	case "list_mkeys":
		return listMKeys(opts, in, out)
	case "update_princ_encryption":
		return updatePrincipalEncryption(opts, rest, in, out, errOut)
	case "purge_mkeys":
		return purgeMKeys(opts, rest, in, out, errOut)
	case "tabdump":
		return tabDump(opts, rest, out)
	default:
		return fmt.Errorf("unsupported command %q (supported: create destroy stash dump load add_mkey use_mkey list_mkeys update_princ_encryption purge_mkeys tabdump)", command)
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
	value = strings.TrimSuffix(value, "\n")
	value = strings.TrimSuffix(value, "\r")
	return value, nil
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
		kvno := uint32(1)
		if len(store.MasterKeys) > 0 {
			kvno = store.MasterKeys[0].KVNO
		}
		if err := mitdump.WriteStashFile(opts.stash, opts.realm, store.MasterEnctype, kvno, store.MasterKey); err != nil {
			return err
		}
	}
	fmt.Fprintf(out, "Initializing database '%s' for realm '%s'\n", opts.db, opts.realm)
	return nil
}

func writeDump(path string, db *kdb.Database, password string) error {
	return writeDumpAtomic(path, db, password, false)
}

func writeDumpAtomic(path string, db *kdb.Database, password string, replace bool) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil { // nosemgrep: tmp.opengrep-rules.go.lang.correctness.permissions.incorrect-default-permission -- 0700 directory is intentionally restrictive
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
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
	if replace {
		return os.Rename(name, path)
	}
	if err := os.Link(name, path); err != nil {
		return fmt.Errorf("database %q already exists: %w", path, err)
	}
	return os.Remove(name)
}

func defaultStashPath(realm string) string {
	const defaultKeyFileStub = "/var/lib/krb5kdc/.k5."
	path := os.Getenv("KRB5_KDC_PROFILE")
	if path == "" {
		path = "/etc/krb5kdc/kdc.conf"
	}
	data, err := os.ReadFile(path)
	if err == nil {
		if profile, parseErr := config.ParseKDCConf(data); parseErr == nil {
			if settings, ok := profile.Realm(realm); ok {
				for key, values := range settings.Values {
					if strings.EqualFold(key, "key_stash_file") && len(values) > 0 {
						if value := strings.TrimSpace(values[0]); value != "" {
							return value
						}
					}
				}
			}
		}
	}
	return defaultKeyFileStub + realm
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
	kvno := store.SuppliedMKVNO
	if kvno == 0 {
		kvno = 1
	}
	return mitdump.WriteStashFile(opts.stash, store.Realm, store.MasterEnctype, kvno, store.MasterKey)
}

func loadMutable(opts options, in io.Reader, out io.Writer) (*kdb.Database, *mitdump.FileStore, error) {
	password, err := masterPassword(opts, in, out, false)
	if err != nil {
		return nil, nil, err
	}
	store, err := mitdump.LoadWithMasterPassword(opts.db, password)
	if err != nil {
		return nil, nil, err
	}
	db := kdb.NewDatabase(store.Realm)
	db.MasterKeys = append([]kdb.Key(nil), store.MasterKeys...)
	db.ActiveMKeys = append([]kdb.ActKVNO(nil), store.ActiveMKeys...)
	db.MKeyAux = append([]kdb.MKeyAuxEntry(nil), store.MKeyAux...)
	for _, policy := range store.Policies() {
		if err := db.CreatePolicy(policy); err != nil {
			return nil, nil, err
		}
	}
	for _, record := range store.Records() {
		if isKM(record.Name) {
			continue
		}
		if err := db.ImportPrincipal(record); err != nil {
			return nil, nil, err
		}
	}
	return db, store, nil
}

func writeDumpAtomicWithMasterKey(path string, db *kdb.Database,
	key kdb.Key, replace bool) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil { // nosemgrep: tmp.opengrep-rules.go.lang.correctness.permissions.incorrect-default-permission -- 0700 directory is intentionally restrictive
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := mitdump.WriteWithMasterKey(tmp, db, key.Enctype, key.Key); err != nil {
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
	if replace {
		return os.Rename(name, path)
	}
	return os.Rename(name, path)
}

func parseMKeyFlags(rest []string) (etype int32, stash, force, dryRun, verbose bool, pattern string, err error) {
	etype = crypto.EnctypeAES256SHA1
	for i := 0; i < len(rest); i++ {
		switch rest[i] {
		case "-e":
			if i+1 >= len(rest) {
				return 0, false, false, false, false, "", errors.New("-e requires an enctype")
			}
			parsed, parseErr := strconv.ParseInt(rest[i+1], 10, 32)
			if parseErr != nil {
				return 0, false, false, false, false, "", fmt.Errorf("invalid enctype %q", rest[i+1])
			}
			etype = int32(parsed)
			i++
		case "-s":
			stash = true
		case "-f":
			force = true
		case "-n":
			dryRun = true
		case "-v":
			verbose = true
		default:
			if strings.HasPrefix(rest[i], "-") {
				return 0, false, false, false, false, "", fmt.Errorf("unknown option %q", rest[i])
			}
			if pattern != "" {
				return 0, false, false, false, false, "", errors.New("too many arguments")
			}
			pattern = rest[i]
		}
	}
	return
}

func addMKey(opts options, rest []string, in io.Reader, out, errOut io.Writer) error {
	etypeID, stash, _, _, _, _, err := parseMKeyFlags(rest)
	if err != nil {
		return err
	}
	password, err := masterPassword(opts, in, errOut, false)
	if err != nil {
		return err
	}
	db, store, err := loadMutable(options{db: opts.db, pass: password}, strings.NewReader(""), errOut)
	if err != nil {
		return err
	}
	newPassword, err := masterPassword(options{}, in, errOut, true)
	if err != nil {
		return err
	}
	etype, err := crypto.NewRegistry().Get(etypeID)
	if err != nil {
		return err
	}
	keyBytes, err := etype.StringToKey([]byte(newPassword), []byte(store.Realm+"KM"), nil)
	if err != nil {
		return err
	}
	nextKVNO := uint32(1)
	for _, key := range db.MasterKeys {
		if key.KVNO >= nextKVNO {
			nextKVNO = key.KVNO + 1
		}
	}
	db.MasterKeys = append([]kdb.Key{{Enctype: etypeID, KVNO: nextKVNO,
		Key: keyBytes, Salt: store.Realm + "KM"}}, db.MasterKeys...)
	db.MKeyAux = nil
	if len(db.ActiveMKeys) == 0 {
		db.ActiveMKeys = []kdb.ActKVNO{{KVNO: uint16(db.MasterKeys[0].KVNO), ActTime: 0}}
	}
	if err := writeDumpAtomicWithMasterKey(opts.db, db, db.MasterKeys[0], true); err != nil {
		return err
	}
	if stash || opts.stash != "" {
		path := opts.stash
		if path == "" {
			path = defaultStashPath(store.Realm)
		}
		if err := mitdump.WriteStashFile(path, store.Realm, etypeID, nextKVNO, keyBytes); err != nil {
			return err
		}
	}
	fmt.Fprintf(out, "Adding new master key, version %d\n", nextKVNO)
	return nil
}

func useMKey(opts options, rest []string, in io.Reader, out, errOut io.Writer) error {
	if len(rest) < 1 || len(rest) > 2 {
		return errors.New("use_mkey requires kvno [time]")
	}
	kvno64, err := strconv.ParseUint(rest[0], 10, 32)
	if err != nil || kvno64 == 0 {
		return errors.New("master key version must be nonzero")
	}
	db, store, err := loadMutable(opts, in, errOut)
	if err != nil {
		return err
	}
	available := false
	for _, key := range db.MasterKeys {
		if key.KVNO == uint32(kvno64) {
			available = true
			break
		}
	}
	if !available {
		return fmt.Errorf("master key version %d does not exist", kvno64)
	}
	when := time.Now().UTC()
	if len(rest) == 2 {
		when, err = parseMKeyTime(rest[1], when)
		if err != nil {
			return err
		}
	}
	updated := make([]kdb.ActKVNO, 0, len(db.ActiveMKeys)+1)
	for _, value := range db.ActiveMKeys {
		if value.KVNO != uint16(kvno64) {
			updated = append(updated, value)
		}
	}
	updated = append(updated, kdb.ActKVNO{KVNO: uint16(kvno64), ActTime: when.Unix()})
	sort.SliceStable(updated, func(i, j int) bool { return updated[i].ActTime < updated[j].ActTime })
	if len(updated) == 0 || updated[0].ActTime > time.Now().Unix() {
		return errors.New("there must be one master key currently active")
	}
	if _, err := kdb.EncodeACTKVNO(updated); err != nil {
		return fmt.Errorf("invalid activation time: %w", err)
	}
	db.ActiveMKeys = updated
	if err := writeDumpAtomicWithMasterKey(opts.db, db, db.MasterKeys[0], true); err != nil {
		return err
	}
	_ = store
	return nil
}

func parseMKeyTime(value string, now time.Time) (time.Time, error) {
	if strings.EqualFold(value, "now") {
		return now, nil
	}
	if seconds, err := strconv.ParseInt(value, 10, 64); err == nil {
		return time.Unix(seconds, 0).UTC(), nil
	}
	for _, layout := range []string{time.RFC3339, "20060102150405", "2006-01-02 15:04:05"} {
		if parsed, err := time.ParseInLocation(layout, value, time.Local); err == nil {
			return parsed.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("could not parse date-time string %q", value)
}

func listMKeys(opts options, in io.Reader, out io.Writer) error {
	db, _, err := loadMutable(opts, in, os.Stderr)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "Master keys for Principal: K/M@%s\n", db.Realm)
	now := time.Now().Unix()
	active := uint32(0)
	var activeTime int64 = -1 << 62
	for _, value := range db.ActiveMKeys {
		if int64(value.ActTime) <= now && int64(value.ActTime) >= activeTime {
			activeTime = int64(value.ActTime)
			active = uint32(value.KVNO)
		}
	}
	for _, key := range db.MasterKeys {
		found := false
		for _, value := range db.ActiveMKeys {
			if value.KVNO == uint16(key.KVNO) {
				found = true
				mark := ""
				if key.KVNO == active {
					mark = " *"
				}
				fmt.Fprintf(out, "KVNO: %d, Enctype: %s, Active on: %s%s\n",
					key.KVNO, crypto.EnctypeName(key.Enctype),
					time.Unix(value.ActTime, 0).Local().Format("Mon Jan 02 15:04:05 MST 2006"), mark)
			}
		}
		if !found {
			fmt.Fprintf(out, "KVNO: %d, Enctype: %s, No activate time set\n",
				key.KVNO, crypto.EnctypeName(key.Enctype))
		}
	}
	return nil
}

func updatePrincipalEncryption(opts options, rest []string, in io.Reader, out, errOut io.Writer) error {
	_, _, force, dryRun, verbose, pattern, err := parseMKeyFlags(rest)
	if err != nil {
		return err
	}
	db, _, err := loadMutable(opts, in, errOut)
	if err != nil {
		return err
	}
	active := findActiveMKey(db.ActiveMKeys, time.Now().Unix())
	if active == 0 {
		return errors.New("there must be one master key currently active")
	}
	matcher, err := principalPattern(pattern)
	if err != nil {
		return err
	}
	type change struct {
		record kdb.PrincipalRecord
		update bool
	}
	var changes []change
	for _, name := range db.ListPrincipals() {
		parsed, parseErr := principal.Parse(name)
		if parseErr != nil || isKM(*parsed) || !matcher(name) {
			continue
		}
		record, ok, lookupErr := db.Lookup(*parsed)
		if lookupErr != nil || !ok {
			continue
		}
		current, _ := kdb.MKVNO(record.TLData)
		needs := current != active
		changes = append(changes, change{record: record, update: needs})
		if verbose {
			if dryRun {
				if needs {
					fmt.Fprintf(out, "would update: %s\n", name)
				} else {
					fmt.Fprintf(out, "would skip: %s\n", name)
				}
			} else if needs {
				fmt.Fprintf(out, "updating: %s\n", name)
			} else {
				fmt.Fprintf(out, "skipping: %s\n", name)
			}
		}
	}
	if !force && !dryRun {
		fmt.Fprintf(out, "Re-encrypt all keys not using master key vno %d? ", active)
		var answer string
		if _, err := fmt.Fscanln(newInputReader(in), &answer); err != nil ||
			!strings.EqualFold(answer, "yes") {
			return errors.New("operation cancelled")
		}
	}
	var updated uint32
	if !dryRun {
		for _, item := range changes {
			if !item.update {
				continue
			}
			encoded, encodeErr := kdb.EncodeMKVNO(active)
			if encodeErr != nil {
				return encodeErr
			}
			item.record.TLData = replaceTL(item.record.TLData, kdb.TLData{Type: kdb.MKVNOType, Data: encoded})
			if err := db.UpdatePrincipal(item.record); err != nil {
				return err
			}
			updated++
		}
		if err := writeDumpAtomicWithMasterKey(opts.db, db, db.MasterKeys[0], true); err != nil {
			return err
		}
	} else {
		for _, item := range changes {
			if item.update {
				updated++
			}
		}
	}
	fmt.Fprintf(out, "%d principals processed: %d updated, %d already current\n",
		len(changes), updated, uint32(len(changes))-updated)
	return nil
}

func purgeMKeys(opts options, rest []string, in io.Reader, out, errOut io.Writer) error {
	_, _, force, dryRun, verbose, _, err := parseMKeyFlags(rest)
	if err != nil {
		return err
	}
	if dryRun {
		force = true
	}
	db, store, err := loadMutable(opts, in, errOut)
	if err != nil {
		return err
	}
	used := make(map[uint32]bool)
	for _, name := range db.ListPrincipals() {
		parsed, parseErr := principal.Parse(name)
		if parseErr != nil || isKM(*parsed) {
			continue
		}
		record, ok, _ := db.Lookup(*parsed)
		if !ok {
			continue
		}
		kvno, _ := kdb.MKVNO(record.TLData)
		if kvno == 0 {
			kvno = 1
		}
		used[kvno] = true
	}
	stashKVNO := uint32(1)
	if store.SuppliedMKVNO != 0 {
		stashKVNO = store.SuppliedMKVNO
	}
	var kept []kdb.Key
	purged := 0
	for _, key := range db.MasterKeys {
		if used[key.KVNO] || key.KVNO == stashKVNO {
			kept = append(kept, key)
		} else {
			purged++
			if verbose {
				fmt.Fprintf(out, "KVNO: %d\n", key.KVNO)
			}
		}
	}
	if purged == 0 {
		fmt.Fprintln(out, "All keys in use, nothing purged.")
		return nil
	}
	if !used[stashKVNO] {
		return errors.New("master key stash file needs updating, command aborting")
	}
	if !force {
		fmt.Fprint(out, "Purge unused master keys? ")
		var answer string
		if _, err := fmt.Fscanln(newInputReader(in), &answer); err != nil ||
			!strings.EqualFold(answer, "yes") {
			return errors.New("operation cancelled")
		}
	}
	if dryRun {
		fmt.Fprintf(out, "%d key(s) would be purged.\n", purged)
		return nil
	}
	db.MasterKeys = kept
	filteredActive := db.ActiveMKeys[:0]
	for _, value := range db.ActiveMKeys {
		if used[uint32(value.KVNO)] {
			filteredActive = append(filteredActive, value)
		}
	}
	db.ActiveMKeys = filteredActive
	filteredAux := db.MKeyAux[:0]
	for _, value := range db.MKeyAux {
		if used[uint32(value.MKeyKVNO)] {
			filteredAux = append(filteredAux, value)
		}
	}
	db.MKeyAux = filteredAux
	if err := writeDumpAtomicWithMasterKey(opts.db, db, db.MasterKeys[0], true); err != nil {
		return err
	}
	fmt.Fprintf(out, "%d key(s) purged.\n", purged)
	return nil
}

func tabDump(opts options, rest []string, out io.Writer) error {
	fs := flag.NewFlagSet("tabdump", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	omitHeader := fs.Bool("H", false, "omit header")
	csvOutput := fs.Bool("c", false, "CSV output")
	_ = fs.Bool("e", false, "empty hex values")
	_ = fs.Bool("n", false, "numeric output")
	outputFile := fs.String("o", "", "output file")
	if err := fs.Parse(rest); err != nil {
		return err
	}
	dumpType := ""
	for _, arg := range fs.Args() {
		if !strings.HasPrefix(arg, "-") {
			dumpType = arg
		}
	}
	if dumpType == "" {
		return errors.New("tabdump requires a dump type")
	}
	var store *mitdump.FileStore
	var err error
	if opts.pass != "" {
		store, err = mitdump.LoadWithMasterPassword(opts.db, opts.pass)
	} else {
		store, err = mitdump.Load(opts.db)
	}
	if err != nil {
		return err
	}
	if *outputFile != "" {
		file, err := os.OpenFile(*outputFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			return err
		}
		defer file.Close()
		out = file
	}
	separator := "\t"
	if *csvOutput {
		separator = ","
	}
	field := func(value string) string {
		if !*csvOutput {
			return tsvField(value)
		}
		if strings.ContainsAny(value, ",\"\r\n") {
			return `"` + strings.ReplaceAll(value, `"`, `""`) + `"`
		}
		return value
	}
	write := func(values ...string) {
		for i, value := range values {
			if i != 0 {
				fmt.Fprint(out, separator)
			}
			fmt.Fprint(out, field(value))
		}
		fmt.Fprintln(out)
	}
	switch dumpType {
	case "keyinfo":
		if !*omitHeader {
			write("principal", "kvno", "enctype")
		}
		for _, record := range store.Records() {
			for _, key := range record.Keys {
				write(record.Name.String(), fmt.Sprint(key.KVNO), crypto.EnctypeName(key.Enctype))
			}
		}
	case "princ_flags":
		if !*omitHeader {
			write("principal", "flags")
		}
		for _, record := range store.Records() {
			write(record.Name.String(), fmt.Sprint(record.Flags))
		}
	case "princ_meta":
		if !*omitHeader {
			write("principal", "kvno", "policy")
		}
		for _, record := range store.Records() {
			write(record.Name.String(), fmt.Sprint(record.KVNO), record.Policy)
		}
	case "princ_stringattrs":
		if !*omitHeader {
			write("principal", "attribute", "value")
		}
		for _, record := range store.Records() {
			keys := make([]string, 0, len(record.Strings))
			for key := range record.Strings {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			for _, key := range keys {
				write(record.Name.String(), key, record.Strings[key])
			}
		}
	case "princ_tktpolicy":
		if !*omitHeader {
			write("principal", "maxlife", "maxrenew")
		}
		for _, record := range store.Records() {
			write(record.Name.String(), fmt.Sprint(int64(record.MaxLife/time.Second)),
				fmt.Sprint(int64(record.MaxRenew/time.Second)))
		}
	default:
		return fmt.Errorf("unsupported tabdump type %q", dumpType)
	}
	return nil
}

func tsvField(value string) string {
	return strings.NewReplacer("\\", "\\\\", "\t", "\\t", "\n", "\\n", "\r", "\\r").Replace(value)
}

func replaceTL(values []kdb.TLData, replacement kdb.TLData) []kdb.TLData {
	for i := range values {
		if values[i].Type == replacement.Type {
			values[i] = replacement
			return values
		}
	}
	return append(values, replacement)
}

func findActiveMKey(values []kdb.ActKVNO, now int64) uint32 {
	var result uint32
	var latest int64 = -1 << 62
	for _, value := range values {
		if int64(value.ActTime) <= now && int64(value.ActTime) >= latest {
			latest = int64(value.ActTime)
			result = uint32(value.KVNO)
		}
	}
	return result
}

func principalPattern(pattern string) (func(string) bool, error) {
	if pattern == "" {
		pattern = "*@*"
	} else if !strings.Contains(pattern, "@") {
		pattern += "@*"
	}
	var b strings.Builder
	b.WriteByte('^')
	for i := 0; i < len(pattern); i++ {
		switch pattern[i] {
		case '*':
			b.WriteString(".*")
		case '?':
			b.WriteByte('.')
		case '[':
			end := strings.IndexByte(pattern[i+1:], ']')
			if end < 0 {
				return nil, fmt.Errorf("invalid principal pattern %q", pattern)
			}
			end += i + 1
			b.WriteString(pattern[i : end+1])
			i = end
		default:
			b.WriteString(regexp.QuoteMeta(string(pattern[i])))
		}
	}
	b.WriteByte('$')
	re, err := regexp.Compile(b.String())
	if err != nil {
		return nil, err
	}
	return re.MatchString, nil
}

func isKM(name principal.Principal) bool {
	return len(name.Components) == 2 && name.Components[0] == "K" &&
		name.Components[1] == "M"
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
	return writeFileAtomic(rest[0], data)
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
	if err := os.MkdirAll(filepath.Dir(opts.db), 0o700); err != nil { // nosemgrep: tmp.opengrep-rules.go.lang.correctness.permissions.incorrect-default-permission -- 0700 directory is intentionally restrictive
		return err
	}
	return writeFileAtomic(opts.db, data)
}

func writeFileAtomic(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil { // nosemgrep: tmp.opengrep-rules.go.lang.correctness.permissions.incorrect-default-permission -- 0700 directory is intentionally restrictive
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
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
