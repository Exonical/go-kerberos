// Command gokproplog displays and resets MIT-compatible iprop update logs.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Exonical/go-kerberos/krb5/config"
	"github.com/Exonical/go-kerberos/krb5/iprop"
)

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string, out, errOut io.Writer) error {
	fs := flag.NewFlagSet("gokproplog", flag.ContinueOnError)
	fs.SetOutput(errOut)
	var verbose int
	var entries uint
	var reset bool
	var help bool
	fs.BoolVar(&reset, "R", false, "reinitialize the ulog")
	fs.UintVar(&entries, "e", 0, "number of entries")
	fs.BoolVar(&help, "h", false, "show usage")
	fs.Func("v", "verbose output", func(string) error { verbose++; return nil })
	if err := fs.Parse(args); err != nil {
		return err
	}
	if help {
		fmt.Fprintln(out, "Usage: gokproplog [-h] [-v] [-v] [-e num]\n       gokproplog -R")
		return nil
	}
	path, err := resolveLogPath()
	if err != nil {
		return err
	}
	if reset {
		fmt.Fprintf(out, "\nKerberos update log (%s)\n", path)
		log, err := iprop.Open(path)
		if err != nil {
			return err
		}
		if err := log.Reset(); err != nil {
			_ = log.Close()
			return err
		}
		_ = log.Close()
		fmt.Fprintln(out, "Reinitialized the ulog.")
		return nil
	}
	log, err := iprop.OpenReadOnly(path)
	if err != nil {
		return err
	}
	defer log.Close()
	header := log.Header()
	fmt.Fprintf(out, "\nKerberos update log (%s)\n", path)
	fmt.Fprintln(out, "Update log dump :")
	fmt.Fprintf(out, "\tLog version # : %d\n", header.Version)
	fmt.Fprintf(out, "\tLog state : %s\n", stateName(header.State))
	fmt.Fprintf(out, "\tEntry block size : %d\n", header.Block)
	fmt.Fprintf(out, "\tNumber of entries : %d\n", header.NumEntries)
	if header.LastSno == 0 {
		fmt.Fprintln(out, "\tLast serial # : None")
	} else {
		if header.FirstSno == 0 {
			fmt.Fprintln(out, "\tFirst serial # : None")
		} else {
			fmt.Fprintf(out, "\tFirst serial # : %d\n", header.FirstSno)
		}
		fmt.Fprintf(out, "\tLast serial # : %d\n", header.LastSno)
	}
	if header.LastTime.Seconds == 0 {
		fmt.Fprintln(out, "\tLast time stamp : None")
	} else {
		if header.FirstTime.Seconds == 0 {
			fmt.Fprintln(out, "\tFirst time stamp : None")
		} else {
			fmt.Fprintf(out, "\tFirst time stamp : %s", ctime(header.FirstTime))
		}
		fmt.Fprintf(out, "\tLast time stamp : %s", ctime(header.LastTime))
	}
	if verbose > 0 {
		updates, err := log.GetEntries(0)
		if err != nil {
			return err
		}
		if entries > 0 && uint(len(updates)) > entries {
			updates = updates[len(updates)-int(entries):]
		}
		for _, entry := range updates {
			printEntry(out, entry, verbose)
		}
	}
	fmt.Fprintln(out)
	return nil
}

func stateName(state uint16) string {
	switch state {
	case 1:
		return "Stable"
	case 2:
		return "Unstable"
	case 3:
		return "Corrupt"
	default:
		return fmt.Sprintf("Unknown state: %d", state)
	}
}

func ctime(value iprop.Time) string {
	return time.Unix(int64(value.Seconds), int64(value.Useconds)*1000).Local().Format("Mon Jan _2 15:04:05 2006\n")
}

func printEntry(out io.Writer, entry iprop.UlogEntry, verbose int) {
	fmt.Fprintln(out, "---")
	fmt.Fprintln(out, "Update Entry")
	fmt.Fprintf(out, "\tUpdate serial # : %d\n", entry.Serial)
	if entry.Dummy {
		fmt.Fprintln(out, "\tDummy entry")
		return
	}
	if entry.Update.Deleted {
		fmt.Fprintln(out, "\tUpdate operation : Delete")
	} else {
		fmt.Fprintln(out, "\tUpdate operation : Add")
	}
	fmt.Fprintf(out, "\tUpdate principal : %s\n", entry.Update.PrincipalName)
	fmt.Fprintf(out, "\tUpdate size : %d\n", len(entry.Update.MarshalXDR()))
	fmt.Fprintf(out, "\tUpdate committed : %t\n", entry.Commit)
	if entry.Time.Seconds == 0 {
		fmt.Fprintln(out, "\tUpdate time stamp : None")
	} else {
		fmt.Fprintf(out, "\tUpdate time stamp : %s", ctime(entry.Time))
	}
	fmt.Fprintf(out, "\tAttributes changed : %d\n", len(entry.Update.Entry))
	if verbose > 1 {
		for _, value := range entry.Update.Entry {
			fmt.Fprintf(out, "\t\tAttribute type : %d\n", value.Type)
		}
	}
}

func resolveLogPath() (string, error) {
	configPath := os.Getenv("KRB5_KDC_PROFILE")
	if configPath == "" {
		configPath = "/etc/krb5kdc/kdc.conf"
	}
	data, err := os.ReadFile(configPath)
	if err != nil {
		return "", err
	}
	cfg, err := config.ParseKDCConf(data)
	if err != nil {
		return "", err
	}
	profile, err := config.Parse(data)
	if err != nil {
		return "", err
	}
	realm := os.Getenv("KRB5_REALM")
	if realm == "" {
		realm = os.Getenv("KRB5_DEFAULT_REALM")
	}
	if realm == "" {
		realm = profile.DefaultRealm
	}
	if realm == "" {
		switch len(cfg.Realms) {
		case 0:
			realm = ""
		case 1:
			for name := range cfg.Realms {
				realm = name
			}
		default:
			return "", fmt.Errorf("multiple realms configured; set default_realm in krb5.conf")
		}
	}
	var values map[string][]string
	if setting, ok := cfg.Realm(realm); ok {
		values = setting.Values
	}
	if values == nil {
		values = cfg.Defaults
	}
	if module := strings.TrimSpace(strings.Join(values["database_module"], " ")); module != "" {
		if moduleValues := profile.SubsectionOptions["dbmodules"][module]; moduleValues != nil {
			for key, value := range moduleValues {
				values[key] = value
			}
		}
	}
	path := strings.TrimSpace(strings.Join(values["iprop_logfile"], " "))
	if path != "" {
		return path, nil
	}
	db := strings.TrimSpace(strings.Join(values["database_name"], " "))
	if db == "" {
		db = filepath.Join("/var/lib/krb5kdc", "principal")
	}
	return db + ".ulog", nil
}
