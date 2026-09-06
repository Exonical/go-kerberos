package kadmin

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Exonical/go-kerberos/krb5/crypto"
	"github.com/Exonical/go-kerberos/krb5/kadm5"
	"github.com/Exonical/go-kerberos/krb5/keytab"
	"github.com/Exonical/go-kerberos/krb5/principal"
)

func (e *Engine) requireOps() error {
	if e.cfg.Ops == nil {
		return errors.New("kadmin: no operations adapter configured")
	}
	return nil
}

func (e *Engine) addPrincipal(args []string) error {
	if err := e.requireOps(); err != nil {
		return err
	}
	opts, err := e.parsePrincipalOptions(args, false)
	if err != nil {
		return fmt.Errorf("usage: add_principal [options] principal: %w", err)
	}
	if opts.entry.Policy == "" && opts.mask&kadm5.KADM5PolicyClear == 0 {
		if _, err := e.cfg.Ops.GetPolicy(context.Background(), "default"); err == nil {
			opts.entry.Policy = "default"
			opts.mask |= kadm5.KADM5Policy
			if !e.cfg.Script {
				fmt.Fprintf(e.cfg.Stderr, "No policy specified for %s; assigning \"default\"\n", e.canonical(opts.entry.Principal))
			}
		} else if !e.cfg.Script {
			fmt.Fprintf(e.cfg.Stderr, "No policy specified for %s; defaulting to no policy\n", e.canonical(opts.entry.Principal))
		}
	} else if opts.entry.Policy != "" && opts.mask&kadm5.KADM5Policy != 0 && !e.cfg.Script {
		if _, err := e.cfg.Ops.GetPolicy(context.Background(), opts.entry.Policy); err != nil {
			fmt.Fprintf(e.cfg.Stderr, "WARNING: policy \"%s\" does not exist\n", opts.entry.Policy)
		}
	}
	opts.mask &^= kadm5.KADM5PolicyClear
	if opts.nokey {
		opts.password = ""
	}
	if !opts.randkey && !opts.nokey && opts.password == "" {
		opts.password, err = e.prompt(fmt.Sprintf("Enter password for principal \"%s\": ", e.canonical(opts.entry.Principal)))
		if err != nil {
			return err
		}
		again, err := e.prompt(fmt.Sprintf("Re-enter password for principal \"%s\": ", e.canonical(opts.entry.Principal)))
		if err != nil {
			return err
		}
		if opts.password != again {
			return errors.New("passwords do not match")
		}
	}
	if err := e.cfg.Ops.CreatePrincipal(context.Background(), opts.entry, opts.password, opts.randkey, opts.nokey, opts.keySalts); err != nil {
		return err
	}
	e.info(fmt.Sprintf("Principal \"%s\" created.\n", e.canonical(opts.entry.Principal)))
	return nil
}

func (e *Engine) modifyPrincipal(args []string) error {
	if err := e.requireOps(); err != nil {
		return err
	}
	opts, err := e.parsePrincipalOptions(args, true)
	if err != nil {
		return fmt.Errorf("usage: modify_principal [options] principal: %w", err)
	}
	old, err := e.cfg.Ops.GetPrincipal(context.Background(), opts.entry.Principal)
	if err != nil {
		return err
	}
	opts.entry = mergeEntry(old, opts.entry, opts.mask)
	if err := e.cfg.Ops.ModifyPrincipal(context.Background(), opts.entry, opts.mask); err != nil {
		return err
	}
	e.info(fmt.Sprintf("Principal \"%s\" modified.\n", e.canonical(opts.entry.Principal)))
	return nil
}

func mergeEntry(old, next PrincipalEntry, mask int32) PrincipalEntry {
	out := old
	out.Principal = next.Principal
	if mask&kadm5.KADM5PrincExpireTime != 0 {
		out.Expiration = next.Expiration
	}
	if mask&kadm5.KADM5PWExpiration != 0 {
		out.PWExpiration = next.PWExpiration
	}
	if mask&kadm5.KADM5MaxLife != 0 {
		out.MaxLife = next.MaxLife
	}
	if mask&kadm5.KADM5MaxRenewableLife != 0 {
		out.MaxRenewableLife = next.MaxRenewableLife
	}
	if mask&kadm5.KADM5KVNO != 0 {
		out.KVNO = next.KVNO
	}
	if mask&kadm5.KADM5Policy != 0 {
		out.Policy = next.Policy
	}
	if mask&kadm5.KADM5Attributes != 0 {
		out.Attributes = next.Attributes
	}
	if mask&kadm5.KADM5FailAuthCount != 0 {
		out.FailAuthCount = next.FailAuthCount
	}
	return out
}

func (e *Engine) deletePrincipal(args []string) error {
	if err := e.requireOps(); err != nil {
		return err
	}
	force := false
	if len(args) == 3 && args[1] == "-force" {
		force = true
		args = []string{args[0], args[2]}
	}
	if len(args) != 2 {
		return errors.New("usage: delete_principal [-force] principal")
	}
	p, err := e.parsePrincipal(args[1])
	if err != nil {
		return err
	}
	name := e.canonical(p)
	if !force && !e.cfg.Script && !e.confirm(fmt.Sprintf("Are you sure you want to delete the principal \"%s\"? (yes/no): ", name)) {
		fmt.Fprintf(e.cfg.Stderr, "Principal \"%s\" not deleted\n", name)
		return nil
	}
	if err := e.cfg.Ops.DeletePrincipal(context.Background(), p); err != nil {
		return err
	}
	e.info(fmt.Sprintf("Principal \"%s\" deleted.\n", name))
	e.info("Make sure that you have removed this principal from all ACLs before reusing.\n")
	return nil
}

func (e *Engine) renamePrincipal(args []string) error {
	if err := e.requireOps(); err != nil {
		return err
	}
	force := false
	if len(args) == 4 && args[1] == "-force" {
		force = true
		args = []string{args[0], args[2], args[3]}
	}
	if len(args) != 3 {
		return errors.New("usage: rename_principal [-force] old new")
	}
	src, err := e.parsePrincipal(args[1])
	if err != nil {
		return err
	}
	dst, err := e.parsePrincipal(args[2])
	if err != nil {
		return err
	}
	if !force && !e.cfg.Script && !e.confirm(fmt.Sprintf("Are you sure you want to rename the principal \"%s\" to \"%s\"? (yes/no): ", e.canonical(src), e.canonical(dst))) {
		fmt.Fprintf(e.cfg.Stderr, "Principal \"%s\" not renamed\n", e.canonical(src))
		return nil
	}
	if err := e.cfg.Ops.RenamePrincipal(context.Background(), src, dst); err != nil {
		return err
	}
	e.info(fmt.Sprintf("Principal \"%s\" renamed to \"%s\".\n", e.canonical(src), e.canonical(dst)))
	e.info("Make sure that you have removed the old principal from all ACLs before reusing.\n")
	return nil
}

func (e *Engine) addAlias(args []string) error {
	if len(args) != 3 {
		return errors.New("usage: add_alias alias principal")
	}
	a, err := e.parsePrincipal(args[1])
	if err != nil {
		return err
	}
	p, err := e.parsePrincipal(args[2])
	if err != nil {
		return err
	}
	if err := e.cfg.Ops.AddAlias(context.Background(), a, p); err != nil {
		return err
	}
	e.info(fmt.Sprintf("Principal \"%s\" aliased to \"%s\".\n", e.canonical(a), e.canonical(p)))
	return nil
}

func (e *Engine) changePassword(args []string) error {
	if err := e.requireOps(); err != nil {
		return err
	}
	randkey, keepold := false, false
	password := ""
	var keySalts []kadm5.KeySaltTuple
	var rest []string
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "-randkey":
			randkey = true
		case "-keepold":
			keepold = true
		case "-pw":
			if i+1 >= len(args)-1 {
				return errors.New("-pw requires password")
			}
			i++
			password = args[i]
		case "-e":
			if i+1 >= len(args)-1 {
				return errors.New("-e requires keysalts")
			}
			i++
			parsed, err := parseKeySalts(args[i])
			if err != nil {
				return err
			}
			keySalts = parsed
		default:
			rest = append(rest, args[i])
		}
	}
	if len(rest) != 1 {
		return errors.New("usage: change_password [-randkey] [-keepold] principal")
	}
	p, err := e.parsePrincipal(rest[0])
	if err != nil {
		return err
	}
	if !randkey && password == "" {
		password, err = e.prompt(fmt.Sprintf("Enter password for principal \"%s\": ", e.canonical(p)))
		if err != nil {
			return err
		}
		again, err := e.prompt(fmt.Sprintf("Re-enter password for principal \"%s\": ", e.canonical(p)))
		if err != nil {
			return err
		}
		if password != again {
			return errors.New("passwords do not match")
		}
	}
	keys, err := e.cfg.Ops.ChangePassword(context.Background(), p, password, randkey, keepold, keySalts)
	if err != nil {
		return err
	}
	if randkey {
		e.info(fmt.Sprintf("Key for \"%s\" randomized.\n", e.canonical(p)))
	} else {
		e.info(fmt.Sprintf("Password for \"%s\" changed.\n", e.canonical(p)))
	}
	_ = keys
	return nil
}

func (e *Engine) getPrincipal(args []string) error {
	if err := e.requireOps(); err != nil {
		return err
	}
	terse := false
	if len(args) == 3 && args[1] == "-terse" {
		terse = true
		args = []string{args[0], args[2]}
	}
	if len(args) != 2 {
		return errors.New("usage: get_principal [-terse] principal")
	}
	p, err := e.parsePrincipal(args[1])
	if err != nil {
		return err
	}
	entry, err := e.cfg.Ops.GetPrincipal(context.Background(), p)
	if err != nil {
		return err
	}
	if terse {
		return e.printPrincipalTerse(entry)
	}
	fmt.Fprintf(e.cfg.Stdout, "Principal: %s\n", e.canonical(entry.Principal))
	fmt.Fprintf(e.cfg.Stdout, "Expiration date: %s\n", formatDate(entry.Expiration, e.cfg.Location))
	fmt.Fprintf(e.cfg.Stdout, "Last password change: %s\n", formatDate(entry.LastPwdChange, e.cfg.Location))
	fmt.Fprintf(e.cfg.Stdout, "Password expiration date: %s\n", formatDate(entry.PWExpiration, e.cfg.Location))
	fmt.Fprintf(e.cfg.Stdout, "Maximum ticket life: %s\n", formatDuration(entry.MaxLife))
	fmt.Fprintf(e.cfg.Stdout, "Maximum renewable life: %s\n", formatDuration(entry.MaxRenewableLife))
	fmt.Fprintf(e.cfg.Stdout, "Last modified: %s (%s)\n", formatDate(entry.LastModified, e.cfg.Location), e.canonical(entry.ModName))
	fmt.Fprintf(e.cfg.Stdout, "Last successful authentication: %s\n", formatDate(entry.LastSuccess, e.cfg.Location))
	fmt.Fprintf(e.cfg.Stdout, "Last failed authentication: %s\n", formatDate(entry.LastFailed, e.cfg.Location))
	fmt.Fprintf(e.cfg.Stdout, "Failed password attempts: %d\n", entry.FailAuthCount)
	fmt.Fprintf(e.cfg.Stdout, "Number of keys: %d\n", len(entry.Keys))
	for _, key := range entry.Keys {
		fmt.Fprintf(e.cfg.Stdout, "Key: vno %d, %s\n", key.KVNO, crypto.EnctypeName(key.Enctype))
	}
	fmt.Fprintf(e.cfg.Stdout, "MKey: vno %d\n", entry.MKVNO)
	fmt.Fprintf(e.cfg.Stdout, "Attributes:%s\n", formatFlags(entry.Attributes))
	policy := entry.Policy
	if policy == "" {
		policy = "[none]"
	} else if _, err := e.cfg.Ops.GetPolicy(context.Background(), policy); err != nil {
		policy += " [does not exist]"
	}
	fmt.Fprintf(e.cfg.Stdout, "Policy: %s\n", policy)
	return nil
}

func (e *Engine) printPrincipalTerse(entry PrincipalEntry) error {
	fmt.Fprintf(e.cfg.Stdout, "\"%s\"\t%d\t%d\t%d\t%d\t\"%s\"\t%d\t%d\t%d\t%d\t\"%s\"\t%d\t%d\t%d\t%d\t%d",
		e.canonical(entry.Principal), unix(entry.Expiration), unix(entry.LastPwdChange), unix(entry.PWExpiration),
		int64(entry.MaxLife/time.Second), e.canonical(entry.ModName), unix(entry.LastModified), entry.Attributes,
		entry.KVNO, entry.MKVNO, choosePolicy(entry.Policy), int64(entry.MaxRenewableLife/time.Second),
		unix(entry.LastSuccess), unix(entry.LastFailed), entry.FailAuthCount, len(entry.Keys))
	for _, key := range entry.Keys {
		fmt.Fprintf(e.cfg.Stdout, "\t%d\t%d", key.KVNO, key.Enctype)
	}
	fmt.Fprintln(e.cfg.Stdout)
	return nil
}

func unix(value time.Time) int64 {
	if value.IsZero() {
		return 0
	}
	return value.Unix()
}
func choosePolicy(value string) string {
	if value == "" {
		return "[none]"
	}
	return value
}

func formatFlags(flags uint32) string {
	names := []struct {
		name string
		bit  uint32
	}{{"DISALLOW_POSTDATED", flagDisallowPostdated}, {"DISALLOW_FORWARDABLE", flagDisallowForwardable}, {"DISALLOW_TGT_BASED", flagDisallowTGTBased}, {"DISALLOW_RENEWABLE", flagDisallowRenewable}, {"DISALLOW_PROXIABLE", flagDisallowProxiable}, {"DISALLOW_DUP_SKEY", flagDisallowDupSkey}, {"DISALLOW_ALL_TIX", flagDisallowAllTickets}, {"REQUIRES_PRE_AUTH", flagRequiresPreAuth}, {"REQUIRES_HW_AUTH", flagRequiresHWAuth}, {"REQUIRES_PWCHANGE", flagRequiresPWChange}, {"DISALLOW_SVR", flagDisallowServer}, {"PWCHANGE_SERVICE", flagPWChangeService}, {"OK_AS_DELEGATE", flagOKAsDelegate}, {"OK_TO_AUTH_AS_DELEGATE", flagOKToAuthAsDelegate}, {"NO_AUTH_DATA_REQUIRED", flagNoAuthDataRequired}, {"LOCKDOWN_KEYS", flagLockdownKeys}}
	var out []string
	for _, item := range names {
		if flags&item.bit != 0 {
			out = append(out, item.name)
		}
	}
	if len(out) == 0 {
		return ""
	}
	return " " + strings.Join(out, " ")
}

func (e *Engine) listPrincipals(args []string) error {
	expr := "*"
	if len(args) > 2 {
		return errors.New("usage: list_principals [expression]")
	}
	if len(args) == 2 {
		expr = args[1]
	}
	values, err := e.cfg.Ops.ListPrincipals(context.Background(), expr)
	if err != nil {
		return err
	}
	sort.Strings(values)
	for _, value := range values {
		if globMatch(expr, value) {
			fmt.Fprintln(e.cfg.Stdout, value)
		}
	}
	return nil
}

func (e *Engine) addPolicy(args []string, modify bool) error {
	if len(args) < 2 {
		return errors.New("usage: add_policy [options] policy")
	}
	policy := Policy{}
	mask := int32(0)
	for i := 1; i < len(args)-1; i++ {
		arg := args[i]
		if i+1 >= len(args)-1 {
			return fmt.Errorf("%s requires value", arg)
		}
		value := args[i+1]
		i++
		switch arg {
		case "-maxlife":
			parsed, err := ParseInterval(value, e.now(), e.cfg.Location)
			if err != nil {
				return err
			}
			policy.MaxLife = parsed
			mask |= kadm5.KADM5PWMaxLife
		case "-minlife":
			parsed, err := ParseInterval(value, e.now(), e.cfg.Location)
			if err != nil {
				return err
			}
			policy.MinLife = parsed
			mask |= kadm5.KADM5PWMinLife
		case "-minlength":
			n, err := parseInt(value)
			if err != nil {
				return err
			}
			policy.MinLength = n
			mask |= kadm5.KADM5PWMinLength
		case "-minclasses":
			n, err := parseInt(value)
			if err != nil {
				return err
			}
			policy.MinClasses = n
			mask |= kadm5.KADM5PWMinClasses
		case "-history":
			n, err := parseInt(value)
			if err != nil {
				return err
			}
			policy.HistoryNum = n
			mask |= kadm5.KADM5PWHistoryNum
		case "-maxfailure":
			n, err := strconv.ParseUint(value, 10, 32)
			if err != nil {
				return err
			}
			policy.MaxFailure = uint32(n)
			mask |= kadm5.KADM5PWMaxFailure
		case "-failurecountinterval":
			parsed, err := ParseInterval(value, e.now(), e.cfg.Location)
			if err != nil {
				return err
			}
			policy.FailureCountInterval = parsed
			mask |= kadm5.KADM5PWFailureCountInterval
		case "-lockoutduration":
			parsed, err := ParseInterval(value, e.now(), e.cfg.Location)
			if err != nil {
				return err
			}
			policy.LockoutDuration = parsed
			mask |= kadm5.KADM5PWLockoutDuration
		case "-allowedkeysalts":
			if value != "-" {
				policy.AllowedKeySalts = value
			}
			mask |= kadm5.KADM5PolicyAllowedKeysalts
		default:
			return fmt.Errorf("unknown policy option %q", arg)
		}
	}
	policy.Name = args[len(args)-1]
	var err error
	if modify {
		err = e.cfg.Ops.ModifyPolicy(context.Background(), policy, mask)
	} else {
		err = e.cfg.Ops.CreatePolicy(context.Background(), policy)
	}
	return err
}

func (e *Engine) deletePolicy(args []string) error {
	force := false
	if len(args) == 3 && args[1] == "-force" {
		force = true
		args = []string{args[0], args[2]}
	}
	if len(args) != 2 {
		return errors.New("usage: delete_policy [-force] policy")
	}
	if !force && !e.cfg.Script && !e.confirm(fmt.Sprintf("Are you sure you want to delete the policy \"%s\"? (yes/no): ", args[1])) {
		fmt.Fprintf(e.cfg.Stderr, "Policy \"%s\" not deleted.\n", args[1])
		return nil
	}
	return e.cfg.Ops.DeletePolicy(context.Background(), args[1])
}

func (e *Engine) getPolicy(args []string) error {
	terse := false
	if len(args) == 3 && args[1] == "-terse" {
		terse = true
		args = []string{args[0], args[2]}
	}
	if len(args) != 2 {
		return errors.New("usage: get_policy [-terse] policy")
	}
	p, err := e.cfg.Ops.GetPolicy(context.Background(), args[1])
	if err != nil {
		return err
	}
	if terse {
		allowed := p.AllowedKeySalts
		if allowed == "" {
			allowed = "-"
		}
		fmt.Fprintf(e.cfg.Stdout, "\"%s\"\t%d\t%d\t%d\t%d\t%d\t0\t%d\t%d\t%d\t%s\n", p.Name, int64(p.MaxLife/time.Second), int64(p.MinLife/time.Second), p.MinLength, p.MinClasses, p.HistoryNum, p.MaxFailure, int64(p.FailureCountInterval/time.Second), int64(p.LockoutDuration/time.Second), allowed)
		return nil
	}
	fmt.Fprintf(e.cfg.Stdout, "Policy: %s\nMaximum password life: %s\nMinimum password life: %s\nMinimum password length: %d\nMinimum number of password character classes: %d\nNumber of old keys kept: %d\nMaximum password failures before lockout: %d\nPassword failure count reset interval: %s\nPassword lockout duration: %s\n", p.Name, formatDuration(p.MaxLife), formatDuration(p.MinLife), p.MinLength, p.MinClasses, p.HistoryNum, p.MaxFailure, formatDuration(p.FailureCountInterval), formatDuration(p.LockoutDuration))
	if p.AllowedKeySalts != "" {
		fmt.Fprintf(e.cfg.Stdout, "Allowed key/salt types: %s\n", p.AllowedKeySalts)
	}
	return nil
}

func (e *Engine) listPolicies(args []string) error {
	expr := "*"
	if len(args) == 2 {
		expr = args[1]
	} else if len(args) > 2 {
		return errors.New("usage: list_policies [expression]")
	}
	values, err := e.cfg.Ops.ListPolicies(context.Background(), expr)
	if err != nil {
		return err
	}
	sort.Strings(values)
	for _, v := range values {
		if globMatch(expr, v) {
			fmt.Fprintln(e.cfg.Stdout, v)
		}
	}
	return nil
}
func (e *Engine) getPrivs() error {
	p, err := e.cfg.Ops.GetPrivs(context.Background())
	if err != nil {
		return err
	}
	names := []string{"INQUIRE", "ADD", "MODIFY", "DELETE"}
	fmt.Fprint(e.cfg.Stdout, "current privileges:")
	for i, n := range names {
		if p&(1<<i) != 0 {
			fmt.Fprint(e.cfg.Stdout, " ", n)
		}
	}
	fmt.Fprintln(e.cfg.Stdout)
	return nil
}
func (e *Engine) purgeKeys(args []string) error {
	keep := int32(-1)
	var name string
	if len(args) == 2 {
		name = args[1]
	} else if len(args) == 3 && args[1] == "-all" {
		keep = math.MaxInt32
		name = args[2]
	} else if len(args) == 4 && args[1] == "-keepkvno" {
		n, err := strconv.ParseInt(args[2], 10, 32)
		if err != nil {
			return err
		}
		keep = int32(n)
		name = args[3]
	} else {
		return errors.New("usage: purgekeys [-all|-keepkvno N] principal")
	}
	p, err := e.parsePrincipal(name)
	if err != nil {
		return err
	}
	if err = e.cfg.Ops.PurgeKeys(context.Background(), p, keep); err != nil {
		return err
	}
	if keep == math.MaxInt32 {
		e.info(fmt.Sprintf("All keys for principal \"%s\" removed.\n", e.canonical(p)))
	} else {
		e.info(fmt.Sprintf("Old keys for principal \"%s\" purged.\n", e.canonical(p)))
	}
	return nil
}
func (e *Engine) getStrings(args []string) error {
	if len(args) != 2 {
		return errors.New("usage: get_strings principal")
	}
	p, err := e.parsePrincipal(args[1])
	if err != nil {
		return err
	}
	m, err := e.cfg.Ops.GetStrings(context.Background(), p)
	if err != nil {
		return err
	}
	if len(m) == 0 {
		fmt.Fprintln(e.cfg.Stdout, "(No string attributes.)")
		return nil
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(e.cfg.Stdout, "%s: %s\n", k, m[k])
	}
	return nil
}
func (e *Engine) setString(args []string) error {
	if len(args) != 4 {
		return errors.New("usage: set_string principal key value")
	}
	p, err := e.parsePrincipal(args[1])
	if err != nil {
		return err
	}
	if err = e.cfg.Ops.SetString(context.Background(), p, args[2], &args[3]); err != nil {
		return err
	}
	e.info(fmt.Sprintf("Attribute set for principal \"%s\".\n", e.canonical(p)))
	return nil
}
func (e *Engine) delString(args []string) error {
	if len(args) != 3 {
		return errors.New("usage: del_string principal key")
	}
	p, err := e.parsePrincipal(args[1])
	if err != nil {
		return err
	}
	if err = e.cfg.Ops.SetString(context.Background(), p, args[2], nil); err != nil {
		return err
	}
	e.info(fmt.Sprintf("Attribute removed from principal \"%s\".\n", e.canonical(p)))
	return nil
}
func (e *Engine) lock() error {
	if !e.cfg.Local {
		return errors.New("lock: operation not supported over RPC")
	}
	return e.cfg.Ops.Lock(context.Background())
}
func (e *Engine) unlock() error {
	if !e.cfg.Local {
		return errors.New("unlock: operation not supported over RPC")
	}
	return e.cfg.Ops.Unlock(context.Background())
}
func (e *Engine) info(s string) {
	if !e.cfg.Script {
		fmt.Fprint(e.cfg.Stdout, s)
	}
}

func (e *Engine) ktadd(args []string) error {
	if err := e.requireOps(); err != nil {
		return err
	}
	name, rest, quiet, norand, keySalts, err := parseKTArgs(args)
	if err != nil {
		return err
	}
	if name == "" {
		name = os.Getenv("KRB5_KTNAME")
	}
	if name == "" {
		name = "/etc/krb5.keytab"
	}
	kt, err := loadKeytab(name)
	if err != nil {
		return err
	}
	for _, value := range rest {
		p, err := e.parsePrincipal(value)
		if err != nil {
			return err
		}
		var keys []Key
		if norand && e.cfg.Local {
			entry, err := e.cfg.Ops.GetPrincipal(context.Background(), p)
			if err != nil {
				return err
			}
			keys = entry.Keys
		} else {
			keys, err = e.cfg.Ops.RandomizeKeys(context.Background(), p, false, keySalts)
			if err != nil {
				return err
			}
		}
		entry, err := e.cfg.Ops.GetPrincipal(context.Background(), p)
		if err != nil {
			return err
		}
		for _, k := range keys {
			if k.KVNO == 0 {
				k.KVNO = entry.KVNO
			}
			if err := kt.AddEntry(keytab.Entry{Principal: p, Timestamp: e.now().Unix(), KVNO: k.KVNO, Enctype: k.Enctype, Key: k.Key}); err != nil {
				return err
			}
			if !quiet {
				fmt.Fprintf(e.cfg.Stdout, "Entry for principal %s with kvno %d, encryption type %s added to keytab %s.\n", e.canonical(p), k.KVNO, crypto.EnctypeName(k.Enctype), name)
			}
		}
	}
	if !strings.HasPrefix(name, "MEMORY:") {
		file, err := os.OpenFile(strings.TrimPrefix(name, "FILE:"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			return err
		}
		defer file.Close()
		if err := keytab.Write(file, kt); err != nil {
			return err
		}
	}
	return nil
}
func (e *Engine) ktremove(args []string) error {
	name, rest, quiet, _, _, err := parseKTArgs(args)
	if err != nil {
		return err
	}
	if len(rest) < 1 || len(rest) > 2 {
		return errors.New("usage: ktremove [-k keytab] principal [kvno|all|old]")
	}
	if name == "" {
		name = "/etc/krb5.keytab"
	}
	if !strings.HasPrefix(name, "MEMORY:") {
		if _, statErr := os.Stat(strings.TrimPrefix(name, "FILE:")); statErr != nil {
			return fmt.Errorf("Keytab %s does not exist", name)
		}
	}
	kt, err := loadKeytab(name)
	if err != nil {
		return err
	}
	p, err := e.parsePrincipal(rest[0])
	if err != nil {
		return err
	}
	selector := "highest"
	if len(rest) == 2 {
		selector = rest[1]
	}
	entries := kt.EntriesSnapshot()
	max := maxKVNO(kt, p)
	removed := 0
	for _, entry := range entries {
		if entry.Principal.String() != p.String() {
			continue
		}
		match := selector == "all" || selector == "highest" && entry.KVNO == max ||
			(selector == "old" && entry.KVNO != max) ||
			strconv.FormatUint(uint64(entry.KVNO), 10) == selector
		if match {
			if err := kt.RemoveEntry(entry); err != nil {
				return err
			}
			removed++
			if !quiet {
				fmt.Fprintf(e.cfg.Stdout, "Entry for principal %s with kvno %d removed from keytab %s.\n", rest[0], entry.KVNO, name)
			}
		}
	}
	if removed == 0 {
		if selector == "old" {
			fmt.Fprintf(e.cfg.Stderr, "There is only one entry for principal %s in keytab %s\n", rest[0], name)
		} else {
			return fmt.Errorf("no entry for principal %s with kvno %s exists in keytab %s", rest[0], selector, name)
		}
	}
	if !strings.HasPrefix(name, "MEMORY:") {
		file, err := os.OpenFile(strings.TrimPrefix(name, "FILE:"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			return err
		}
		defer file.Close()
		if err := keytab.Write(file, kt); err != nil {
			return err
		}
	}
	return nil
}

func loadKeytab(name string) (*keytab.Keytab, error) {
	kt, err := keytab.Resolve(name)
	if err == nil {
		return kt, nil
	}
	if strings.HasPrefix(name, "MEMORY:") {
		return nil, err
	}
	if os.IsNotExist(errors.Unwrap(err)) || os.IsNotExist(err) {
		return &keytab.Keytab{}, nil
	}
	return nil, err
}
func maxKVNO(kt *keytab.Keytab, p principal.Principal) uint32 {
	var max uint32
	for _, e := range kt.EntriesSnapshot() {
		if e.Principal.String() == p.String() && e.KVNO > max {
			max = e.KVNO
		}
	}
	return max
}
func parseKTArgs(args []string) (string, []string, bool, bool, []kadm5.KeySaltTuple, error) {
	name := ""
	quiet := false
	norand := false
	var keySalts []kadm5.KeySaltTuple
	rest := []string{}
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "-q":
			quiet = true
		case "-norandkey":
			norand = true
		case "-k", "-keytab":
			if i+1 >= len(args) {
				return "", nil, false, false, nil, errors.New("-k requires keytab")
			}
			i++
			name = args[i]
		default:
			if args[i] == "-e" {
				if i+1 >= len(args) {
					return "", nil, false, false, nil, errors.New("-e requires keysalts")
				}
				i++
				var err error
				keySalts, err = parseKeySalts(args[i])
				if err != nil {
					return "", nil, false, false, nil, err
				}
			} else {
				rest = append(rest, args[i])
			}
		}
	}
	return name, rest, quiet, norand, keySalts, nil
}
