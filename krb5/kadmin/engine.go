// Package kadmin implements the command engine shared by gokadmin and
// gokadmin.local.
package kadmin

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/Exonical/go-kerberos/krb5/kadm5"
	"github.com/Exonical/go-kerberos/krb5/kdb"
	"github.com/Exonical/go-kerberos/krb5/principal"
	"golang.org/x/term"
)

const (
	flagDisallowPostdated   = kdb.DisallowPostdated
	flagDisallowForwardable = kdb.DisallowForwardable
	flagDisallowTGTBased    = kdb.DisallowTGTBased
	flagDisallowRenewable   = kdb.DisallowRenewable
	flagDisallowProxiable   = kdb.DisallowProxiable
	flagDisallowDupSkey     = kdb.DisallowDupSkey
	flagDisallowAllTickets  = kdb.DisallowAllTickets
	flagRequiresPreAuth     = kdb.RequiresPreAuth
	flagRequiresHWAuth      = kdb.RequiresHWAuth
	flagRequiresPWChange    = kdb.RequiresPWChange
	flagDisallowServer      = kdb.DisallowServer
	flagPWChangeService     = kdb.PWChangeService
	flagOKAsDelegate        = 1 << 16
	flagOKToAuthAsDelegate  = 1 << 17
	flagNoAuthDataRequired  = 1 << 18
	flagLockdownKeys        = 1 << 19
)

// Key is a keytab-compatible principal key.
type Key struct {
	KVNO    uint32
	Enctype int32
	Key     []byte
	Salt    string
}

// PrincipalEntry is the common display and mutation model.
type PrincipalEntry struct {
	Principal        principal.Principal
	Expiration       time.Time
	LastPwdChange    time.Time
	PWExpiration     time.Time
	MaxLife          time.Duration
	MaxRenewableLife time.Duration
	LastModified     time.Time
	ModName          principal.Principal
	LastSuccess      time.Time
	LastFailed       time.Time
	FailAuthCount    uint32
	KVNO             uint32
	MKVNO            uint32
	Attributes       uint32
	Policy           string
	PolicyClear      bool
	Keys             []Key
	Strings          map[string]string
}

// Policy is the common policy model.
type Policy struct {
	Name                 string
	MinLife              time.Duration
	MaxLife              time.Duration
	MinLength            int32
	MinClasses           int32
	HistoryNum           int32
	MaxFailure           uint32
	FailureCountInterval time.Duration
	LockoutDuration      time.Duration
	AllowedKeySalts      string
}

// Operations contains the operations used by the command engine.
type Operations interface {
	Realm() string
	GetPrincipal(context.Context, principal.Principal) (PrincipalEntry, error)
	CreatePrincipal(context.Context, PrincipalEntry, string, bool, bool, []kadm5.KeySaltTuple) error
	ModifyPrincipal(context.Context, PrincipalEntry, int32) error
	DeletePrincipal(context.Context, principal.Principal) error
	RenamePrincipal(context.Context, principal.Principal, principal.Principal) error
	AddAlias(context.Context, principal.Principal, principal.Principal) error
	ChangePassword(context.Context, principal.Principal, string, bool, bool, []kadm5.KeySaltTuple) ([]Key, error)
	RandomizeKeys(context.Context, principal.Principal, bool, []kadm5.KeySaltTuple) ([]Key, error)
	PurgeKeys(context.Context, principal.Principal, int32) error
	ListPrincipals(context.Context, string) ([]string, error)
	CreatePolicy(context.Context, Policy) error
	ModifyPolicy(context.Context, Policy, int32) error
	DeletePolicy(context.Context, string) error
	GetPolicy(context.Context, string) (Policy, error)
	ListPolicies(context.Context, string) ([]string, error)
	GetPrivs(context.Context) (int32, error)
	GetStrings(context.Context, principal.Principal) (map[string]string, error)
	SetString(context.Context, principal.Principal, string, *string) error
	Lock(context.Context) error
	Unlock(context.Context) error
}

// Config controls an Engine.
type Config struct {
	Ops             Operations
	Local           bool
	Realm           string
	DefaultKeySalts string
	Now             func() time.Time
	Location        *time.Location
	Stdin           io.Reader
	Stdout          io.Writer
	Stderr          io.Writer
	Password        string
	Script          bool
	AfterMutation   func() error
}

// Engine executes kadmin commands.
type Engine struct {
	cfg Config
	now func() time.Time
	in  *bufio.Reader
}

// New returns a command engine.
func New(cfg Config) *Engine {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Location == nil {
		cfg.Location = time.Local
	}
	if cfg.Stdin == nil {
		cfg.Stdin = strings.NewReader("")
	}
	if cfg.Stdout == nil {
		cfg.Stdout = io.Discard
	}
	if cfg.Stderr == nil {
		cfg.Stderr = io.Discard
	}
	if cfg.Realm == "" && cfg.Ops != nil {
		cfg.Realm = cfg.Ops.Realm()
	}
	return &Engine{cfg: cfg, now: cfg.Now, in: bufio.NewReader(cfg.Stdin)}
}

// Execute runs one command line. It returns whether the command requested exit.
func (e *Engine) Execute(line string) (bool, error) {
	args, err := splitCommand(line)
	if err != nil {
		return false, err
	}
	if len(args) == 0 {
		return false, nil
	}
	exit, err := e.executeArgs(args)
	if err == nil && e.cfg.AfterMutation != nil && isMutatingCommand(args[0]) {
		err = e.cfg.AfterMutation()
	}
	return exit, err
}

func (e *Engine) executeArgs(args []string) (bool, error) {
	switch strings.ToLower(args[0]) {
	case "quit", "exit", "q":
		return true, nil
	case "list_requests", "lr", "?":
		e.help()
		return false, nil
	case "add_principal", "addprinc", "ank":
		return false, e.addPrincipal(args)
	case "modify_principal", "modprinc":
		return false, e.modifyPrincipal(args)
	case "delete_principal", "delprinc":
		return false, e.deletePrincipal(args)
	case "rename_principal", "renprinc":
		return false, e.renamePrincipal(args)
	case "add_alias", "alias":
		return false, e.addAlias(args)
	case "change_password", "cpw":
		return false, e.changePassword(args)
	case "get_principal", "getprinc":
		return false, e.getPrincipal(args)
	case "list_principals", "listprincs", "get_principals", "getprincs":
		return false, e.listPrincipals(args)
	case "add_policy", "addpol":
		return false, e.addPolicy(args, false)
	case "modify_policy", "modpol":
		return false, e.addPolicy(args, true)
	case "delete_policy", "delpol":
		return false, e.deletePolicy(args)
	case "get_policy", "getpol":
		return false, e.getPolicy(args)
	case "get_policies", "getpols", "list_policies", "listpols":
		return false, e.listPolicies(args)
	case "get_privs", "getprivs":
		return false, e.getPrivs()
	case "purgekeys":
		return false, e.purgeKeys(args)
	case "get_strings", "getstrs":
		return false, e.getStrings(args)
	case "set_string", "setstr":
		return false, e.setString(args)
	case "del_string", "delstr":
		return false, e.delString(args)
	case "lock":
		return false, e.lock()
	case "unlock":
		return false, e.unlock()
	case "ktadd", "xst":
		return false, e.ktadd(args)
	case "ktremove", "ktrem":
		return false, e.ktremove(args)
	default:
		return false, fmt.Errorf("unknown request \"%s\"", args[0])
	}
}

func isMutatingCommand(name string) bool {
	switch strings.ToLower(name) {
	case "add_principal", "addprinc", "ank", "modify_principal", "modprinc",
		"delete_principal", "delprinc", "rename_principal", "renprinc",
		"add_alias", "alias", "change_password", "cpw", "add_policy", "addpol",
		"modify_policy", "modpol", "delete_policy", "delpol", "purgekeys",
		"set_string", "setstr", "del_string", "delstr", "lock", "unlock",
		"ktadd", "xst", "ktremove", "ktrem":
		return true
	default:
		return false
	}
}

// RunInteractive executes query, script, or interactive mode.
func (e *Engine) RunInteractive(query string, args []string, prompt string) error {
	if query != "" {
		e.cfg.Script = false
		_, err := e.Execute(query)
		return err
	}
	if len(args) != 0 {
		e.cfg.Script = true
		_, err := e.Execute(strings.Join(args, " "))
		return err
	}
	for {
		fmt.Fprint(e.cfg.Stdout, prompt)
		line, err := e.in.ReadString('\n')
		if err != nil && err != io.EOF {
			return err
		}
		if len(line) == 0 {
			break
		}
		exit, err := e.Execute(strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r"))
		if err != nil {
			fmt.Fprintln(e.cfg.Stderr, err)
		}
		if exit {
			break
		}
		if err == io.EOF {
			break
		}
	}
	return nil
}

func splitCommand(line string) ([]string, error) {
	var out []string
	var b strings.Builder
	quote := rune(0)
	escaped := false
	for _, r := range line {
		if escaped {
			b.WriteRune(r)
			escaped = false
			continue
		}
		if r == '\\' {
			escaped = true
			continue
		}
		if quote != 0 {
			if r == quote {
				quote = 0
			} else {
				b.WriteRune(r)
			}
			continue
		}
		if r == '\'' || r == '"' {
			quote = r
		} else if r == ' ' || r == '\t' || r == '\r' || r == '\n' {
			if b.Len() != 0 {
				out = append(out, b.String())
				b.Reset()
			}
		} else {
			b.WriteRune(r)
		}
	}
	if escaped || quote != 0 {
		return nil, errors.New("unterminated quote or escape")
	}
	if b.Len() != 0 {
		out = append(out, b.String())
	}
	return out, nil
}

func (e *Engine) parsePrincipal(value string) (principal.Principal, error) {
	if !hasUnescapedRealm(value) {
		if e.cfg.Realm == "" {
			return principal.Principal{}, errors.New("principal has no realm and no default realm")
		}
		value += "@" + e.cfg.Realm
	}
	p, err := principal.Parse(value)
	if err != nil {
		return principal.Principal{}, fmt.Errorf("parsing principal: %w", err)
	}
	return *p, nil
}

func hasUnescapedRealm(value string) bool {
	escaped := false
	for _, r := range value {
		if escaped {
			escaped = false
		} else if r == '\\' {
			escaped = true
		} else if r == '@' {
			return true
		}
	}
	return false
}

// ParseDate parses the supported absolute kadmin date forms.
func ParseDate(value string, now time.Time, loc *time.Location) (time.Time, error) {
	if strings.EqualFold(value, "never") {
		return time.Time{}, nil
	}
	if loc == nil {
		loc = time.Local
	}
	for _, layout := range []string{"2006-01-02 15:04:05", "2006-01-02"} {
		if parsed, err := time.ParseInLocation(layout, value, loc); err == nil {
			return parsed, nil
		}
	}
	if parsed, err := time.Parse(time.RFC3339, value); err == nil {
		return parsed.In(loc), nil
	}
	return time.Time{}, fmt.Errorf("invalid date specification %q", value)
}

// ParseInterval parses a MIT-style duration or absolute future date.
func ParseInterval(value string, now time.Time, loc *time.Location) (time.Duration, error) {
	if value == "-" || strings.EqualFold(value, "never") {
		return 0, nil
	}
	if d, err := parseDeltat(value); err == nil {
		return d, nil
	}
	date, err := ParseDate(value, now, loc)
	if err != nil {
		return 0, err
	}
	if date.IsZero() {
		return 0, nil
	}
	if date.Before(now) {
		return 0, fmt.Errorf("interval specification %q is in the past", value)
	}
	return date.Sub(now), nil
}

func parseDeltat(value string) (time.Duration, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, errors.New("empty interval")
	}
	if d, err := time.ParseDuration(value); err == nil {
		return d, nil
	}
	var days, hours, mins, secs int64
	if _, err := fmt.Sscanf(value, "%dd %dh %dm %ds", &days, &hours, &mins, &secs); err == nil {
		return time.Duration(days)*24*time.Hour + time.Duration(hours)*time.Hour +
			time.Duration(mins)*time.Minute + time.Duration(secs)*time.Second, nil
	}
	if _, err := fmt.Sscanf(value, "%dd %02d:%02d:%02d", &days, &hours, &mins, &secs); err == nil {
		return time.Duration(days)*24*time.Hour + time.Duration(hours)*time.Hour +
			time.Duration(mins)*time.Minute + time.Duration(secs)*time.Second, nil
	}
	return 0, errors.New("invalid interval")
}

func parseInt(value string) (int32, error) {
	n, err := strconv.ParseInt(value, 10, 32)
	return int32(n), err
}

type principalOptions struct {
	entry                PrincipalEntry
	mask                 int32
	password             string
	randkey              bool
	nokey                bool
	keepOld              bool
	keySalts             []kadm5.KeySaltTuple
	attrsSet, attrsClear uint32
}

func (e *Engine) parsePrincipalOptions(args []string, mod bool) (principalOptions, error) {
	if len(args) < 2 {
		return principalOptions{}, errors.New("principal is required")
	}
	out := principalOptions{}
	out.entry.Attributes = 0
	for i := 1; i < len(args)-1; i++ {
		arg := args[i]
		next := func() (string, error) {
			if i+1 >= len(args)-1 {
				return "", fmt.Errorf("%s requires a value", arg)
			}
			i++
			return args[i], nil
		}
		switch arg {
		case "-expire":
			v, err := next()
			if err != nil {
				return out, err
			}
			out.entry.Expiration, err = ParseDate(v, e.now(), e.cfg.Location)
			if err != nil {
				return out, err
			}
			out.mask |= kadm5.KADM5PrincExpireTime
		case "-pwexpire":
			v, err := next()
			if err != nil {
				return out, err
			}
			out.entry.PWExpiration, err = ParseDate(v, e.now(), e.cfg.Location)
			if err != nil {
				return out, err
			}
			out.mask |= kadm5.KADM5PWExpiration
		case "-maxlife":
			v, err := next()
			if err != nil {
				return out, err
			}
			out.entry.MaxLife, err = ParseInterval(v, e.now(), e.cfg.Location)
			if err != nil {
				return out, err
			}
			out.mask |= kadm5.KADM5MaxLife
		case "-maxrenewlife":
			v, err := next()
			if err != nil {
				return out, err
			}
			out.entry.MaxRenewableLife, err = ParseInterval(v, e.now(), e.cfg.Location)
			if err != nil {
				return out, err
			}
			out.mask |= kadm5.KADM5MaxRenewableLife
		case "-kvno":
			v, err := next()
			if err != nil {
				return out, err
			}
			n, err := strconv.ParseUint(v, 10, 32)
			if err != nil {
				return out, err
			}
			out.entry.KVNO = uint32(n)
			out.mask |= kadm5.KADM5KVNO
		case "-policy":
			v, err := next()
			if err != nil {
				return out, err
			}
			out.entry.Policy = v
			out.mask |= kadm5.KADM5Policy
		case "-clearpolicy":
			out.entry.Policy = ""
			out.entry.PolicyClear = true
			out.mask |= kadm5.KADM5PolicyClear
		case "-pw":
			if mod {
				return out, errors.New("modify_principal does not support -pw")
			}
			v, err := next()
			if err != nil {
				return out, err
			}
			out.password = v
		case "-randkey":
			if mod {
				return out, errors.New("modify_principal does not support -randkey")
			}
			out.randkey = true
		case "-nokey":
			if mod {
				return out, errors.New("modify_principal does not support -nokey")
			}
			out.nokey = true
		case "-unlock":
			if !mod {
				return out, errors.New("-unlock is only valid for modify_principal")
			}
			out.entry.FailAuthCount = 0
			out.mask |= kadm5.KADM5FailAuthCount
		case "-e":
			if mod {
				return out, errors.New("modify_principal does not support -e")
			}
			value, err := next()
			if err != nil {
				return out, err
			}
			out.keySalts, err = parseKeySalts(value)
			if err != nil {
				return out, err
			}
		default:
			if strings.HasPrefix(arg, "+") || strings.HasPrefix(arg, "-") {
				flag, set, err := parseFlagSpec(arg)
				if err != nil {
					return out, err
				}
				if set {
					out.entry.Attributes |= flag
					out.attrsSet |= flag
				} else {
					out.entry.Attributes &^= flag
					out.attrsClear |= flag
				}
				out.mask |= kadm5.KADM5Attributes
			} else {
				return out, fmt.Errorf("unexpected argument %q", arg)
			}
		}
	}
	if len(out.keySalts) == 0 && !mod && e.cfg.DefaultKeySalts != "" {
		var err error
		out.keySalts, err = parseKeySalts(e.cfg.DefaultKeySalts)
		if err != nil {
			return out, err
		}
	}
	out.entry.Principal, _ = e.parsePrincipal(args[len(args)-1])
	if out.entry.Principal.Realm == "" {
		return out, errors.New("invalid principal")
	}
	return out, nil
}

func parseKeySalts(value string) ([]kadm5.KeySaltTuple, error) {
	var out []kadm5.KeySaltTuple
	for _, item := range strings.Split(value, ",") {
		parts := strings.SplitN(item, ":", 2)
		enctype, err := strconv.ParseInt(parts[0], 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid key/salt type %q", item)
		}
		tuple := kadm5.KeySaltTuple{Enctype: int32(enctype)}
		if len(parts) == 2 {
			salt, err := strconv.ParseInt(parts[1], 10, 32)
			if err != nil {
				return nil, fmt.Errorf("invalid salt type %q", item)
			}
			tuple.SaltType = int32(salt)
		}
		out = append(out, tuple)
	}
	return out, nil
}

func parseFlagSpec(value string) (uint32, bool, error) {
	set := value[0] == '+'
	name := value[1:]
	flags := map[string]uint32{
		"allow_postdated": flagDisallowPostdated, "allow_forwardable": flagDisallowForwardable,
		"allow_tgs_req": flagDisallowTGTBased, "allow_renewable": flagDisallowRenewable,
		"allow_proxiable": flagDisallowProxiable, "allow_dup_skey": flagDisallowDupSkey,
		"allow_tix": flagDisallowAllTickets, "requires_preauth": flagRequiresPreAuth,
		"requires_hwauth": flagRequiresHWAuth, "needchange": flagRequiresPWChange,
		"allow_svr": flagDisallowServer, "password_changing_service": flagPWChangeService,
		"ok_as_delegate": flagOKAsDelegate, "ok_to_auth_as_delegate": flagOKToAuthAsDelegate,
		"no_auth_data_required": flagNoAuthDataRequired, "lockdown_keys": flagLockdownKeys,
	}
	flag, ok := flags[name]
	if !ok {
		return 0, false, fmt.Errorf("unknown principal flag %q", name)
	}
	// "allow_*" flags are represented by a disallow bit.
	if strings.HasPrefix(name, "allow_") {
		set = !set
	}
	return flag, set, nil
}

func (e *Engine) prompt(prompt string) (string, error) {
	fmt.Fprint(e.cfg.Stderr, prompt)
	if file, ok := e.cfg.Stdin.(*os.File); ok && term.IsTerminal(int(file.Fd())) {
		value, err := term.ReadPassword(int(file.Fd()))
		fmt.Fprintln(e.cfg.Stderr)
		if err != nil {
			return "", err
		}
		return string(value), nil
	}
	value, err := e.in.ReadString('\n')
	if err != nil && err != io.EOF {
		return "", err
	}
	return strings.TrimSuffix(strings.TrimSuffix(value, "\n"), "\r"), nil
}

func (e *Engine) confirm(prompt string) bool {
	value, err := e.prompt(prompt)
	return err == nil && strings.TrimSpace(value) == "yes"
}

func (e *Engine) help() {
	fmt.Fprintln(e.cfg.Stdout, "Available requests: addprinc delprinc modprinc renprinc cpw getprinc listprincs addpol modpol delpol getpol listpols getprivs ktadd ktremove purgekeys getstrs setstr delstr quit")
}

func formatDate(value time.Time, loc *time.Location) string {
	if value.IsZero() {
		return "[never]"
	}
	return value.In(loc).Format("Mon Jan _2 15:04:05 MST 2006")
}

func formatDuration(value time.Duration) string {
	if value < 0 {
		value = 0
	}
	days := value / (24 * time.Hour)
	value %= 24 * time.Hour
	h := value / time.Hour
	value %= time.Hour
	m := value / time.Minute
	value %= time.Minute
	s := value / time.Second
	word := "days"
	if days == 1 {
		word = "day"
	}
	return fmt.Sprintf("%d %s %02d:%02d:%02d", days, word, h, m, s)
}

func (e *Engine) canonical(p principal.Principal) string {
	if value, err := p.Format(); err == nil {
		return value
	}
	return p.String()
}

func globMatch(pattern, value string) bool {
	if pattern == "" || pattern == "*" {
		return true
	}
	ok, err := path.Match(pattern, value)
	return err == nil && ok
}

func keytabName(args []string) (string, []string, bool, error) {
	name := ""
	quiet := false
	norand := false
	rest := make([]string, 0)
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "-q":
			quiet = true
		case "-norandkey":
			norand = true
		case "-k", "-keytab":
			if i+1 >= len(args) {
				return "", nil, false, errors.New("-k requires a keytab")
			}
			i++
			name = args[i]
		case "-e":
			if i+1 >= len(args) {
				return "", nil, false, errors.New("-e requires keysalts")
			}
			i++
		default:
			rest = append(rest, args[i])
		}
	}
	return name, rest, quiet || norand, nil
}
