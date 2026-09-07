package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/Exonical/go-kerberos/krb5/client"
	"github.com/Exonical/go-kerberos/krb5/config"
	"github.com/Exonical/go-kerberos/krb5/hostrealm"
	"github.com/Exonical/go-kerberos/krb5/iprop"
	"github.com/Exonical/go-kerberos/krb5/kdb"
	"github.com/Exonical/go-kerberos/krb5/kdb/mitdump"
	"github.com/Exonical/go-kerberos/krb5/keytab"
	"github.com/Exonical/go-kerberos/krb5/kprop"
	"github.com/Exonical/go-kerberos/krb5/principal"
)

const (
	defaultIpropPort = 2121
	defaultIpropPoll = 10 * time.Second
	maxIpropBackoff  = 5 * time.Minute
)

type incrementalState struct {
	replica     *iprop.Replica
	ulog        *iprop.Ulog
	fullResync  chan error
	pendingLast iprop.Last
	mu          sync.Mutex
	pending     bool
}

func runIncremental(ctx context.Context, options propdOptions, cfg *config.Config,
	realm string, kt *keytab.Keytab, authorize func(principal.Principal, int32) error,
	out, errOut io.Writer) error {
	if ctx == nil {
		ctx = context.Background()
	}
	stashPath, stash, err := loadIncrementalMasterKey(realm, options)
	if err != nil {
		return err
	}
	adminHost, adminPort := ipropAdminAddress(cfg, realm, options.AdminServer)
	entries := kt.EntriesSnapshot()
	clientPrincipal, err := localIpropPrincipal(ctx, cfg, realm)
	if err != nil {
		return err
	}
	var entry keytab.Entry
	found := false
	for _, candidate := range entries {
		if candidate.Principal.String() == clientPrincipal.String() {
			entry, found = candidate, true
			break
		}
	}
	if !found {
		return fmt.Errorf("keytab contains no client principal for realm %s", realm)
	}
	kclient := &client.Client{Config: cfg}
	tgtService := principal.Principal{
		Realm: realm, NameType: principal.NTSrvInstance,
		Components: []string{"krbtgt", realm},
	}
	service := principal.Principal{
		Realm: realm, NameType: principal.NTSrvHst,
		Components: []string{"kiprop", adminHost},
	}
	dialIprop := func(dialCtx context.Context) (*iprop.Client, error) {
		tgt, dialErr := kclient.ASExchangeServiceWithKey(dialCtx, clientPrincipal, entry, tgtService)
		if dialErr != nil {
			return nil, fmt.Errorf("get iprop TGT: %w", dialErr)
		}
		credentials, dialErr := kclient.TGSExchange(dialCtx, tgt, service)
		if dialErr != nil {
			return nil, fmt.Errorf("get iprop service ticket: %w", dialErr)
		}
		ipropClient, dialErr := iprop.Dial(dialCtx, net.JoinHostPort(adminHost, adminPort), credentials)
		if dialErr != nil {
			return nil, fmt.Errorf("connect to iprop master: %w", dialErr)
		}
		return ipropClient, nil
	}
	ipropClient, err := dialIprop(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = ipropClient.Close() }()

	ulogPath, poll, ulogSize, resyncTimeout, err := ipropSettings(cfg, realm, options)
	if err != nil {
		return err
	}
	ulog, cursor, err := openReplicaUlog(ulogPath, ulogSize)
	if err != nil {
		return err
	}
	defer ulog.Close()
	replica := &iprop.Replica{Client: ipropClient, Database: kdb.NewDatabase(realm),
		Cursor: cursor, Ulog: ulog, MasterEnctype: stash.Enctype,
		MasterKey: append([]byte(nil), stash.Key...)}
	state := &incrementalState{replica: replica, ulog: ulog,
		fullResync: make(chan error, 1)}
	replica.Persist = func() error {
		database := replica.Database
		data, err := mitdump.DumpWithMasterKey(database,
			replica.MasterEnctype, replica.MasterKey)
		if err != nil {
			return err
		}
		if options.KDBUtil == "" {
			return writeFileAtomic(options.Database, data)
		}
		if err := writeFileAtomic(options.ReplicaFile, data); err != nil {
			return err
		}
		args := buildLoadArgs(options)
		command := exec.Command(options.KDBUtil, args...) // nosemgrep: tmp.opengrep-rules.go.lang.security.audit.dangerous-exec-command -- -p intentionally selects an administrator-configured kdb5_util-compatible loader
		if output, err := command.CombinedOutput(); err != nil {
			return fmt.Errorf("%s load: %w: %s", options.KDBUtil, err,
				strings.TrimSpace(string(output)))
		}
		return nil
	}

	listener, err := net.Listen("tcp", net.JoinHostPort("", options.Port))
	if err != nil {
		return fmt.Errorf("listen on port %s: %w", options.Port, err)
	}
	defer listener.Close()
	kpropServer := &kprop.Server{
		Keytab: kt, Realm: realm, Authorize: authorize,
		Load: func(reader io.Reader, size uint64) error {
			if err := loadReceivedDump(reader, size, options); err != nil {
				return err
			}
			data, err := os.ReadFile(options.ReplicaFile)
			if err != nil {
				return err
			}
			store, err := mitdump.Parse(data)
			if err != nil {
				return err
			}
			database := kdb.NewDatabase(realm)
			for _, record := range store.Records() {
				if err := database.ImportPrincipal(record); err != nil {
					return err
				}
			}
			state.mu.Lock()
			state.replica.Database = database
			pending := state.pending
			state.mu.Unlock()
			if pending {
				state.fullResync <- nil
			}
			return nil
		},
		ErrorLog: func(err error) {
			if options.Debug {
				fmt.Fprintln(errOut, err)
			}
		},
	}
	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go func() {
				if serveErr := kpropServer.ServeConn(ctx, conn); serveErr != nil {
					state.mu.Lock()
					pending := state.pending
					state.mu.Unlock()
					var classified *kprop.ServeConnError
					if errors.As(serveErr, &classified) && !classified.Authenticated {
						if options.Debug {
							fmt.Fprintln(errOut, serveErr)
						}
						return
					}
					if pending {
						select {
						case state.fullResync <- serveErr:
						default:
						}
					} else if options.Debug {
						fmt.Fprintln(errOut, serveErr)
					}
				}
			}()
		}
	}()
	if options.Debug {
		fmt.Fprintf(errOut, "incremental iprop master %s:%s, polling every %s, master-key stash %s\n",
			adminHost, adminPort, poll, stashPath)
	}

	backoff := 0
	for {
		state.mu.Lock()
		status, pollErr := replica.Poll(ctx)
		state.mu.Unlock()
		if pollErr != nil {
			if options.RunOnce {
				return pollErr
			}
			_ = ipropClient.Close()
			ipropClient, err = dialIprop(ctx)
			if err == nil {
				replica.Client = ipropClient
			}
			if err := sleepIprop(ctx, ipropBackoff(&backoff)); err != nil {
				return err
			}
			continue
		}
		switch status {
		case iprop.UpdateOK:
			backoff = 0
			if options.RunOnce {
				return nil
			}
			if err := sleepIprop(ctx, poll); err != nil {
				return err
			}
		case iprop.UpdateNil:
			backoff = 0
			if options.RunOnce {
				return nil
			}
			if err := sleepIprop(ctx, poll); err != nil {
				return err
			}
		case iprop.UpdateBusy:
			if options.RunOnce {
				return nil
			}
			backoff++
			if err := sleepIprop(ctx, ipropBackoff(&backoff)); err != nil {
				return err
			}
		case iprop.UpdateFullResyncNeeded:
			backoff = 0
			state.mu.Lock()
			state.pending = true
			state.mu.Unlock()
			select {
			case <-state.fullResync:
			default:
			}
			rpcCtx, cancelRPC := context.WithTimeout(ctx, 25*time.Second)
			result, resyncErr := requestFullResync(rpcCtx, ipropClient)
			cancelRPC()
			if resyncErr != nil {
				state.mu.Lock()
				state.pending = false
				state.mu.Unlock()
				_ = ipropClient.Close()
				ipropClient, err = dialIprop(ctx)
				if err == nil {
					replica.Client = ipropClient
				}
				if options.RunOnce {
					return resyncErr
				}
				backoff++
				if err := sleepIprop(ctx, ipropBackoff(&backoff)); err != nil {
					return err
				}
				continue
			}
			switch result.Ret {
			case iprop.UpdateOK:
			case iprop.UpdateBusy:
				state.mu.Lock()
				state.pending = false
				state.mu.Unlock()
				if options.RunOnce {
					return nil
				}
				backoff++
				if err := sleepIprop(ctx, ipropBackoff(&backoff)); err != nil {
					return err
				}
				continue
			case iprop.UpdatePermDenied, iprop.UpdateError:
				state.mu.Lock()
				state.pending = false
				state.mu.Unlock()
				return fmt.Errorf("iprop full resync failed with status %d", result.Ret)
			default:
				state.mu.Lock()
				state.pending = false
				state.mu.Unlock()
				return fmt.Errorf("iprop full resync returned status %d", result.Ret)
			}
			state.pendingLast = result.LastEntry
			waitCtx := ctx
			cancelWait := func() {}
			if resyncTimeout > 0 {
				waitCtx, cancelWait = context.WithTimeout(ctx, resyncTimeout)
			}
			select {
			case transferErr := <-state.fullResync:
				cancelWait()
				state.mu.Lock()
				state.pending = false
				state.mu.Unlock()
				if transferErr != nil {
					return transferErr
				}
				if err := replica.SetCursor(state.pendingLast); err != nil {
					return err
				}
			case <-waitCtx.Done():
				cancelWait()
				state.mu.Lock()
				state.pending = false
				state.mu.Unlock()
				if options.Debug {
					fmt.Fprintln(errOut, "iprop full resync dump timed out")
				}
				continue
			}
			if options.RunOnce {
				return nil
			}
		case iprop.UpdatePermDenied, iprop.UpdateError:
			return fmt.Errorf("iprop update failed with status %d", status)
		default:
			return fmt.Errorf("iprop unknown update status %d", status)
		}
	}
}

func localIpropPrincipal(ctx context.Context, cfg *config.Config,
	realm string) (principal.Principal, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return principal.Principal{}, fmt.Errorf("get local hostname: %w", err)
	}
	return localIpropPrincipalForHost(ctx, cfg, realm, hostname)
}

func localIpropPrincipalForHost(ctx context.Context, cfg *config.Config,
	realm, hostname string) (principal.Principal, error) {
	p := principal.Principal{
		Realm: realm, NameType: principal.NTSrvHst,
		Components: []string{"kiprop", hostname},
	}
	var err error
	p, err = hostrealm.CanonicalizePrincipal(ctx, cfg, p, hostrealm.Options{})
	if err != nil {
		return principal.Principal{}, fmt.Errorf("canonicalize local hostname: %w", err)
	}
	return p, nil
}

func requestFullResync(ctx context.Context, c *iprop.Client) (iprop.FullResyncResult, error) {
	result, err := c.FullResyncExt(ctx, 1)
	if err == nil {
		return result, nil
	}
	// MIT falls back only when the extension procedure is unavailable. The
	// Go RPC client exposes that condition as a rejected procedure call.
	if strings.Contains(err.Error(), "RPC call failed") ||
		strings.Contains(err.Error(), "RPC call rejected") {
		return c.FullResync(ctx)
	}
	return iprop.FullResyncResult{}, err
}

func openReplicaUlog(path string, size int) (*iprop.Ulog, iprop.Last, error) {
	if path == "" {
		return nil, iprop.Last{}, errors.New("iprop ulog path is empty")
	}
	if _, err := os.Stat(path); err == nil {
		ulog, openErr := iprop.Open(path)
		if openErr != nil {
			return nil, iprop.Last{}, openErr
		}
		last, lastErr := ulog.Last()
		if lastErr != nil {
			ulog.Close()
			return nil, iprop.Last{}, lastErr
		}
		if last.LastSno == 1 && last.LastTime == (iprop.Time{}) {
			last = iprop.Last{}
		}
		return ulog, last, nil
	} else if !os.IsNotExist(err) {
		return nil, iprop.Last{}, err
	}
	if err := os.MkdirAll(filepathDir(path), 0o700); err != nil { // nosemgrep: tmp.opengrep-rules.go.lang.correctness.permissions.incorrect-default-permission -- 0700 directory is intentionally restrictive
		return nil, iprop.Last{}, err
	}
	if size <= 0 {
		size = 1000
	}
	ulog, err := iprop.Create(path, uint32(size))
	if err != nil {
		return nil, iprop.Last{}, err
	}
	return ulog, iprop.Last{}, nil
}

func ipropSettings(cfg *config.Config, realm string, options propdOptions) (string, time.Duration, int, time.Duration, error) {
	poll := defaultIpropPoll
	ulogSize := 1000
	resyncTimeout := 5 * time.Minute
	ulogPath := options.ReplicaFile + ".ulog"
	if path := os.Getenv("KRB5_KDC_PROFILE"); path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return "", 0, 0, 0, err
		}
		profile, err := config.ParseKDCConf(data)
		if err != nil {
			return "", 0, 0, 0, err
		}
		if settings, ok := profile.Realm(realm); ok {
			if settings.IpropPollTime > 0 {
				poll = settings.IpropPollTime
			}
			if settings.IpropUlogSize > 0 {
				ulogSize = settings.IpropUlogSize
			}
			if settings.IpropResyncTimeout > 0 {
				resyncTimeout = settings.IpropResyncTimeout
			}
			if settings.IpropLogfile != "" {
				ulogPath = settings.IpropLogfile
			}
		}
	}
	return ulogPath, poll, ulogSize, resyncTimeout, nil
}

func loadIncrementalMasterKey(realm string, options propdOptions) (string, mitdump.StashKey, error) {
	path := strings.TrimSpace(options.Stash)
	if path == "" {
		path = defaultIncrementalStashPath(realm)
	}
	stash, err := mitdump.ReadStash(path, realm)
	if err != nil {
		return path, mitdump.StashKey{}, fmt.Errorf(
			"incremental iprop requires the master key stash %s: %w", path, err)
	}
	return path, stash, nil
}

func defaultIncrementalStashPath(realm string) string {
	const defaultKeyFileStub = "/var/lib/krb5kdc/.k5."
	path := os.Getenv("KRB5_KDC_PROFILE")
	if path == "" {
		path = "/etc/krb5kdc/kdc.conf"
	}
	if data, err := os.ReadFile(path); err == nil {
		if profile, err := config.ParseKDCConf(data); err == nil {
			values := profile.Defaults
			if settings, ok := profile.Realm(realm); ok {
				values = settings.Values
			}
			if stash := strings.TrimSpace(strings.Join(values["key_stash_file"], " ")); stash != "" {
				return stash
			}
		}
	}
	return defaultKeyFileStub + realm
}

func profileIpropEnabled(realm string) bool {
	path := os.Getenv("KRB5_KDC_PROFILE")
	if path == "" {
		return false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	profile, err := config.ParseKDCConf(data)
	if err != nil {
		return false
	}
	settings, ok := profile.Realm(realm)
	return ok && settings.IpropEnabled
}

func ipropAdminAddress(cfg *config.Config, realm, configured string) (string, string) {
	host := strings.TrimSpace(configured)
	if host == "" && cfg != nil {
		for name, values := range cfg.RealmOptions {
			if strings.EqualFold(name, realm) {
				for key, candidates := range values {
					if strings.EqualFold(key, "admin_server") && len(candidates) > 0 {
						host = strings.TrimSpace(candidates[0])
						break
					}
				}
			}
		}
	}
	if host == "" {
		host = "localhost"
	}
	if h, p, err := net.SplitHostPort(host); err == nil {
		return h, p
	}
	if path := os.Getenv("KRB5_KDC_PROFILE"); path != "" {
		if data, err := os.ReadFile(path); err == nil {
			if profile, err := config.ParseKDCConf(data); err == nil {
				if settings, ok := profile.Realm(realm); ok && settings.IpropPort > 0 {
					return host, fmt.Sprintf("%d", settings.IpropPort)
				}
			}
		}
	}
	return host, fmt.Sprintf("%d", defaultIpropPort)
}

func ipropBackoff(count *int) time.Duration {
	if *count < 0 {
		*count = 0
	}
	seconds := 2 << min(*count, 7)
	if seconds > int(maxIpropBackoff/time.Second) {
		seconds = int(maxIpropBackoff / time.Second)
		if *count > 0 {
			(*count)--
		}
	}
	return time.Duration(seconds) * time.Second
}

func sleepIprop(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func filepathDir(path string) string {
	if index := strings.LastIndexByte(path, os.PathSeparator); index >= 0 {
		if index == 0 {
			return string(os.PathSeparator)
		}
		return path[:index]
	}
	return "."
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
