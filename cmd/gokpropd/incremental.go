package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/Exonical/go-kerberos/krb5/client"
	"github.com/Exonical/go-kerberos/krb5/config"
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
}

func runIncremental(ctx context.Context, options propdOptions, cfg *config.Config,
	realm string, kt *keytab.Keytab, authorize func(principal.Principal) error,
	out, errOut io.Writer) error {
	if ctx == nil {
		ctx = context.Background()
	}
	adminHost, adminPort := ipropAdminAddress(cfg, realm, options.AdminServer)
	entries := kt.EntriesSnapshot()
	var entry keytab.Entry
	found := false
	clientPrincipal := principal.Principal{
		Realm: realm, NameType: principal.NTSrvHst,
		Components: []string{"kiprop", realm},
	}
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
	tgt, err := kclient.ASExchangeServiceWithKey(ctx, clientPrincipal, entry, tgtService)
	if err != nil {
		return fmt.Errorf("get iprop TGT: %w", err)
	}
	service := principal.Principal{
		Realm: realm, NameType: principal.NTSrvHst,
		Components: []string{"kiprop", adminHost},
	}
	credentials, err := kclient.TGSExchange(ctx, tgt, service)
	if err != nil {
		return fmt.Errorf("get iprop service ticket: %w", err)
	}
	ipropClient, err := iprop.Dial(ctx, net.JoinHostPort(adminHost, adminPort),
		credentials)
	if err != nil {
		return fmt.Errorf("connect to iprop master: %w", err)
	}
	defer ipropClient.Close()

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
		Cursor: cursor, Ulog: ulog}
	state := &incrementalState{replica: replica, ulog: ulog,
		fullResync: make(chan error, 1)}

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
			state.replica.Database = database
			state.fullResync <- nil
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
					select {
					case state.fullResync <- serveErr:
					default:
					}
				}
			}()
		}
	}()
	if options.Debug {
		fmt.Fprintf(errOut, "incremental iprop master %s:%s, polling every %s\n",
			adminHost, adminPort, poll)
	}

	backoff := 0
	for {
		status, pollErr := replica.Poll(ctx)
		if pollErr != nil {
			if options.RunOnce {
				return pollErr
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
			resyncCtx := ctx
			cancel := func() {}
			if resyncTimeout > 0 {
				resyncCtx, cancel = context.WithTimeout(ctx, resyncTimeout)
			}
			result, resyncErr := requestFullResync(resyncCtx, ipropClient)
			cancel()
			if resyncErr != nil {
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
				if options.RunOnce {
					return nil
				}
				backoff++
				if err := sleepIprop(ctx, ipropBackoff(&backoff)); err != nil {
					return err
				}
				continue
			case iprop.UpdatePermDenied, iprop.UpdateError:
				return fmt.Errorf("iprop full resync failed with status %d", result.Ret)
			default:
				return fmt.Errorf("iprop full resync returned status %d", result.Ret)
			}
			state.pendingLast = result.LastEntry
			select {
			case transferErr := <-state.fullResync:
				if transferErr != nil {
					return transferErr
				}
				if err := replica.SetCursor(state.pendingLast); err != nil {
					return err
				}
			case <-ctx.Done():
				return ctx.Err()
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
	if err := os.MkdirAll(filepathDir(path), 0o700); err != nil {
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
