package kadmin

import (
	"context"
	"fmt"
	"time"

	"github.com/Exonical/go-kerberos/krb5/kadm5"
	"github.com/Exonical/go-kerberos/krb5/kdb"
	"github.com/Exonical/go-kerberos/krb5/principal"
)

// Remote adapts a kadm5 RPC client.
type Remote struct {
	Client    *kadm5.Client
	RealmName string
}

// NewRemote returns a remote operation adapter.
func NewRemote(client *kadm5.Client, realm string) *Remote {
	return &Remote{Client: client, RealmName: realm}
}
func (r *Remote) Realm() string {
	if r.RealmName != "" {
		return r.RealmName
	}
	return ""
}
func (r *Remote) GetPrincipal(ctx context.Context, p principal.Principal) (PrincipalEntry, error) {
	e, err := r.Client.GetPrincipal(ctx, p)
	if err != nil {
		return PrincipalEntry{}, err
	}
	out := remoteEntry(e)
	keys, err := r.Client.GetPrincipalKeys(ctx, p, 0)
	if err == nil {
		for _, k := range keys {
			out.Keys = append(out.Keys, Key{KVNO: k.KVNO, Enctype: k.Enctype, Key: k.Key})
		}
	}
	return out, nil
}
func remoteEntry(e kadm5.PrincipalEntry) PrincipalEntry {
	return PrincipalEntry{Principal: e.Principal, Expiration: unixTime(e.PrincExpireTime), LastPwdChange: unixTime(e.LastPwdChange), PWExpiration: unixTime(e.PWExpiration), MaxLife: time.Duration(e.MaxLife) * time.Second, MaxRenewableLife: time.Duration(e.MaxRenewableLife) * time.Second, LastSuccess: unixTime(e.LastSuccess), LastFailed: unixTime(e.LastFailed), FailAuthCount: e.FailAuthCount, KVNO: e.KVNO, MKVNO: e.MKVNO, Attributes: uint32(e.Attributes), Policy: e.Policy}
}
func unixTime(value int32) time.Time {
	if value == 0 {
		return time.Time{}
	}
	return time.Unix(int64(value), 0)
}
func remoteKadmEntry(e PrincipalEntry) kadm5.PrincipalEntry {
	return kadm5.PrincipalEntry{Principal: e.Principal, PrincExpireTime: int32(unix(e.Expiration)), PWExpiration: int32(unix(e.PWExpiration)), MaxLife: int32(e.MaxLife / time.Second), MaxRenewableLife: int32(e.MaxRenewableLife / time.Second), Attributes: int32(e.Attributes), KVNO: e.KVNO, MKVNO: e.MKVNO, Policy: e.Policy, LastSuccess: int32(unix(e.LastSuccess)), LastFailed: int32(unix(e.LastFailed)), FailAuthCount: e.FailAuthCount}
}
func (r *Remote) CreatePrincipal(ctx context.Context, e PrincipalEntry, password string, randkey, nokey bool, tuples []kadm5.KeySaltTuple) error {
	mask := kadm5.KADM5Principal
	if e.Policy != "" {
		mask |= kadm5.KADM5Policy
	}
	if e.Attributes != 0 {
		mask |= kadm5.KADM5Attributes
	}
	if e.Expiration.IsZero() == false {
		mask |= kadm5.KADM5PrincExpireTime
	}
	if e.PWExpiration.IsZero() == false {
		mask |= kadm5.KADM5PWExpiration
	}
	if e.MaxLife != 0 {
		mask |= kadm5.KADM5MaxLife
	}
	if e.MaxRenewableLife != 0 {
		mask |= kadm5.KADM5MaxRenewableLife
	}
	if e.KVNO != 0 {
		mask |= kadm5.KADM5KVNO
	}
	if nokey {
		password = ""
	}
	_ = randkey
	return r.Client.CreatePrincipal3(ctx, remoteKadmEntry(e), mask, tuples, password)
}
func (r *Remote) ModifyPrincipal(ctx context.Context, e PrincipalEntry, mask int32) error {
	return r.Client.ModifyPrincipal(ctx, remoteKadmEntry(e), mask)
}
func (r *Remote) DeletePrincipal(ctx context.Context, p principal.Principal) error {
	return r.Client.DeletePrincipal(ctx, p)
}
func (r *Remote) RenamePrincipal(ctx context.Context, a, b principal.Principal) error {
	return r.Client.RenamePrincipal(ctx, a, b)
}
func (r *Remote) AddAlias(ctx context.Context, a, b principal.Principal) error {
	return r.Client.CreateAlias(ctx, a, b)
}
func (r *Remote) ChangePassword(ctx context.Context, p principal.Principal, password string, randkey, keepold bool, t []kadm5.KeySaltTuple) ([]Key, error) {
	if randkey {
		return r.RandomizeKeys(ctx, p, keepold, t)
	}
	if err := r.Client.ChangePassword(ctx, p, password); err != nil {
		return nil, err
	}
	return nil, nil
}
func (r *Remote) RandomizeKeys(ctx context.Context, p principal.Principal, keepold bool, t []kadm5.KeySaltTuple) ([]Key, error) {
	var ks []kadm5.Key
	var err error
	if len(t) > 0 || keepold {
		ks, err = r.Client.RandKey3(ctx, p, keepold, t)
	} else {
		ks, err = r.Client.RandKey(ctx, p)
	}
	out := make([]Key, len(ks))
	for i, k := range ks {
		out[i] = Key{Enctype: k.Enctype, Key: k.Key}
	}
	return out, err
}
func (r *Remote) PurgeKeys(ctx context.Context, p principal.Principal, k int32) error {
	return r.Client.PurgeKeys(ctx, p, k)
}
func (r *Remote) ListPrincipals(ctx context.Context, e string) ([]string, error) {
	return r.Client.ListPrincipals(ctx, e)
}
func remotePolicy(p kadm5.Policy) Policy {
	return Policy{Name: p.Name, MinLife: time.Duration(p.MinLife) * time.Second, MaxLife: time.Duration(p.MaxLife) * time.Second, MinLength: p.MinLength, MinClasses: p.MinClasses, HistoryNum: p.HistoryNum, MaxFailure: p.MaxFailure, FailureCountInterval: time.Duration(p.FailureCountInterval) * time.Second, LockoutDuration: time.Duration(p.LockoutDuration) * time.Second, AllowedKeySalts: p.AllowedKeySalts}
}
func kadmPolicy(p Policy) kadm5.Policy {
	return kadm5.Policy{Name: p.Name, MinLife: int32(p.MinLife / time.Second), MaxLife: int32(p.MaxLife / time.Second), MinLength: p.MinLength, MinClasses: p.MinClasses, HistoryNum: p.HistoryNum, MaxFailure: p.MaxFailure, FailureCountInterval: int32(p.FailureCountInterval / time.Second), LockoutDuration: int32(p.LockoutDuration / time.Second), AllowedKeySalts: p.AllowedKeySalts}
}
func (r *Remote) CreatePolicy(ctx context.Context, p Policy) error {
	return r.Client.CreatePolicy(ctx, kadmPolicy(p), 0)
}
func (r *Remote) ModifyPolicy(ctx context.Context, p Policy, m int32) error {
	return r.Client.ModifyPolicy(ctx, kadmPolicy(p), m)
}
func (r *Remote) DeletePolicy(ctx context.Context, n string) error {
	return r.Client.DeletePolicy(ctx, n)
}
func (r *Remote) GetPolicy(ctx context.Context, n string) (Policy, error) {
	p, e := r.Client.GetPolicy(ctx, n)
	return remotePolicy(p), e
}
func (r *Remote) ListPolicies(ctx context.Context, e string) ([]string, error) {
	return r.Client.ListPolicies(ctx, e)
}
func (r *Remote) GetPrivs(ctx context.Context) (int32, error) { return r.Client.GetPrivs(ctx) }
func (r *Remote) GetStrings(ctx context.Context, p principal.Principal) (map[string]string, error) {
	a, e := r.Client.GetStrings(ctx, p)
	if e != nil {
		return nil, e
	}
	out := map[string]string{}
	for _, v := range a {
		out[v.Key] = v.Value
	}
	return out, nil
}
func (r *Remote) SetString(ctx context.Context, p principal.Principal, k string, v *string) error {
	return r.Client.SetString(ctx, p, k, v)
}
func (r *Remote) Lock(context.Context) error {
	return fmt.Errorf("lock: operation not supported over RPC")
}
func (r *Remote) Unlock(context.Context) error {
	return fmt.Errorf("unlock: operation not supported over RPC")
}

// Local adapts the mutable KDB backend used by kadmind and gokadmin.local.
type Local struct {
	Backend   kadm5.Backend
	RealmName string
}

// NewLocal returns a local operation adapter.
func NewLocal(backend kadm5.Backend) *Local {
	realm := ""
	if backend != nil {
		realm = backend.GetRealm()
	}
	return &Local{Backend: backend, RealmName: realm}
}
func (l *Local) Realm() string { return l.RealmName }
func (l *Local) GetPrincipal(_ context.Context, p principal.Principal) (PrincipalEntry, error) {
	r, ok, e := l.Backend.Lookup(p)
	if e != nil {
		return PrincipalEntry{}, e
	}
	if !ok {
		return PrincipalEntry{}, kdb.ErrPrincipalNotFound
	}
	return kdbEntry(r), nil
}
func kdbEntry(r kdb.PrincipalRecord) PrincipalEntry {
	out := PrincipalEntry{Principal: r.Name, Expiration: r.Expiration, LastPwdChange: r.LastPasswordChange, PWExpiration: r.PasswordExpiration, MaxLife: r.MaxLife, MaxRenewableLife: r.MaxRenew, LastSuccess: r.LastSuccess, LastFailed: r.LastFailed, FailAuthCount: r.FailAuthCount, KVNO: r.KVNO, Attributes: r.Flags, Policy: r.Policy, Strings: r.Strings}
	for _, k := range r.Keys {
		out.Keys = append(out.Keys, Key{KVNO: k.KVNO, Enctype: k.Enctype, Key: k.Key, Salt: k.Salt})
	}
	return out
}
func (l *Local) CreatePrincipal(_ context.Context, e PrincipalEntry, password string, randkey, nokey bool, t []kadm5.KeySaltTuple) error {
	var policy *kdb.PolicyRecord
	if e.Policy != "" {
		p, err := l.Backend.GetPolicy(e.Policy)
		if err != nil {
			return err
		}
		policy = &p
	}
	var err error
	if len(t) > 0 {
		tuples := make([]kdb.KeySaltTuple, len(t))
		for i, v := range t {
			tuples[i] = kdb.KeySaltTuple{Enctype: v.Enctype, SaltType: v.SaltType}
		}
		err = l.Backend.CreatePrincipalWithKeySaltsAndOptions(e.Principal.String(), password, tuples, policy)
	} else {
		err = l.Backend.CreatePrincipalWithOptions(e.Principal.String(), password, policy)
	}
	if err != nil {
		return err
	}
	if r, ok, lookupErr := l.Backend.Lookup(e.Principal); lookupErr == nil && ok {
		if !e.Expiration.IsZero() {
			r.Expiration = e.Expiration
		}
		if !e.PWExpiration.IsZero() {
			r.PasswordExpiration = e.PWExpiration
		}
		if e.MaxLife != 0 {
			r.MaxLife = e.MaxLife
		}
		if e.MaxRenewableLife != 0 {
			r.MaxRenew = e.MaxRenewableLife
		}
		if e.KVNO != 0 {
			r.KVNO = e.KVNO
		}
		r.Flags = e.Attributes
		r.Policy = e.Policy
		if updateErr := l.Backend.UpdatePrincipal(r); updateErr != nil {
			return updateErr
		}
	}
	if nokey {
		r, ok, _ := l.Backend.Lookup(e.Principal)
		if ok {
			r.Keys = nil
			_ = l.Backend.UpdatePrincipal(r)
		}
	}
	if randkey {
		_, err = l.RandomizeKeys(context.Background(), e.Principal, false, nil)
	}
	return err
}
func (l *Local) ModifyPrincipal(_ context.Context, e PrincipalEntry, m int32) error {
	r, ok, err := l.Backend.Lookup(e.Principal)
	if err != nil {
		return err
	}
	if !ok {
		return kdb.ErrPrincipalNotFound
	}
	if m&kadm5.KADM5PrincExpireTime != 0 {
		r.Expiration = e.Expiration
	}
	if m&kadm5.KADM5PWExpiration != 0 {
		r.PasswordExpiration = e.PWExpiration
	}
	if m&kadm5.KADM5MaxLife != 0 {
		r.MaxLife = e.MaxLife
	}
	if m&kadm5.KADM5MaxRenewableLife != 0 {
		r.MaxRenew = e.MaxRenewableLife
	}
	if m&kadm5.KADM5KVNO != 0 {
		r.KVNO = e.KVNO
	}
	if m&kadm5.KADM5Policy != 0 {
		r.Policy = e.Policy
	}
	if m&kadm5.KADM5Attributes != 0 {
		r.Flags = e.Attributes
	}
	if m&kadm5.KADM5FailAuthCount != 0 {
		r.FailAuthCount = e.FailAuthCount
	}
	return l.Backend.UpdatePrincipal(r)
}
func (l *Local) DeletePrincipal(_ context.Context, p principal.Principal) error {
	return l.Backend.DeletePrincipal(p)
}
func (l *Local) RenamePrincipal(_ context.Context, a, b principal.Principal) error {
	return l.Backend.RenamePrincipal(a, b)
}
func (l *Local) AddAlias(_ context.Context, a, b principal.Principal) error {
	return l.Backend.AddAlias(a.String(), b.String())
}
func (l *Local) ChangePassword(ctx context.Context, p principal.Principal, password string, randkey, keepold bool, t []kadm5.KeySaltTuple) ([]Key, error) {
	if randkey {
		return l.RandomizeKeys(ctx, p, keepold, t)
	}
	if err := l.Backend.ChangePasswordWithPolicyAndKeepOld(p, password, time.Now(), nil, keepold, false); err != nil {
		return nil, err
	}
	return nil, nil
}
func (l *Local) RandomizeKeys(_ context.Context, p principal.Principal, keepold bool, t []kadm5.KeySaltTuple) ([]Key, error) {
	var ks []kdb.Key
	var err error
	if len(t) > 0 {
		tt := make([]kdb.KeySaltTuple, len(t))
		for i, v := range t {
			tt[i] = kdb.KeySaltTuple{Enctype: v.Enctype, SaltType: v.SaltType}
		}
		ks, err = l.Backend.RandomizeKeysWithKeySalts(p, keepold, tt)
	} else if keepold {
		ks, err = l.Backend.RandomizeKeysWithKeySalts(p, true, nil)
	} else {
		ks, err = l.Backend.RandomizeKeys(p)
	}
	out := make([]Key, len(ks))
	for i, k := range ks {
		out[i] = Key{KVNO: k.KVNO, Enctype: k.Enctype, Key: k.Key, Salt: k.Salt}
	}
	return out, err
}
func (l *Local) PurgeKeys(_ context.Context, p principal.Principal, k int32) error {
	return l.Backend.PurgeKeys(p, k)
}
func (l *Local) ListPrincipals(context.Context, string) ([]string, error) {
	return l.Backend.ListPrincipals(), nil
}
func (l *Local) CreatePolicy(_ context.Context, p Policy) error {
	return l.Backend.CreatePolicy(kdbPolicy(p))
}
func (l *Local) ModifyPolicy(_ context.Context, p Policy, _ int32) error {
	return l.Backend.UpdatePolicy(kdbPolicy(p))
}
func (l *Local) DeletePolicy(_ context.Context, n string) error { return l.Backend.DeletePolicy(n) }
func (l *Local) GetPolicy(_ context.Context, n string) (Policy, error) {
	p, e := l.Backend.GetPolicy(n)
	return policyFromKDB(p), e
}
func policyFromKDB(p kdb.PolicyRecord) Policy {
	return Policy{Name: p.Name, MinLife: time.Duration(p.MinLife) * time.Second, MaxLife: time.Duration(p.MaxLife) * time.Second, MinLength: p.MinLength, MinClasses: p.MinClasses, HistoryNum: p.HistoryNum, MaxFailure: p.MaxFailure, FailureCountInterval: time.Duration(p.FailureCountInterval) * time.Second, LockoutDuration: time.Duration(p.LockoutDuration) * time.Second, AllowedKeySalts: p.AllowedKeySalts}
}
func kdbPolicy(p Policy) kdb.PolicyRecord {
	return kdb.PolicyRecord{Name: p.Name, MinLife: int32(p.MinLife / time.Second), MaxLife: int32(p.MaxLife / time.Second), MinLength: p.MinLength, MinClasses: p.MinClasses, HistoryNum: p.HistoryNum, MaxFailure: p.MaxFailure, FailureCountInterval: int32(p.FailureCountInterval / time.Second), LockoutDuration: int32(p.LockoutDuration / time.Second), AllowedKeySalts: p.AllowedKeySalts}
}
func (l *Local) ListPolicies(context.Context, string) ([]string, error) {
	return l.Backend.ListPolicies(), nil
}
func (l *Local) GetPrivs(context.Context) (int32, error) { return 0xf, nil }
func (l *Local) GetStrings(_ context.Context, p principal.Principal) (map[string]string, error) {
	return l.Backend.GetStrings(p)
}
func (l *Local) SetString(_ context.Context, p principal.Principal, k string, v *string) error {
	return l.Backend.SetString(p, k, v)
}
func (l *Local) Lock(context.Context) error   { return nil }
func (l *Local) Unlock(context.Context) error { return nil }
