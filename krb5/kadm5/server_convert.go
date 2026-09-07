package kadm5

import (
	"errors"
	"time"

	"github.com/Exonical/go-kerberos/krb5/kdb"
	"github.com/Exonical/go-kerberos/krb5/principal"
)

func readKeySaltTuples(r *xdrReader) ([]KeySaltTuple, error) {
	n, err := r.u32()
	if err != nil {
		return nil, err
	}
	if n > 1024 {
		return nil, errors.New("kadm5: oversized key-salt tuple array")
	}
	out := make([]KeySaltTuple, n)
	for i := range out {
		out[i].Enctype, err = r.i32()
		if err != nil {
			return nil, err
		}
		out[i].SaltType, err = r.i32()
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

func readKeyBlocks(r *xdrReader) ([]kdb.Key, error) {
	n, err := r.u32()
	if err != nil {
		return nil, err
	}
	if n > 1<<16 {
		return nil, errors.New("kadm5: oversized keyblock array")
	}
	out := make([]kdb.Key, n)
	for i := range out {
		out[i].Enctype, err = r.i32()
		if err != nil {
			return nil, err
		}
		out[i].Key, err = r.opaque()
		if err != nil {
			return nil, err
		}
		if len(out[i].Key) == 0 {
			return nil, errors.New("kadm5: empty keyblock")
		}
	}
	return out, nil
}

func toKDBKeySaltTuples(in []KeySaltTuple) []kdb.KeySaltTuple {
	out := make([]kdb.KeySaltTuple, len(in))
	for i, tuple := range in {
		out[i] = kdb.KeySaltTuple{Enctype: tuple.Enctype, SaltType: tuple.SaltType}
	}
	return out
}

func kdbCode(err error) uint32 {
	if err == nil {
		return 0
	}
	switch {
	case errors.Is(err, kdb.ErrPrincipalExists):
		return 43787527
	case errors.Is(err, kdb.ErrPrincipalNotFound):
		return 43787534
	case errors.Is(err, kdb.ErrPolicyExists):
		return 43787527
	case errors.Is(err, kdb.ErrPolicyNotFound):
		return 43787533
	case errors.Is(err, kdb.ErrPolicyInUse):
		return 43787547
	case errors.Is(err, kdb.ErrPasswordTooShort):
		return passTooShort
	case errors.Is(err, kdb.ErrPasswordClasses):
		return passClass
	case errors.Is(err, kdb.ErrPasswordReuse):
		return passReuse
	case errors.Is(err, kdb.ErrPasswordTooSoon):
		return passTooSoon
	case qualityCode(err) != 0:
		return qualityCode(err)
	case errors.Is(err, kdb.ErrBadKeySalts):
		return 43787578
	default:
		return 43787548
	}
}

func formatPrincipal(p principal.Principal) string {
	s, _ := p.Format()
	return s
}

func recordEntry(r kdb.PrincipalRecord) PrincipalEntry {
	expire, pwExpire := int32(0), int32(0)
	if !r.Expiration.IsZero() {
		expire = int32(r.Expiration.Unix())
	}
	if !r.PasswordExpiration.IsZero() {
		pwExpire = int32(r.PasswordExpiration.Unix())
	}
	return PrincipalEntry{
		Principal: r.Name, PrincExpireTime: expire,
		LastPwdChange: unixSeconds(r.LastPasswordChange), PWExpiration: pwExpire,
		MaxLife: int32(r.MaxLife / time.Second), Attributes: int32(r.Flags),
		KVNO: r.KVNO, Policy: r.Policy, MaxRenewableLife: int32(r.MaxRenew / time.Second),
	}
}

func applyEntry(r *kdb.PrincipalRecord, e PrincipalEntry, mask int32) {
	if mask&KADM5Attributes != 0 {
		r.Flags = uint32(e.Attributes)
	}
	if mask&KADM5PrincExpireTime != 0 {
		r.Expiration = unixTime(e.PrincExpireTime)
	}
	if mask&KADM5LastPwdChange != 0 {
		r.LastPasswordChange = unixTime(e.LastPwdChange)
	}
	if mask&KADM5PWExpiration != 0 {
		r.PasswordExpiration = unixTime(e.PWExpiration)
	}
	if mask&KADM5MaxLife != 0 {
		r.MaxLife = time.Duration(e.MaxLife) * time.Second
	}
	if mask&KADM5MaxRenewableLife != 0 {
		r.MaxRenew = time.Duration(e.MaxRenewableLife) * time.Second
	}
	if mask&KADM5Policy != 0 {
		if mask&KADM5PolicyClear != 0 {
			r.Policy = ""
		} else {
			r.Policy = e.Policy
		}
	}
}

func unixTime(value int32) time.Time {
	if value == 0 {
		return time.Time{}
	}
	return time.Unix(int64(value), 0).UTC()
}

func unixSeconds(value time.Time) int32 {
	if value.IsZero() {
		return 0
	}
	return int32(value.Unix())
}

func policyRecord(p Policy) kdb.PolicyRecord {
	return kdb.PolicyRecord{Name: p.Name, MinLife: p.MinLife, MaxLife: p.MaxLife, MinLength: p.MinLength,
		MinClasses: p.MinClasses, HistoryNum: p.HistoryNum, MaxFailure: p.MaxFailure,
		FailureCountInterval: p.FailureCountInterval, LockoutDuration: p.LockoutDuration,
		Attributes: p.Attributes, MaxTicketLife: p.MaxTicketLife, MaxRenewableLife: p.MaxRenewableLife,
		AllowedKeySalts: p.AllowedKeySalts}
}

func policyValue(p kdb.PolicyRecord) Policy {
	return Policy{Name: p.Name, MinLife: p.MinLife, MaxLife: p.MaxLife, MinLength: p.MinLength,
		MinClasses: p.MinClasses, HistoryNum: p.HistoryNum, MaxFailure: p.MaxFailure,
		FailureCountInterval: p.FailureCountInterval, LockoutDuration: p.LockoutDuration,
		Attributes: p.Attributes, MaxTicketLife: p.MaxTicketLife, MaxRenewableLife: p.MaxRenewableLife,
		AllowedKeySalts: p.AllowedKeySalts}
}

func applyPolicy(dst *kdb.PolicyRecord, src kdb.PolicyRecord, mask int32) {
	if mask&KADM5PWMinLife != 0 {
		dst.MinLife = src.MinLife
	}
	if mask&KADM5PWMaxLife != 0 {
		dst.MaxLife = src.MaxLife
	}
	if mask&KADM5PWMinLength != 0 {
		dst.MinLength = src.MinLength
	}
	if mask&KADM5PWMinClasses != 0 {
		dst.MinClasses = src.MinClasses
	}
	if mask&KADM5PWHistoryNum != 0 {
		dst.HistoryNum = src.HistoryNum
	}
	if mask&KADM5PWMaxFailure != 0 {
		dst.MaxFailure = src.MaxFailure
	}
	if mask&KADM5PWFailureCountInterval != 0 {
		dst.FailureCountInterval = src.FailureCountInterval
	}
	if mask&KADM5PWLockoutDuration != 0 {
		dst.LockoutDuration = src.LockoutDuration
	}
	if mask&KADM5PolicyAttributes != 0 {
		dst.Attributes = src.Attributes
	}
	if mask&KADM5PolicyMaxLife != 0 {
		dst.MaxTicketLife = src.MaxTicketLife
	}
	if mask&KADM5PolicyMaxRenewableLife != 0 {
		dst.MaxRenewableLife = src.MaxRenewableLife
	}
	if mask&KADM5PolicyAllowedKeysalts != 0 {
		dst.AllowedKeySalts = src.AllowedKeySalts
	}
}

func validPolicyMask(mask int32, api uint32) bool {
	allowed := KADM5PWMaxLife | KADM5PWMinLife | KADM5PWMinLength |
		KADM5PWMinClasses | KADM5PWHistoryNum | KADM5RefCount
	if api >= APIv3 {
		allowed |= KADM5PWMaxFailure | KADM5PWFailureCountInterval |
			KADM5PWLockoutDuration
	}
	if api >= APIv4 {
		allowed |= KADM5PolicyAttributes | KADM5PolicyMaxLife |
			KADM5PolicyMaxRenewableLife | KADM5PolicyAllowedKeysalts |
			KADM5PolicyTLData
	}
	return mask&KADM5Policy == 0 && mask&^allowed == 0
}

func validateModifiedPolicy(policy kdb.PolicyRecord, mask int32) bool {
	if mask&KADM5PWMinLife != 0 && policy.MinLife < 0 {
		return false
	}
	if mask&KADM5PWMaxLife != 0 && policy.MaxLife < 0 {
		return false
	}
	if policy.MaxLife != 0 && policy.MinLife > policy.MaxLife {
		return false
	}
	if mask&KADM5PWMinLength != 0 && policy.MinLength < 1 {
		return false
	}
	if mask&KADM5PWMinClasses != 0 && (policy.MinClasses < 1 || policy.MinClasses > 5) {
		return false
	}
	if mask&KADM5PWHistoryNum != 0 && policy.HistoryNum < 1 {
		return false
	}
	if mask&KADM5PWFailureCountInterval != 0 && policy.FailureCountInterval < 0 {
		return false
	}
	if mask&KADM5PWLockoutDuration != 0 && policy.LockoutDuration < 0 {
		return false
	}
	return true
}
