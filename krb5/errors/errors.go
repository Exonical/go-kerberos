package errors

import (
	stderrors "errors"
	"fmt"
	"time"
)

var (
	// ErrNotImplemented identifies behavior that is intentionally deferred.
	ErrNotImplemented = stderrors.New("kerberos: not implemented")
	// ErrIntegrity identifies a failed Kerberos integrity check.
	ErrIntegrity = stderrors.New("kerberos integrity check failed")
	// ErrReplay identifies a replayed authenticated message.
	ErrReplay = stderrors.New("kerberos replay detected")
	// ErrClockSkew identifies a timestamp outside the permitted clock skew.
	ErrClockSkew = stderrors.New("kerberos clock skew")
	// ErrTicketExpired identifies an expired ticket.
	ErrTicketExpired = stderrors.New("kerberos ticket expired")
	// ErrTicketNotYetValid identifies a ticket that is not yet valid.
	ErrTicketNotYetValid = stderrors.New("kerberos ticket not yet valid")
	// ErrTicketInvalid identifies a ticket carrying TKT_FLG_INVALID.
	ErrTicketInvalid = stderrors.New("kerberos ticket invalid")
	// ErrUnsupportedEType identifies an unsupported encryption type.
	ErrUnsupportedEType = stderrors.New("unsupported kerberos encryption type")
)

// ErrorCode is a numeric Kerberos protocol error code from RFC 4120.
type ErrorCode int32

const (
	// KDCErrTktExpired is KDC_ERR_TKT_EXPIRED.
	KDCErrTktExpired ErrorCode = 32
	// KDCErrPreauthFailed is KDC_ERR_PREAUTH_FAILED.
	KDCErrPreauthFailed ErrorCode = 24
	// KDCErrPreauthExpired is KDC_ERR_PREAUTH_EXPIRED.
	KDCErrPreauthExpired ErrorCode = 90
	// KDCErrEtypeNosp is KDC_ERR_ETYPE_NOSUPP.
	KDCErrEtypeNosp ErrorCode = 14
	// KDCErrSPrincipalUnknown is KDC_ERR_S_PRINCIPAL_UNKNOWN.
	KDCErrSPrincipalUnknown ErrorCode = 7
	// KRBAPErrBadIntegrity is KRB_AP_ERR_BAD_INTEGRITY.
	KRBAPErrBadIntegrity ErrorCode = 31
	// KRBAPErrTktNYV is KRB_AP_ERR_TKT_NYV.
	KRBAPErrTktNYV ErrorCode = 33
	// KRBAPErrSkew is KRB_AP_ERR_SKEW.
	KRBAPErrSkew ErrorCode = 37
)

// KRBError represents a KRB-ERROR response with safe protocol metadata.
//
// EData is copied when the error is constructed and returned as a copy by
// ErrorData. It must not contain passwords or key material.
type KRBError struct {
	Code   ErrorCode
	Server string
	Realm  string
	Stime  time.Time
	Susec  int32
	EData  []byte
}

// NewKRBError constructs a KRBError and copies eData.
func NewKRBError(code ErrorCode, server, realm string, stime time.Time, susec int32, eData []byte) *KRBError {
	return &KRBError{
		Code:   code,
		Server: server,
		Realm:  realm,
		Stime:  stime,
		Susec:  susec,
		EData:  append([]byte(nil), eData...),
	}
}

// Error returns a concise message without including sensitive protocol data.
func (e *KRBError) Error() string {
	if e == nil {
		return "<nil>"
	}
	return fmt.Sprintf("kerberos KRB-ERROR code %d from %s", e.Code, e.Server)
}

// ErrorData returns a copy of the KRB-ERROR e-data.
func (e *KRBError) ErrorData() []byte {
	if e == nil {
		return nil
	}
	return append([]byte(nil), e.EData...)
}

// Is allows callers to classify protocol errors with errors.Is.
func (e *KRBError) Is(target error) bool {
	switch e.Code {
	case KDCErrTktExpired:
		return target == ErrTicketExpired
	case KRBAPErrTktNYV:
		return target == ErrTicketNotYetValid
	case KDCErrEtypeNosp:
		return target == ErrUnsupportedEType
	case KRBAPErrBadIntegrity, KDCErrPreauthFailed:
		return target == ErrIntegrity
	case KRBAPErrSkew:
		return target == ErrClockSkew
	default:
		return false
	}
}

var _ error = (*KRBError)(nil)
