package errors

import (
	"errors"
	"testing"
	"time"
)

func TestKRBErrorClassificationAndAs(t *testing.T) {
	err := NewKRBError(KDCErrTktExpired, "krbtgt/REALM", "REALM", time.Time{}, 7, []byte{1, 2})
	if !errors.Is(err, ErrTicketExpired) {
		t.Fatalf("errors.Is(%v, ErrTicketExpired) = false", err)
	}
	var typed *KRBError
	if !errors.As(err, &typed) || typed.Code != KDCErrTktExpired {
		t.Fatalf("errors.As = %#v", typed)
	}
	data := typed.ErrorData()
	data[0] = 9
	if typed.ErrorData()[0] != 1 {
		t.Fatal("ErrorData did not return a copy")
	}
}

func TestKRBErrorClassificationCodes(t *testing.T) {
	tests := []struct {
		code   ErrorCode
		target error
	}{
		{KDCErrTktExpired, ErrTicketExpired},
		{KDCErrEtypeNosp, ErrUnsupportedEType},
		{KRBAPErrBadIntegrity, ErrIntegrity},
		{KDCErrPreauthFailed, ErrIntegrity},
		{KRBAPErrSkew, ErrClockSkew},
	}
	for _, test := range tests {
		err := NewKRBError(test.code, "krbtgt/EXAMPLE.COM", "EXAMPLE.COM", time.Time{}, 0, nil)
		if !errors.Is(err, test.target) {
			t.Errorf("code %d did not classify as %v", test.code, test.target)
		}
		if errors.Is(err, ErrReplay) {
			t.Errorf("code %d incorrectly classified as replay", test.code)
		}
	}
	unknown := NewKRBError(999, "server", "REALM", time.Time{}, 0, nil)
	if errors.Is(unknown, ErrIntegrity) {
		t.Fatal("unknown code classified as integrity")
	}
}

func TestKRBErrorNilAndSafeMessage(t *testing.T) {
	var err *KRBError
	if err.Error() != "<nil>" || err.ErrorData() != nil {
		t.Fatalf("nil KRBError = %q, %#v", err.Error(), err.ErrorData())
	}
	err = NewKRBError(KDCErrPreauthFailed, "server", "REALM", time.Time{}, 0, []byte("secret"))
	if got := err.Error(); got != "kerberos KRB-ERROR code 24 from server" {
		t.Fatalf("KRBError message = %q", got)
	}
	if string(err.ErrorData()) != "secret" {
		t.Fatalf("KRBError data = %q", err.ErrorData())
	}
}
