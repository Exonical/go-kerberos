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
