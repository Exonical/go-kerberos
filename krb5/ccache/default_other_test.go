//go:build !windows

package ccache

import (
	"strings"
	"testing"
)

func TestSetDefaultNameUnsupportedOther(t *testing.T) {
	if err := SetDefaultName("FILE:/tmp/krb5cc"); err == nil ||
		!strings.Contains(err.Error(), "not supported") {
		t.Fatalf("SetDefaultName error = %v", err)
	}
}
