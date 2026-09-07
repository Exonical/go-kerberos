//go:build !windows

package ccache

import (
	"errors"

	"github.com/Exonical/go-kerberos/internal/secureenv"
)

func osDefaultCCacheName() string {
	return secureenv.Get("KRB5CCNAME")
}

func setOSDefaultCCacheName(string) error {
	return errors.New("ccache: platform default cache is not supported")
}
