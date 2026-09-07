//go:build !windows

package ccache

import (
	"errors"
	"os"
)

func osDefaultCCacheName() string {
	return os.Getenv("KRB5CCNAME")
}

func setOSDefaultCCacheName(string) error {
	return errors.New("ccache: platform default cache is not supported")
}
