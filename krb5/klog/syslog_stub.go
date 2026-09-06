//go:build windows || plan9

package klog

import (
	"errors"
	"io"
)

func openSyslog(Facility, string) (io.WriteCloser, error) {
	return nil, errors.New("klog: syslog unavailable on this platform")
}
