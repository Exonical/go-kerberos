//go:build windows || plan9

package klog

import (
	"errors"
)

type unavailableSyslog struct{}

func openSyslog(Facility, string) (*unavailableSyslog, error) {
	return nil, errors.New("klog: syslog unavailable on this platform")
}

func (*unavailableSyslog) write(Severity, string) error {
	return errors.New("klog: syslog unavailable on this platform")
}

func (*unavailableSyslog) Close() error { return nil }
