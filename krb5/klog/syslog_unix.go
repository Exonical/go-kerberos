//go:build !windows && !plan9

package klog

import (
	"io"
	"log/syslog"
)

func openSyslog(facility Facility, program string) (io.WriteCloser, error) {
	return syslog.New(syslog.Priority(facility<<3), program)
}
