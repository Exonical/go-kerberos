//go:build !windows && !plan9

package klog

import (
	"log/syslog"
)

type unixSyslog struct {
	writer *syslog.Writer
}

func openSyslog(facility Facility, program string) (*unixSyslog, error) {
	writer, err := syslog.New(syslog.Priority(facility<<3), program)
	if err != nil {
		return nil, err
	}
	return &unixSyslog{writer: writer}, nil
}

func (s *unixSyslog) write(level Severity, message string) error {
	switch level {
	case SeverityEmerg:
		return s.writer.Emerg(message)
	case SeverityAlert:
		return s.writer.Alert(message)
	case SeverityCrit:
		return s.writer.Crit(message)
	case SeverityError:
		return s.writer.Err(message)
	case SeverityWarning:
		return s.writer.Warning(message)
	case SeverityNotice:
		return s.writer.Notice(message)
	case SeverityInfo:
		return s.writer.Info(message)
	case SeverityDebug:
		return s.writer.Debug(message)
	default:
		return s.writer.Info(message)
	}
}

func (s *unixSyslog) Close() error {
	return s.writer.Close()
}
