// Package klog implements the MIT Kerberos logging profile syntax.
package klog

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Exonical/go-kerberos/krb5/config"
)

type Kind int

const (
	Syslog Kind = iota
	File
	Stderr
	Console
	Device
)

// Facility identifies a syslog facility using the values shared by Unix
// syslog implementations.
type Facility int

const (
	FacilityKern     Facility = 0
	FacilityUser     Facility = 1
	FacilityMail     Facility = 2
	FacilityDaemon   Facility = 3
	FacilityAuth     Facility = 4
	FacilitySyslog   Facility = 5
	FacilityLPR      Facility = 6
	FacilityNews     Facility = 7
	FacilityUUCP     Facility = 8
	FacilityCron     Facility = 9
	FacilityAuthPriv Facility = 10
	FacilityFTP      Facility = 11
	FacilityLocal0   Facility = 16
	FacilityLocal1   Facility = 17
	FacilityLocal2   Facility = 18
	FacilityLocal3   Facility = 19
	FacilityLocal4   Facility = 20
	FacilityLocal5   Facility = 21
	FacilityLocal6   Facility = 22
	FacilityLocal7   Facility = 23
)

// Severity identifies a syslog severity.
type Severity int

const (
	SeverityEmerg Severity = iota
	SeverityAlert
	SeverityCrit
	SeverityError
	SeverityWarning
	SeverityNotice
	SeverityInfo
	SeverityDebug
)

type Destination struct {
	Kind     Kind
	Path     string
	Facility Facility
	Append   bool
}

type Logger struct {
	mu           sync.Mutex
	destinations []destination
	Program      string
	Hostname     string
	Now          func() time.Time
	PID          int
}

type destination struct {
	spec   Destination
	file   io.Writer
	syslog syslogSink
	close  func() error
}

type syslogSink interface {
	write(Severity, string) error
	Close() error
}

var facilities = map[string]Facility{
	"AUTH":     FacilityAuth,
	"AUTHPRIV": FacilityAuthPriv,
	"KERN":     FacilityKern,
	"USER":     FacilityUser,
	"MAIL":     FacilityMail,
	"DAEMON":   FacilityDaemon,
	"FTP":      FacilityFTP,
	"LPR":      FacilityLPR,
	"NEWS":     FacilityNews,
	"UUCP":     FacilityUUCP,
	"CRON":     FacilityCron,
	"LOCAL0":   FacilityLocal0,
	"LOCAL1":   FacilityLocal1,
	"LOCAL2":   FacilityLocal2,
	"LOCAL3":   FacilityLocal3,
	"LOCAL4":   FacilityLocal4,
	"LOCAL5":   FacilityLocal5,
	"LOCAL6":   FacilityLocal6,
	"LOCAL7":   FacilityLocal7,
}

// ParseSpecs parses FILE, SYSLOG, STDERR, CONSOLE, and DEVICE destinations.
func ParseSpecs(values []string) ([]Destination, error) {
	var out []Destination
	for _, value := range values {
		for _, raw := range strings.Fields(value) {
			spec, err := parseSpec(raw)
			if err != nil {
				return nil, err
			}
			out = append(out, spec)
		}
	}
	return out, nil
}

func parseSpec(raw string) (Destination, error) {
	upper := strings.ToUpper(raw)
	switch {
	case upper == "STDERR":
		return Destination{Kind: Stderr}, nil
	case upper == "CONSOLE":
		return Destination{Kind: Console}, nil
	case strings.HasPrefix(upper, "FILE="):
		if len(raw) == len("FILE=") {
			return Destination{}, fmt.Errorf("logging destination %q has empty path", raw)
		}
		return Destination{Kind: File, Path: raw[5:]}, nil
	case strings.HasPrefix(upper, "FILE:"):
		if len(raw) == len("FILE:") {
			return Destination{}, fmt.Errorf("logging destination %q has empty path", raw)
		}
		return Destination{Kind: File, Path: raw[5:], Append: true}, nil
	case strings.HasPrefix(upper, "DEVICE="):
		if len(raw) == len("DEVICE=") {
			return Destination{}, fmt.Errorf("logging destination %q has empty path", raw)
		}
		return Destination{Kind: Device, Path: raw[7:]}, nil
	case upper == "SYSLOG" || strings.HasPrefix(upper, "SYSLOG:"):
		spec := Destination{Kind: Syslog, Facility: FacilityAuth}
		if len(raw) == len("SYSLOG") {
			return spec, nil
		}
		parts := strings.Split(raw, ":")
		if len(parts) > 3 {
			return Destination{}, fmt.Errorf("invalid logging destination %q", raw)
		}
		if len(parts) == 3 {
			if facility, ok := facilities[strings.ToUpper(parts[2])]; ok {
				spec.Facility = facility
			} else {
				return Destination{}, fmt.Errorf("unknown syslog facility %q", parts[2])
			}
		}
		return spec, nil
	default:
		return Destination{}, fmt.Errorf("unknown logging destination %q", raw)
	}
}

// NewFromConfig selects entity and default relations from a parsed profile.
func NewFromConfig(cfg *config.Config, entity, program string) (*Logger, error) {
	var values []string
	if cfg != nil && cfg.Options != nil {
		values = cfg.Options["logging"][entity]
		if len(values) == 0 {
			values = cfg.Options["logging"]["default"]
		}
	}
	return New(values, program)
}

func New(values []string, program string) (*Logger, error) {
	specs, err := ParseSpecs(values)
	if err != nil {
		return nil, err
	}
	if len(specs) == 0 {
		specs = []Destination{{Kind: Syslog, Facility: FacilityAuth}}
	}
	l := &Logger{Program: program, Hostname: hostname(), Now: time.Now, PID: os.Getpid()}
	for _, spec := range specs {
		d := destination{spec: spec}
		switch spec.Kind {
		case File:
			flags := os.O_CREATE | os.O_WRONLY
			if spec.Append {
				flags |= os.O_APPEND
			} else {
				flags |= os.O_TRUNC
			}
			f, err := os.OpenFile(spec.Path, flags, 0o640) // nosemgrep: tmp.opengrep-rules.go.lang.correctness.permissions.incorrect-default-permission -- 0640 log file is intentionally restrictive
			if err != nil {
				l.Close()
				return nil, err
			}
			d.file, d.close = f, f.Close
		case Device:
			f, err := os.OpenFile(spec.Path, os.O_WRONLY|os.O_APPEND, 0)
			if err != nil {
				l.Close()
				return nil, err
			}
			d.file, d.close = f, f.Close
		case Stderr:
			d.file = os.Stderr
		case Console:
			f, err := os.OpenFile("/dev/console", os.O_WRONLY|os.O_APPEND, 0)
			if err != nil {
				l.Close()
				return nil, err
			}
			d.file, d.close = f, f.Close
		case Syslog:
			writer, err := openSyslog(spec.Facility, program)
			if err != nil {
				l.Close()
				return nil, err
			}
			d.syslog, d.close = writer, writer.Close
		}
		l.destinations = append(l.destinations, d)
	}
	return l, nil
}

func hostname() string {
	value, err := os.Hostname()
	if err != nil {
		return ""
	}
	return value
}

func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	var first error
	for i := range l.destinations {
		if l.destinations[i].close != nil {
			if err := l.destinations[i].close(); err != nil && first == nil {
				first = err
			}
		}
	}
	l.destinations = nil
	return first
}

func (l *Logger) Log(level Severity, format string, args ...any) {
	if l == nil {
		return
	}
	message := fmt.Sprintf(format, args...)
	now := time.Now
	if l.Now != nil {
		now = l.Now
	}
	line := fmt.Sprintf("%s %s %s[%d](%s): %s\n",
		now().Local().Format("Jan 02 15:04:05"), l.Hostname, l.Program, l.PID,
		severityName(level), message)
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, d := range l.destinations {
		if d.syslog != nil {
			_ = d.syslog.write(level, message)
			continue
		}
		_, _ = io.WriteString(d.file, line)
	}
}

func (l *Logger) Info(format string, args ...any) {
	l.Log(SeverityInfo, format, args...)
}
func (l *Logger) Error(format string, args ...any) {
	l.Log(SeverityError, format, args...)
}
func (l *Logger) Warning(format string, args ...any) {
	l.Log(SeverityWarning, format, args...)
}
func (l *Logger) Debug(format string, args ...any) {
	l.Log(SeverityDebug, format, args...)
}

func severityName(level Severity) string {
	switch level {
	case SeverityEmerg:
		return "emergency"
	case SeverityAlert:
		return "alert"
	case SeverityCrit:
		return "critical"
	case SeverityError:
		return "error"
	case SeverityWarning:
		return "warning"
	case SeverityNotice:
		return "notice"
	case SeverityInfo:
		return "info"
	case SeverityDebug:
		return "debug"
	default:
		return "unknown"
	}
}
