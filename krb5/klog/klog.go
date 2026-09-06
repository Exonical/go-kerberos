// Package klog implements the MIT Kerberos logging profile syntax.
package klog

import (
	"fmt"
	"io"
	"log/syslog"
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

type Destination struct {
	Kind     Kind
	Path     string
	Facility syslog.Priority
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
	spec  Destination
	file  io.Writer
	close func() error
}

var facilities = map[string]syslog.Priority{
	"AUTH":     syslog.LOG_AUTH,
	"AUTHPRIV": syslog.LOG_AUTHPRIV,
	"KERN":     syslog.LOG_KERN,
	"USER":     syslog.LOG_USER,
	"MAIL":     syslog.LOG_MAIL,
	"DAEMON":   syslog.LOG_DAEMON,
	"FTP":      syslog.LOG_FTP,
	"LPR":      syslog.LOG_LPR,
	"NEWS":     syslog.LOG_NEWS,
	"UUCP":     syslog.LOG_UUCP,
	"CRON":     syslog.LOG_CRON,
	"LOCAL0":   syslog.LOG_LOCAL0,
	"LOCAL1":   syslog.LOG_LOCAL1,
	"LOCAL2":   syslog.LOG_LOCAL2,
	"LOCAL3":   syslog.LOG_LOCAL3,
	"LOCAL4":   syslog.LOG_LOCAL4,
	"LOCAL5":   syslog.LOG_LOCAL5,
	"LOCAL6":   syslog.LOG_LOCAL6,
	"LOCAL7":   syslog.LOG_LOCAL7,
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
		spec := Destination{Kind: Syslog, Facility: syslog.LOG_AUTH}
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
	if cfg != nil {
		if cfg.Options != nil {
			values = cfg.Options["logging"][entity]
			if len(values) == 0 {
				values = cfg.Options["logging"]["default"]
			}
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
		specs = []Destination{{Kind: Syslog, Facility: syslog.LOG_AUTH}}
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
			f, err := os.OpenFile(spec.Path, flags, 0o640)
			if err != nil {
				l.Close()
				return nil, err
			}
			d.file, d.close = f, f.Close
		case Device:
			f, err := os.OpenFile(spec.Path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o640)
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
			writer, err := syslog.New(spec.Facility, program)
			if err != nil {
				l.Close()
				return nil, err
			}
			d.file = writer
			d.close = writer.Close
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

func (l *Logger) Log(level syslog.Priority, format string, args ...any) {
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
		severity(level), message)
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, d := range l.destinations {
		if writer, ok := d.file.(*syslog.Writer); ok {
			_, _ = writer.Write([]byte(message))
			continue
		}
		_, _ = io.WriteString(d.file, line)
	}
}

func (l *Logger) Info(format string, args ...any)    { l.Log(syslog.LOG_INFO, format, args...) }
func (l *Logger) Error(format string, args ...any)   { l.Log(syslog.LOG_ERR, format, args...) }
func (l *Logger) Warning(format string, args ...any) { l.Log(syslog.LOG_WARNING, format, args...) }
func (l *Logger) Debug(format string, args ...any)   { l.Log(syslog.LOG_DEBUG, format, args...) }

func severity(level syslog.Priority) string {
	switch level & 7 {
	case syslog.LOG_EMERG:
		return "emergency"
	case syslog.LOG_ALERT:
		return "alert"
	case syslog.LOG_CRIT:
		return "critical"
	case syslog.LOG_ERR:
		return "error"
	case syslog.LOG_WARNING:
		return "warning"
	case syslog.LOG_NOTICE:
		return "notice"
	case syslog.LOG_INFO:
		return "info"
	case syslog.LOG_DEBUG:
		return "debug"
	default:
		return "unknown"
	}
}
