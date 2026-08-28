package kdb

import (
	"sync"
	"time"

	"github.com/Exonical/go-kerberos/krb5/principal"
)

// UpdateLogEntry is an immutable snapshot of one principal database change.
// Record preserves the prior principal for deletion records.
type UpdateLogEntry struct {
	Serial  uint32
	Time    time.Time
	Name    principal.Principal
	Record  PrincipalRecord
	Deleted bool
	Commit  bool
}

// UpdateLog is a bounded, concurrency-safe incremental propagation log.
type UpdateLog struct {
	mu       sync.RWMutex
	capacity int
	entries  []UpdateLogEntry
	last     uint32
	lastTime time.Time
	reset    bool
}

// NewUpdateLog creates an in-memory update log with the requested retention
// size. A non-positive size disables retention and causes replicas to require
// a full resynchronization.
func NewUpdateLog(capacity int) *UpdateLog {
	if capacity < 0 {
		capacity = 0
	}
	return &UpdateLog{capacity: capacity}
}

// SetCapacity changes retention size and drops entries which no longer fit.
func (l *UpdateLog) SetCapacity(capacity int) {
	if l == nil {
		return
	}
	if capacity < 0 {
		capacity = 0
	}
	l.mu.Lock()
	l.capacity = capacity
	if capacity == 0 {
		l.entries = nil
	} else if len(l.entries) > capacity {
		l.entries = append([]UpdateLogEntry(nil), l.entries[len(l.entries)-capacity:]...)
	}
	l.mu.Unlock()
}

// Reset discards retained entries while preserving the serial marker. A
// replica whose cursor is not exactly the marker must perform full resync.
func (l *UpdateLog) Reset() {
	if l == nil {
		return
	}
	l.mu.Lock()
	l.entries = nil
	l.reset = true
	l.mu.Unlock()
}

// Last returns the current log cursor.
func (l *UpdateLog) Last() (uint32, time.Time) {
	if l == nil {
		return 0, time.Time{}
	}
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.last, l.lastTime
}

// Entries returns a status and updates after the supplied cursor. The status
// values intentionally match the public iprop package constants numerically:
// 0=OK, 2=full resync needed, and 4=nil.
func (l *UpdateLog) Entries(serial uint32, stamp time.Time) (int32, []UpdateLogEntry) {
	if l == nil {
		return 2, nil
	}
	l.mu.RLock()
	defer l.mu.RUnlock()
	if !l.reset && serial == l.last && stamp.Equal(l.lastTime) {
		return 4, nil
	}
	if len(l.entries) == 0 || serial > l.last {
		return 2, nil
	}
	first := l.entries[0].Serial
	if serial < first {
		return 2, nil
	}
	index := -1
	for i := range l.entries {
		if l.entries[i].Serial == serial {
			if !l.entries[i].Time.Equal(stamp) {
				return 2, nil
			}
			index = i
			break
		}
	}
	if index < 0 {
		return 2, nil
	}
	out := make([]UpdateLogEntry, len(l.entries[index+1:]))
	for i, entry := range l.entries[index+1:] {
		out[i] = copyUpdateLogEntry(entry)
	}
	if len(out) == 0 {
		return 4, nil
	}
	return 0, out
}

func (l *UpdateLog) append(entry UpdateLogEntry) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.last == ^uint32(0) {
		l.entries = nil
		l.last = 0
		l.lastTime = time.Time{}
	}
	l.last++
	entry.Serial = l.last
	// MIT kdbe_time_t carries microseconds, so cursors must compare at that
	// precision rather than against Go's nanosecond clock value.
	entry.Time = entry.Time.UTC().Truncate(time.Microsecond)
	l.lastTime = entry.Time
	l.reset = false
	if l.capacity > 0 {
		l.entries = append(l.entries, copyUpdateLogEntry(entry))
		if len(l.entries) > l.capacity {
			l.entries = l.entries[len(l.entries)-l.capacity:]
		}
	} else {
		l.entries = nil
	}
}

func copyUpdateLogEntry(entry UpdateLogEntry) UpdateLogEntry {
	entry.Name.Components = append([]string(nil), entry.Name.Components...)
	entry.Record = copyRecord(entry.Record)
	return entry
}
