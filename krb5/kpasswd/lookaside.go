package kpasswd

import (
	"container/list"
	"sync"
	"time"
)

const (
	lookasideStaleTime = 2 * time.Minute
	lookasideMaxSize   = 10 << 20
)

type lookasideCache struct {
	mu      sync.Mutex
	entries map[string]*lookasideEntry
	queue   list.List
	size    int
	maxSize int
}

type lookasideEntry struct {
	request  []byte
	response []byte
	timeIn   time.Time
	hits     uint64
	element  *list.Element
}

func newLookasideCache() *lookasideCache {
	return &lookasideCache{
		entries: make(map[string]*lookasideEntry),
		maxSize: lookasideMaxSize,
	}
}

// begin returns a cached response or reserves a request for processing. A
// found entry with a nil response is an in-progress duplicate and must be
// dropped silently by the caller.
func (c *lookasideCache) begin(request []byte, now time.Time) ([]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.initializeLocked()
	c.expireLocked(now)
	key := string(request)
	if entry, ok := c.entries[key]; ok {
		entry.hits++
		if entry.response == nil {
			return nil, true
		}
		return cloneBytes(entry.response), true
	}
	entry := &lookasideEntry{
		request: cloneBytes(request),
		timeIn:  now,
	}
	entry.element = c.queue.PushBack(entry)
	c.entries[key] = entry
	c.size += len(entry.request)
	c.evictLocked()
	return nil, false
}

// complete stores a response for a reserved request. A nil response removes
// the reservation, allowing a later retry to be processed normally.
func (c *lookasideCache) complete(request, response []byte, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.initializeLocked()
	c.expireLocked(now)
	key := string(request)
	entry, ok := c.entries[key]
	if !ok {
		return
	}
	if response == nil {
		c.removeLocked(entry)
		return
	}
	entry.response = cloneBytes(response)
	c.size += len(entry.response)
	c.evictLocked()
}

func (c *lookasideCache) initializeLocked() {
	if c.entries == nil {
		c.entries = make(map[string]*lookasideEntry)
	}
	if c.maxSize <= 0 {
		c.maxSize = lookasideMaxSize
	}
}

func (c *lookasideCache) expireLocked(now time.Time) {
	for element := c.queue.Front(); element != nil; {
		next := element.Next()
		entry := element.Value.(*lookasideEntry)
		if now.Before(entry.timeIn) || now.Sub(entry.timeIn) < lookasideStaleTime {
			break
		}
		c.removeLocked(entry)
		element = next
	}
}

func (c *lookasideCache) evictLocked() {
	for c.size > c.maxSize {
		element := c.queue.Front()
		if element == nil {
			c.size = 0
			return
		}
		c.removeLocked(element.Value.(*lookasideEntry))
	}
}

func (c *lookasideCache) removeLocked(entry *lookasideEntry) {
	delete(c.entries, string(entry.request))
	if entry.element != nil {
		c.queue.Remove(entry.element)
		entry.element = nil
	}
	c.size -= len(entry.request) + len(entry.response)
	if c.size < 0 {
		c.size = 0
	}
}

func cloneBytes(value []byte) []byte {
	if value == nil {
		return nil
	}
	return append([]byte{}, value...)
}
