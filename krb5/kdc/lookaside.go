package kdc

import (
	"container/list"
	"sync"
	"time"
)

const (
	kdcLookasideStaleTime = 2 * time.Minute
	kdcLookasideMaxSize   = 10 << 20
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
	return &lookasideCache{entries: make(map[string]*lookasideEntry), maxSize: kdcLookasideMaxSize}
}

// begin returns a cached response, or marks a new request as in progress.
// A nil response with cached=true means another request is processing it.
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
		return append([]byte(nil), entry.response...), true
	}
	entry := &lookasideEntry{request: append([]byte(nil), request...), timeIn: now}
	entry.element = c.queue.PushBack(entry)
	c.entries[key] = entry
	c.size += len(entry.request)
	c.evictLocked()
	return nil, false
}

func (c *lookasideCache) complete(request, response []byte, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.initializeLocked()
	c.expireLocked(now)
	entry, ok := c.entries[string(request)]
	if !ok {
		return
	}
	if len(response) == 0 {
		c.removeLocked(entry)
		return
	}
	entry.response = append([]byte(nil), response...)
	c.size += len(entry.response)
	c.evictLocked()
}

func (c *lookasideCache) initializeLocked() {
	if c.entries == nil {
		c.entries = make(map[string]*lookasideEntry)
	}
	if c.maxSize <= 0 {
		c.maxSize = kdcLookasideMaxSize
	}
}

func (c *lookasideCache) expireLocked(now time.Time) {
	for element := c.queue.Front(); element != nil; {
		next := element.Next()
		entry := element.Value.(*lookasideEntry)
		if now.Before(entry.timeIn.Add(kdcLookasideStaleTime)) {
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
			return
		}
		c.removeLocked(element.Value.(*lookasideEntry))
	}
}

func (c *lookasideCache) removeLocked(entry *lookasideEntry) {
	delete(c.entries, string(entry.request))
	c.queue.Remove(entry.element)
	c.size -= len(entry.request) + len(entry.response)
	if c.size < 0 {
		c.size = 0
	}
}
