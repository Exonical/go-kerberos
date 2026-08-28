package kdc

import (
	"bytes"
	"testing"
	"time"
)

func TestLookasideCacheHitReturnsCopy(t *testing.T) {
	cache := newLookasideCache()
	now := time.Unix(100, 0)
	request := []byte("request")
	response := []byte("response")
	if got, hit := cache.begin(request, now); hit || got != nil {
		t.Fatalf("first begin = %q, %v", got, hit)
	}
	cache.complete(request, response, now)
	response[0] = 'R'
	got, hit := cache.begin(request, now)
	if !hit || !bytes.Equal(got, []byte("response")) {
		t.Fatalf("cached begin = %q, %v", got, hit)
	}
	got[0] = 'x'
	got, hit = cache.begin(request, now)
	if !hit || !bytes.Equal(got, []byte("response")) {
		t.Fatalf("cached response mutation leaked: %q, %v", got, hit)
	}
}

func TestLookasideCacheSuppressesInProgressAndRemovesEmpty(t *testing.T) {
	cache := newLookasideCache()
	now := time.Unix(100, 0)
	request := []byte("request")
	if _, hit := cache.begin(request, now); hit {
		t.Fatal("first request reported as a hit")
	}
	if got, hit := cache.begin(request, now); !hit || got != nil {
		t.Fatalf("in-progress duplicate = %q, %v", got, hit)
	}
	cache.complete(request, nil, now)
	if got, hit := cache.begin(request, now); hit || got != nil {
		t.Fatalf("request after empty completion = %q, %v", got, hit)
	}
}

func TestLookasideCacheExpiresEntries(t *testing.T) {
	cache := newLookasideCache()
	now := time.Unix(100, 0)
	request := []byte("request")
	cache.begin(request, now)
	cache.complete(request, []byte("response"), now)
	if got, hit := cache.begin(request, now.Add(kdcLookasideStaleTime)); hit || got != nil {
		t.Fatalf("expired request = %q, %v", got, hit)
	}
}

func TestLookasideCacheEvictsOldestEntry(t *testing.T) {
	cache := newLookasideCache()
	cache.maxSize = len("a") + len("1") + len("b") + len("2")
	now := time.Unix(100, 0)
	cache.begin([]byte("a"), now)
	cache.complete([]byte("a"), []byte("1"), now)
	cache.begin([]byte("b"), now.Add(time.Second))
	cache.complete([]byte("b"), []byte("2"), now.Add(time.Second))
	cache.begin([]byte("c"), now.Add(2*time.Second))
	if _, ok := cache.entries["a"]; ok {
		t.Fatal("oldest entry was not evicted")
	}
	if _, ok := cache.entries["b"]; !ok {
		t.Fatal("newer entry was evicted")
	}
}
