package kpasswd

import (
	"bytes"
	"testing"
	"time"
)

func TestLookasideCacheHitReturnsIdenticalResponse(t *testing.T) {
	cache := newLookasideCache()
	now := time.Unix(1900000500, 0).UTC()
	request := []byte("request")
	response := []byte("response")
	if got, found := cache.begin(request, now); found || got != nil {
		t.Fatalf("initial begin = (%x, %t), want (nil, false)", got, found)
	}
	cache.complete(request, response, now)
	got, found := cache.begin(request, now.Add(time.Second))
	if !found || !bytes.Equal(got, response) {
		t.Fatalf("cached begin = (%x, %t), want (%x, true)", got, found, response)
	}
	got[0] = 'R'
	if entry := cache.entries[string(request)]; !bytes.Equal(entry.response, response) {
		t.Fatalf("cache response was not isolated from caller mutation: %q", entry.response)
	}
	if cache.entries[string(request)].hits != 1 {
		t.Fatalf("cache hits = %d, want 1", cache.entries[string(request)].hits)
	}
}

func TestLookasideCacheDropsInProgressDuplicateAndCleansPlaceholder(t *testing.T) {
	cache := newLookasideCache()
	now := time.Unix(1900000600, 0).UTC()
	request := []byte("request")
	if _, found := cache.begin(request, now); found {
		t.Fatal("initial request unexpectedly found")
	}
	if response, found := cache.begin(request, now); !found || response != nil {
		t.Fatalf("in-progress duplicate = (%x, %t), want (nil, true)", response, found)
	}
	cache.complete(request, nil, now)
	if _, found := cache.begin(request, now); found {
		t.Fatal("nil-response placeholder was not removed")
	}
}

func TestLookasideCacheExpiresEntries(t *testing.T) {
	cache := newLookasideCache()
	now := time.Unix(1900000700, 0).UTC()
	request := []byte("request")
	if _, found := cache.begin(request, now); found {
		t.Fatal("initial request unexpectedly found")
	}
	cache.complete(request, []byte("response"), now)
	if response, found := cache.begin(request, now.Add(lookasideStaleTime)); found || response != nil {
		t.Fatalf("expired entry = (%x, %t), want (nil, false)", response, found)
	}
}

func TestLookasideCacheEvictsOldestEntriesBySize(t *testing.T) {
	cache := newLookasideCache()
	cache.maxSize = 8
	now := time.Unix(1900000800, 0).UTC()
	first := []byte("old")
	second := []byte("new")
	if _, found := cache.begin(first, now); found {
		t.Fatal("first request unexpectedly found")
	}
	cache.complete(first, []byte("12345"), now)
	if _, found := cache.begin(second, now.Add(time.Second)); found {
		t.Fatal("second request unexpectedly found")
	}
	cache.complete(second, []byte("12345"), now.Add(time.Second))
	if _, found := cache.entries[string(first)]; found {
		t.Fatal("oldest entry was not evicted")
	}
	if response, found := cache.begin(second, now.Add(2*time.Second)); !found || !bytes.Equal(response, []byte("12345")) {
		t.Fatalf("newest entry = (%x, %t), want (12345, true)", response, found)
	}
}
