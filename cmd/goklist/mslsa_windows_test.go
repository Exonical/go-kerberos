//go:build windows

package main

import (
	"strings"
	"testing"
)

func TestListMSLSA(t *testing.T) {
	err := runList([]string{"-c", "MSLSA:"}, listDiscardWriter{})
	if err != nil {
		if strings.Contains(err.Error(), "MSLSA") {
			t.Skipf("MSLSA is unavailable: %v", err)
		}
		t.Fatalf("MSLSA listing failed unexpectedly: %v", err)
	}
}

type listDiscardWriter struct{}

func (listDiscardWriter) Write(p []byte) (int, error) { return len(p), nil }
