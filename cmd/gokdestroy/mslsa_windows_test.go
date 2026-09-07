//go:build windows

package main

import (
	"strings"
	"testing"
)

func TestDestroyMSLSAIsReadOnly(t *testing.T) {
	err := runDestroy([]string{"-c", "MSLSA:"}, discardWriter{})
	if err == nil || !strings.Contains(err.Error(), "MSLSA is read-only in this implementation") {
		t.Fatalf("destroy error = %v", err)
	}
}

type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }
