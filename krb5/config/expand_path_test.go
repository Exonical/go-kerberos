package config

import (
	"runtime"
	"testing"
)

func TestExpandPathTokensSharedSyntax(t *testing.T) {
	path, err := ExpandPathTokens(`prefix/%{null}/suffix`)
	if err != nil {
		t.Fatal(err)
	}
	want := `prefix//suffix`
	if runtime.GOOS == "windows" {
		want = `prefix\suffix`
	}
	if path != want {
		t.Fatalf("expanded path = %q, want %q", path, want)
	}
	for _, input := range []string{"%{unknown}", "%{uid"} {
		if _, err := ExpandPathTokens(input); err == nil {
			t.Fatalf("ExpandPathTokens(%q) unexpectedly succeeded", input)
		}
	}
}
