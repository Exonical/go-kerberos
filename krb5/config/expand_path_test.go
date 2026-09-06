package config

import "testing"

func TestExpandPathTokensSharedSyntax(t *testing.T) {
	path, err := ExpandPathTokens(`prefix/%{null}/suffix`)
	if err != nil {
		t.Fatal(err)
	}
	if path != `prefix//suffix` {
		t.Fatalf("expanded path = %q, want %q", path, `prefix//suffix`)
	}
	for _, input := range []string{"%{unknown}", "%{uid"} {
		if _, err := ExpandPathTokens(input); err == nil {
			t.Fatalf("ExpandPathTokens(%q) unexpectedly succeeded", input)
		}
	}
}
