package principal

import "testing"

func TestMITPrincipalParseUnparseBehavior(t *testing.T) {
	tests := []string{
		"alice/admin@EXAMPLE.COM",
		`test\/principal@SU.SE`,
		`user\@name@EXAMPLE.COM`,
		`a\\b@EXAMPLE.COM`,
	}
	for _, input := range tests {
		p, err := Parse(input)
		if err != nil {
			t.Fatalf("Parse(%q): %v", input, err)
		}
		got, err := p.Format()
		if err != nil || got != input {
			t.Fatalf("Format(Parse(%q)) = %q, %v", input, got, err)
		}
	}
}

func TestMITPrincipalRealmAndComparisonBehavior(t *testing.T) {
	qualified, err := Parse("alice@EXAMPLE.COM")
	if err != nil {
		t.Fatal(err)
	}
	short := *qualified
	short.Realm = "OTHER.COM"
	if short.Components[0] != qualified.Components[0] {
		t.Fatal("changing realm changed principal components")
	}
	if short.String() == qualified.String() {
		t.Fatal("principals with different realms formatted identically")
	}
	empty := Principal{Realm: "EXAMPLE.COM", Components: []string{"a", "b"}}
	if got, err := empty.Format(); err != nil || got != "a/b@EXAMPLE.COM" {
		t.Fatalf("default name type format = %q, %v", got, err)
	}
}
