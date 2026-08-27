package principal

import "testing"

func FuzzPrincipalParse(f *testing.F) {
	for _, seed := range []string{"alice@REALM", `service/a\/b@REALM`, "malformed"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		_, _ = Parse(input)
	})
}
