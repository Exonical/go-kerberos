package crypto

import (
	"io"

	"github.com/Exonical/go-kerberos/krb5/internal/random"
)

func SetRandomSource(source io.Reader) func() {
	return random.SetSource(source)
}
