package random

import (
	"crypto/rand"
	"io"
)

var source io.Reader = rand.Reader

func Reader() io.Reader {
	return source
}

func SetSource(value io.Reader) func() {
	previous := source
	if value != nil {
		source = value
	}
	return func() {
		source = previous
	}
}
