//go:build !linux

package ccache

import (
	"errors"
	"fmt"

	"github.com/Exonical/go-kerberos/krb5/principal"
)

type keyringHandle struct{}

func resolveKeyring(string) (*Handle, error) {
	return nil, errors.New("ccache: KEYRING is unsupported on this platform")
}

func (h *keyringHandle) read() (*Cache, error) {
	return nil, errors.New("ccache: KEYRING is unsupported on this platform")
}

func (h *keyringHandle) write(*Cache) error {
	return errors.New("ccache: KEYRING is unsupported on this platform")
}

func (h *keyringHandle) initialize(principal.Principal) error {
	return fmt.Errorf("ccache: KEYRING is unsupported on this platform")
}

func (h *keyringHandle) store(Credential) error {
	return errors.New("ccache: KEYRING is unsupported on this platform")
}

func (h *keyringHandle) destroy() error {
	return errors.New("ccache: KEYRING is unsupported on this platform")
}
