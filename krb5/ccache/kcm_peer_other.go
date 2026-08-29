//go:build !linux

package ccache

import (
	"errors"
	"net"
)

var errKCMPeerCredentialsUnavailable = errors.New("kcm: peer credentials unavailable")

func kcmPeerUID(net.Conn) (uint32, error) {
	return 0, errKCMPeerCredentialsUnavailable
}
