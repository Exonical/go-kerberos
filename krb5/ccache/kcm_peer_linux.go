//go:build linux

package ccache

import (
	"errors"
	"net"

	"golang.org/x/sys/unix"
)

var errKCMPeerCredentialsUnavailable = errors.New("kcm: peer credentials unavailable")

func kcmPeerUID(conn net.Conn) (uint32, error) {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return 0, errKCMPeerCredentialsUnavailable
	}
	raw, err := unixConn.SyscallConn()
	if err != nil {
		return 0, err
	}
	var (
		uid   uint32
		opErr error
	)
	if err := raw.Control(func(fd uintptr) {
		cred, err := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		if err != nil {
			opErr = err
			return
		}
		uid = cred.Uid
	}); err != nil {
		return 0, err
	}
	if opErr != nil {
		return 0, opErr
	}
	return uid, nil
}
