//go:build !windows

package ccache

import "errors"

func resolveMSLSA(string) (*Handle, error) {
	return nil, errors.New("ccache: MSLSA is only supported on Windows")
}

func (h *mslsaHandle) read() (*Cache, error) {
	return nil, errors.New("ccache: MSLSA is only supported on Windows")
}
