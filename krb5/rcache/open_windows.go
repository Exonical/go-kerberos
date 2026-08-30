//go:build windows

package rcache

import "os"

func openReplayFile(path string, _ bool) (*os.File, error) {
	return os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
}
