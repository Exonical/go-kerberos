//go:build !windows

package rcache

import (
	"os"
	"syscall"
)

func openReplayFile(path string, secure bool) (*os.File, error) {
	flags := syscall.O_CREAT | syscall.O_RDWR
	if secure {
		flags |= syscall.O_NOFOLLOW
	}
	fd, err := syscall.Open(path, flags, 0600)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = syscall.Close(fd)
		return nil, syscall.EINVAL
	}
	if secure {
		info, err := file.Stat()
		if err != nil {
			_ = file.Close()
			return nil, err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || uint32(stat.Uid) != uint32(os.Geteuid()) {
			_ = file.Close()
			return nil, syscall.EIO
		}
	}
	return file, nil
}
