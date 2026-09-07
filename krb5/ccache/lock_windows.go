//go:build windows

package ccache

import (
	"os"

	"golang.org/x/sys/windows"
)

func lockCachePath(path string) (func(), error) {
	file, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	var overlapped windows.Overlapped
	if err := windows.LockFileEx(windows.Handle(file.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK,
		0, 0xffffffff, 0xffffffff, &overlapped); err != nil {
		_ = file.Close()
		return nil, err
	}
	return func() {
		_ = windows.UnlockFileEx(windows.Handle(file.Fd()), 0, 0xffffffff, 0xffffffff,
			&overlapped)
		_ = file.Close()
	}, nil
}
