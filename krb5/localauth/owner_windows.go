//go:build windows

package localauth

import "os"

func fileOwnerUID(info os.FileInfo) (uint32, bool) {
	return 0, false
}
