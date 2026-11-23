//go:build linux && cgo

package quarantine

import (
	"os"
	"strconv"
	"syscall"
)

func sourceChanged(a, b os.FileInfo) bool {
	return a.Sys().(*syscall.Stat_t).Ctim != b.Sys().(*syscall.Stat_t).Ctim
}

func stagePath(stage *os.File) string {
	path, err := os.Readlink("/proc/self/fd/" + strconv.FormatUint(uint64(stage.Fd()), 10))
	if err != nil { // audit:ok the diagnostic switches to its recorded directory when descriptor lookup is unavailable
		return "" // the calling recovery report falls back to the original directory
	}
	return path
}
