package scanner

import (
	"os"
	"syscall"
)

// Linux records changes to file contents and metadata separately from mtime.
func fileChangeTime(fi os.FileInfo) syscall.Timespec {
	return fi.Sys().(*syscall.Stat_t).Ctim
}
