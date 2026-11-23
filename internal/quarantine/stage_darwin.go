//go:build darwin && cgo

package quarantine

/*
#include <fcntl.h>
#include <sys/param.h>

static int cau_fd_path(int fd, char *path) {
	return fcntl(fd, F_GETPATH, path);
}
*/
import "C"

import (
	"os"
	"syscall"
)

func sourceChanged(a, b os.FileInfo) bool {
	return a.Sys().(*syscall.Stat_t).Ctimespec != b.Sys().(*syscall.Stat_t).Ctimespec
}

func stagePath(stage *os.File) string {
	var path [C.MAXPATHLEN]C.char
	if C.cau_fd_path(C.int(stage.Fd()), &path[0]) != 0 {
		return ""
	}
	return C.GoString(&path[0])
}
