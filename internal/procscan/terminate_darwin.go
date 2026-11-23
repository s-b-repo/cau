package procscan

import (
	"errors"
	"path/filepath"
	"strings"

	"github.com/s-b-repo/cau/internal/desktop"
)

func terminateDesktop(process Process) error {
	if process.nativeCreated == 0 || !filepath.IsAbs(process.Exe) {
		return errors.New("process identity or image was unavailable during collection")
	}
	path, err := filepath.EvalSymlinks(process.Exe)
	if err != nil {
		return errors.New("could not verify the process image path")
	}
	if systemExePath(path) || strings.HasPrefix(path, "/System/") {
		return errors.New("process image is in a protected macOS system directory")
	}
	return desktop.TerminateMacProcess(process.PID, process.nativeCreated, process.Exe)
}
