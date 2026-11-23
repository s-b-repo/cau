package procscan

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

const processQueryLimitedInformation = 0x1000

var processKernel = syscall.NewLazyDLL("kernel32.dll")
var queryProcessImage = processKernel.NewProc("QueryFullProcessImageNameW")
var windowsDirectory = processKernel.NewProc("GetSystemWindowsDirectoryW")

func terminateDesktop(process Process) error {
	if process.PID <= 4 || uint64(process.PID) > uint64(^uint32(0)) || process.nativeCreated == 0 || !filepath.IsAbs(process.Exe) {
		return errors.New("process identity or image was unavailable during collection")
	}
	handle, err := syscall.OpenProcess(syscall.PROCESS_TERMINATE|processQueryLimitedInformation, false, uint32(process.PID))
	if err != nil {
		return fmt.Errorf("open process for response: %w", err)
	}
	defer syscall.CloseHandle(handle)

	var created, exited, kernel, user syscall.Filetime
	if err := syscall.GetProcessTimes(handle, &created, &exited, &kernel, &user); err != nil {
		return fmt.Errorf("read process creation time: %w", err)
	}
	ticks := uint64(created.HighDateTime)<<32 | uint64(created.LowDateTime)
	// WMI reports the creation time with microsecond precision, while
	// GetProcessTimes uses units of 100 ns.
	if ticks/10 != process.nativeCreated/10 {
		return errors.New("process creation time changed since the scan")
	}
	var image [32768]uint16
	length := uint32(len(image))
	ok, _, err := queryProcessImage.Call(uintptr(handle), 0, uintptr(unsafe.Pointer(&image[0])), uintptr(unsafe.Pointer(&length))) // audit:ok synchronous Win32 call with a UTF-16 array and its character count
	if ok == 0 || length == 0 || length >= uint32(len(image)) {
		return fmt.Errorf("read image from the process handle: %w", err)
	}
	actual := filepath.Clean(syscall.UTF16ToString(image[:length]))
	if !strings.EqualFold(actual, filepath.Clean(process.Exe)) {
		return errors.New("process image changed since the scan")
	}
	var root [32768]uint16
	n, _, err := windowsDirectory.Call(uintptr(unsafe.Pointer(&root[0])), uintptr(len(root))) // audit:ok synchronous Win32 call with a UTF-16 array and its character count
	if n == 0 || n >= uintptr(len(root)) {
		return fmt.Errorf("locate protected Windows directory: %w", err)
	}
	system, err := filepath.EvalSymlinks(syscall.UTF16ToString(root[:n]))
	if err != nil {
		return errors.New("could not resolve the protected Windows directory")
	}
	resolved, err := filepath.EvalSymlinks(actual)
	if err != nil {
		return errors.New("could not resolve the process image")
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.Mode().IsRegular() {
		return errors.New("the process image is not a readable regular file")
	}
	relative, err := filepath.Rel(system, resolved)
	if err == nil && filepath.IsLocal(relative) {
		return errors.New("process image is in the protected Windows directory")
	}
	return syscall.TerminateProcess(handle, 1)
}
