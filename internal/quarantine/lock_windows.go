package quarantine

import (
	"fmt"
	"path/filepath"
	"syscall"
	"unsafe"

	"github.com/s-b-repo/cau/internal/safefs"
)

const lockFileExclusive = 0x00000002

var (
	lockFileEx   = syscall.NewLazyDLL("kernel32.dll").NewProc("LockFileEx")
	unlockFileEx = syscall.NewLazyDLL("kernel32.dll").NewProc("UnlockFileEx")
)

// lockFile serializes Windows service and CLI operations on the same vault.
// A synchronous handle waits for the byte lock and denies replacement of the
// lock file until the handle closes. Process exit also releases the lock.
func lockFile(path string) (func(), error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	wide, err := windowsPathUTF16(abs)
	if err != nil {
		return nil, err
	}
	handle, err := syscall.CreateFile(wide, syscall.GENERIC_READ|syscall.GENERIC_WRITE,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE, nil, syscall.OPEN_ALWAYS,
		syscall.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, err
	}

	var attrs syscall.ByHandleFileInformation
	if err := syscall.GetFileInformationByHandle(handle, &attrs); err != nil {
		syscall.CloseHandle(handle)
		return nil, err
	}
	if attrs.FileAttributes&(syscall.FILE_ATTRIBUTE_REPARSE_POINT|syscall.FILE_ATTRIBUTE_DIRECTORY) != 0 {
		syscall.CloseHandle(handle)
		return nil, fmt.Errorf("%s: %w", path, safefs.ErrNotRegular)
	}

	var region syscall.Overlapped
	locked, _, lockErr := lockFileEx.Call(uintptr(handle), lockFileExclusive, 0, 1, 0,
		uintptr(unsafe.Pointer(&region))) // audit:ok Win32 uses this structure synchronously
	if locked == 0 {
		syscall.CloseHandle(handle)
		return nil, lockErr
	}
	return func() {
		var region syscall.Overlapped
		unlockFileEx.Call(uintptr(handle), 0, 1, 0,
			uintptr(unsafe.Pointer(&region))) // audit:ok Win32 uses this structure synchronously
		syscall.CloseHandle(handle)
	}, nil
}
