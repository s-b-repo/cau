package quarantine

import (
	"crypto/sha256"
	"fmt"
	"os"
	"strings"
	"syscall"
	"unsafe"

	"github.com/s-b-repo/cau/internal/safefs"
)

const (
	deleteAccess        = 0x10000
	fileDispositionInfo = 4
)

var setFileInformationByHandle = syscall.NewLazyDLL("kernel32.dll").NewProc("SetFileInformationByHandle")

type quarantineSource struct {
	path      string
	file      *os.File
	removeErr error
}

func windowsPathUTF16(name string) (*uint16, error) {
	if !strings.HasPrefix(name, `\\?\`) && !strings.HasPrefix(name, `\\.\`) {
		if unc, ok := strings.CutPrefix(name, `\\`); ok {
			name = `\\?\UNC\` + unc
		} else {
			name = `\\?\` + name
		}
	}
	return syscall.UTF16PtrFromString(name)
}

func openQuarantineSource(path string, remove bool) (*quarantineSource, error) {
	wide, err := windowsPathUTF16(path)
	if err != nil {
		return nil, err
	}
	open := func(access, sharing uint32) (syscall.Handle, error) {
		return syscall.CreateFile(wide, access, sharing, nil, syscall.OPEN_EXISTING,
			syscall.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	}
	var handle syscall.Handle
	var removeErr error
	if remove {
		// Deny new writes and renames while this handle authorizes deletion.
		handle, removeErr = open(syscall.GENERIC_READ|deleteAccess, syscall.FILE_SHARE_READ)
	}
	if !remove || removeErr != nil {
		// A busy or read-only source can still be copied into the vault.
		handle, err = open(syscall.GENERIC_READ, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE)
		if err != nil {
			return nil, err
		}
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
	return &quarantineSource{path: path, file: os.NewFile(uintptr(handle), path), removeErr: removeErr}, nil
}

func (s *quarantineSource) close() {
	if s.file != nil {
		s.file.Close()
	}
}

func IsStagingDir(string) bool  { return false }
func IsStagingFile(string) bool { return false }

func (s *quarantineSource) remove(info os.FileInfo, size int64, digest [sha256.Size]byte) error {
	if s.removeErr != nil {
		return fmt.Errorf("quarantine: could not obtain a delete-capable handle: %w", s.removeErr)
	}
	current, err := s.file.Stat()
	if err != nil {
		return err
	}
	if !sameFile(current, info, size) {
		return fmt.Errorf("%w: %s changed after it was read", ErrPathChanged, s.path)
	}
	if err := verifySourceBytes(s.file, s.path, size, digest); err != nil {
		return err
	}

	// FILE_DISPOSITION_INFO contains a single BOOLEAN. Passing it to the
	// kernel marks only the file attached to this handle for deletion.
	deleteFile := uint8(1)
	result, _, callErr := setFileInformationByHandle.Call(s.file.Fd(), fileDispositionInfo,
		uintptr(unsafe.Pointer(&deleteFile)), unsafe.Sizeof(deleteFile)) // audit:ok passes a live one-byte Win32 structure synchronously
	if result == 0 {
		return fmt.Errorf("quarantine: set file disposition: %w", callErr)
	}
	err = s.file.Close()
	s.file = nil
	return err
}
