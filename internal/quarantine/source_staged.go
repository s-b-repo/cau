//go:build (linux || darwin) && cgo

package quarantine

/*
#define _GNU_SOURCE
#include <fcntl.h>
#include <unistd.h>
#ifdef __linux__
#include <sys/syscall.h>
#endif
#include <sys/stat.h>
#include <limits.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef __APPLE__
#define CAU_DIRECTORY_FLAGS (O_RDONLY | O_DIRECTORY)
#define CAU_INSPECT_FLAGS (O_EVTONLY | O_NONBLOCK)
#else
#define CAU_DIRECTORY_FLAGS (O_PATH | O_DIRECTORY)
#define CAU_INSPECT_FLAGS O_PATH
#endif

static int cau_openat(int fd, const char *name, int flags) {
	return openat(fd, name, flags);
}

static int cau_rename_noreplace(int src, const char *name, int dst, const char *slot) {
#ifdef __APPLE__
	return renameatx_np(src, name, dst, slot, RENAME_EXCL);
#elif defined(SYS_renameat2)
	return syscall(SYS_renameat2, src, name, dst, slot, RENAME_NOREPLACE);
#else
	errno = ENOSYS;
	return -1;
#endif
}
*/
import "C"

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"github.com/s-b-repo/cau/internal/safefs"
)

type quarantineSource struct {
	path   string
	parent *os.File
	file   *os.File
}

func openQuarantineSource(path string, _ bool) (*quarantineSource, error) {
	// The path has been resolved and checked against the protected path
	// policy. Refuse any symlink that appeared since that resolution.
	parent, err := os.OpenFile("/", C.CAU_DIRECTORY_FLAGS, 0)
	if err != nil {
		return nil, err
	}
	for component := range strings.SplitSeq(strings.Trim(filepath.Dir(path), "/"), "/") {
		if component == "" {
			continue
		}
		next, err := openRelative(parent, component, C.CAU_DIRECTORY_FLAGS)
		parent.Close()
		if err != nil {
			return nil, err
		}
		parent = next
	}
	file, err := openRelative(parent, filepath.Base(path), syscall.O_RDONLY|syscall.O_NONBLOCK)
	if err != nil {
		parent.Close()
		return nil, err
	}
	return &quarantineSource{path: path, parent: parent, file: file}, nil
}

func (s *quarantineSource) close() {
	s.file.Close()
	s.parent.Close()
}

func openRelative(dir *os.File, name string, flags int) (*os.File, error) {
	leaf := C.CString(name)
	defer C.free(unsafe.Pointer(leaf)) // audit:ok frees the allocation returned by C.CString
	fd, err := C.cau_openat(C.int(dir.Fd()), leaf, C.int(flags|syscall.O_NOFOLLOW|syscall.O_CLOEXEC))
	if fd < 0 {
		if errors.Is(err, syscall.ELOOP) {
			return nil, fmt.Errorf("%w: %s", safefs.ErrNotRegular, name)
		}
		return nil, err
	}
	return os.NewFile(uintptr(fd), name), nil
}

// The parent may be on another filesystem than the vault. Keep a private
// staging directory on that filesystem. Its descriptor stays valid even if
// someone moves or replaces the directory's name.
func openStage(parent *os.File) (*os.File, error) {
	name := stageDirName()
	leaf := C.CString(name)
	defer C.free(unsafe.Pointer(leaf)) // audit:ok frees the allocation returned by C.CString
	if rc, err := C.mkdirat(C.int(parent.Fd()), leaf, 0o700); rc != 0 && !errors.Is(err, syscall.EEXIST) {
		return nil, err
	}
	stage, err := openRelative(parent, name, C.CAU_DIRECTORY_FLAGS)
	if err != nil {
		return nil, err
	}
	info, err := stage.Stat()
	if err != nil {
		stage.Close()
		return nil, err
	}
	if !ownsPrivateDir(info) {
		stage.Close()
		return nil, fmt.Errorf("quarantine: %s must be private and owned by the vault process", name)
	}
	return stage, nil
}

func stageDirName() string { return ".cau-quarantine-" + strconv.Itoa(os.Geteuid()) }

func ownsPrivateDir(info os.FileInfo) bool {
	return info.IsDir() && info.Mode().Perm() == 0o700 && info.Sys().(*syscall.Stat_t).Uid == uint32(os.Geteuid())
}

// IsStagingDir identifies only a staging directory accessible to this process's
// owner. A lookalike directory controlled by another user is still scanned.
func IsStagingDir(path string) bool {
	if filepath.Base(path) != stageDirName() {
		return false
	}
	info, err := os.Lstat(path)
	return err == nil && ownsPrivateDir(info)
}

// IsStagingFile reports whether path is a staged entry emitted by a file watch.
func IsStagingFile(path string) bool {
	if !strings.Contains(path, stageDirName()+string(os.PathSeparator)) {
		return false
	}
	for dir := filepath.Dir(path); ; dir = filepath.Dir(dir) {
		if IsStagingDir(dir) {
			return true
		}
		if filepath.Dir(dir) == dir {
			return false
		}
	}
}

func renameNoReplace(from *os.File, name string, to *os.File, slot string) error {
	src, dst := C.CString(name), C.CString(slot)
	defer C.free(unsafe.Pointer(src)) // audit:ok frees the allocation returned by C.CString
	defer C.free(unsafe.Pointer(dst)) // audit:ok frees the allocation returned by C.CString
	if rc, err := C.cau_rename_noreplace(C.int(from.Fd()), src, C.int(to.Fd()), dst); rc != 0 {
		return err
	}
	return nil
}

func (s *quarantineSource) remove(info os.FileInfo, size int64, digest [sha256.Size]byte) error {
	return s.removeWithRename(info, size, digest, renameNoReplace)
}

// A rename atomically takes custody of whatever currently owns the source
// name. Verify that object inside the private directory before unlinking it.
func (s *quarantineSource) removeWithRename(info os.FileInfo, size int64, digest [sha256.Size]byte, rename func(*os.File, string, *os.File, string) error) error {
	base := filepath.Base(s.path)
	current, err := s.file.Stat()
	if err != nil {
		return err
	}
	if !sameFile(current, info, size) || sourceChanged(current, info) {
		return fmt.Errorf("%w: %s changed after it was read", ErrPathChanged, s.path)
	}

	stage, err := openStage(s.parent)
	if err != nil {
		return fmt.Errorf("quarantine: open staging directory: %w", err)
	}
	defer stage.Close()
	slot, err := randomHex(16)
	if err != nil {
		return err
	}
	if err := rename(s.parent, base, stage, slot); err != nil {
		return fmt.Errorf("quarantine: stage source: %w", err)
	}
	if err = s.verifyStaged(stage, slot, info, size, digest); err == nil {
		err = unlinkStaged(stage, slot)
		if err == nil {
			return nil
		}
	}
	// Rollback never replaces an entry that appeared at the source name. If
	// rollback fails, the staged object stays intact for manual recovery.
	if restoreErr := renameNoReplace(stage, slot, s.parent, base); restoreErr != nil {
		dir := stagePath(stage)
		if dir == "" {
			dir = filepath.Join(filepath.Dir(s.path), stage.Name())
		}
		return errors.Join(err, fmt.Errorf("could not restore %s: %w (preserved at %s)", s.path, restoreErr, filepath.Join(dir, slot)))
	}
	return err
}

func (s *quarantineSource) verifyStaged(stage *os.File, slot string, info os.FileInfo, size int64, digest [sha256.Size]byte) error {
	staged, err := openRelative(stage, slot, C.CAU_INSPECT_FLAGS)
	if err != nil {
		return fmt.Errorf("%w: could not verify staged name for %s: %w", ErrPathChanged, s.path, err)
	}
	defer staged.Close()
	stat, err := staged.Stat()
	if err != nil {
		return err
	}
	if !sameFile(stat, info, size) {
		return fmt.Errorf("%w: %s was replaced before staging", ErrPathChanged, s.path)
	}
	return verifySourceBytes(s.file, s.path, size, digest)
}

func unlinkStaged(stage *os.File, slot string) error {
	leaf := C.CString(slot)
	defer C.free(unsafe.Pointer(leaf)) // audit:ok frees the allocation returned by C.CString
	if rc, err := C.unlinkat(C.int(stage.Fd()), leaf, 0); rc != 0 {
		return err
	}
	return nil
}
