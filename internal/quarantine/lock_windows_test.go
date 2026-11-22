package quarantine

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

func TestWindowsVaultLockAcrossProcesses(t *testing.T) {
	const fixturePath = "CAU_TEST_WINDOWS_VAULT_LOCK_PATH"
	const fixtureMode = "CAU_TEST_WINDOWS_VAULT_LOCK_MODE"
	if path := os.Getenv(fixturePath); path != "" {
		if os.Getenv(fixtureMode) == "contend" {
			verifyContendedWindowsLock(t, path)
			return
		}
		unlock, err := lockFile(path)
		if err != nil {
			t.Fatal(err)
		}
		unlock()
		return
	}

	path := filepath.Join(t.TempDir(), "vault-with-unicode-ç", lockName)
	if err := os.Mkdir(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	unlock, err := lockFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if unlock != nil {
			unlock()
		}
	}()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	runChild := func(mode string) {
		t.Helper()
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, self, "-test.run=^TestWindowsVaultLockAcrossProcesses$")
		cmd.Env = append(os.Environ(), fixturePath+"="+path, fixtureMode+"="+mode)
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%s child: %v\n%s", mode, err, output)
		}
	}
	runChild("contend")
	unlock()
	unlock = nil
	runChild("acquire")
}

func verifyContendedWindowsLock(t *testing.T, path string) {
	t.Helper()
	wide, err := windowsPathUTF16(path)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := syscall.CreateFile(wide, syscall.GENERIC_READ|syscall.GENERIC_WRITE,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE, nil, syscall.OPEN_EXISTING, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.CloseHandle(handle)

	const (
		failImmediately    = 1
		errorLockViolation = syscall.Errno(33)
	)
	var region syscall.Overlapped
	locked, _, lockErr := lockFileEx.Call(uintptr(handle), lockFileExclusive|failImmediately, 0, 1, 0,
		uintptr(unsafe.Pointer(&region))) // audit:ok Win32 uses this structure synchronously
	if locked != 0 || !errors.Is(lockErr, errorLockViolation) {
		t.Fatalf("contender locked=%d err=%v, want lock violation", locked, lockErr)
	}
	if err := os.Remove(path); err == nil {
		t.Fatal("lock file was removable through a different process")
	}
}
