package nativecmd

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"path/filepath"
	"syscall"
	"unicode/utf16"
	"unsafe"
)

var getSystemDirectory = syscall.NewLazyDLL("kernel32.dll").NewProc("GetSystemDirectoryW")

// PowerShell runs a fixed script with the system's copy of Windows PowerShell.
func PowerShell(ctx context.Context, script string) ([]byte, bool, error) {
	var buffer [32768]uint16
	n, _, _ := getSystemDirectory.Call(uintptr(unsafe.Pointer(&buffer[0])), uintptr(len(buffer))) // audit:ok synchronous Win32 call with a UTF-16 array and its character count
	if n == 0 || n >= uintptr(len(buffer)) {
		return nil, false, errors.New("Windows system directory could not be located")
	}
	systemDir := syscall.UTF16ToString(buffer[:n])
	powershellDir := filepath.Join(systemDir, "WindowsPowerShell", "v1.0")
	env := []string{"SystemRoot=" + filepath.Dir(systemDir), "PATH=" + systemDir, "PSModulePath=" + filepath.Join(powershellDir, "Modules")}
	command := utf16.Encode([]rune(script))
	encoded := make([]byte, len(command)*2)
	for i, ch := range command {
		binary.LittleEndian.PutUint16(encoded[2*i:], ch)
	}
	return run(ctx, filepath.Join(powershellDir, "powershell.exe"), env, nil, false,
		"-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", base64.StdEncoding.EncodeToString(encoded))
}
