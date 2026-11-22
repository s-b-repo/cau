package inventory

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"syscall"
	"unsafe"
)

func platformCollections(ctx context.Context) []Collection {
	return []Collection{
		windowsUninstall(ctx, "windows-uninstall-64", syscall.KEY_WOW64_64KEY),
		windowsUninstall(ctx, "windows-uninstall-32", syscall.KEY_WOW64_32KEY),
	}
}

func windowsUninstall(ctx context.Context, provider string, view uint32) Collection {
	const uninstall = `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`
	const noMoreItems = syscall.Errno(259)
	c := collection(provider, "system")
	key, err := openRegistry(syscall.HKEY_LOCAL_MACHINE, uninstall, view|syscall.KEY_ENUMERATE_SUB_KEYS|syscall.KEY_QUERY_VALUE)
	if errors.Is(err, syscall.ERROR_FILE_NOT_FOUND) {
		return c
	}
	if err != nil {
		c.fail(err, "uninstall registry view could not be opened")
		return c
	}
	defer syscall.RegCloseKey(key)
	var stamp syscall.Filetime
	if err := syscall.RegQueryInfoKey(key, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, &stamp); err != nil {
		c.fail(err, "uninstall registry view could not be inspected")
		return c
	}
	var incomplete error
	var name [256]uint16
	for i := uint32(0); ; i++ {
		if err := ctx.Err(); err != nil {
			c.fail(err, "uninstall registry collection was interrupted")
			return c
		}
		size := uint32(len(name))
		err := syscall.RegEnumKeyEx(key, i, &name[0], &size, nil, nil, nil, nil)
		if errors.Is(err, noMoreItems) {
			break
		}
		if err != nil || i == maxPackages {
			c.fail(err, "uninstall registry enumeration did not finish within the entry limit")
			return c
		}
		pkg, err := windowsPackage(key, view, syscall.UTF16ToString(name[:size]))
		if err != nil {
			incomplete = err
			continue
		}
		if pkg.ID != "" {
			c.Packages = append(c.Packages, pkg)
		}
	}
	var after syscall.Filetime
	if err := syscall.RegQueryInfoKey(key, nil, nil, nil, nil, nil, nil, nil, nil, nil, nil, &after); err != nil || after != stamp {
		c.fail(err, "uninstall registry view changed during collection")
		return c
	}
	if incomplete != nil {
		c.fail(incomplete, "some uninstall registry records could not be read or validated")
	}
	return c
}

func openRegistry(parent syscall.Handle, name string, flags uint32) (syscall.Handle, error) {
	p, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return 0, err
	}
	var key syscall.Handle
	err = syscall.RegOpenKeyEx(parent, p, 0, flags, &key)
	return key, err
}

func windowsPackage(parent syscall.Handle, view uint32, entry string) (Package, error) {
	key, err := openRegistry(parent, entry, view|syscall.KEY_QUERY_VALUE)
	if err != nil {
		return Package{}, err
	}
	defer syscall.RegCloseKey(key)
	name, err := registryString(key, "DisplayName")
	if err != nil || name == "" {
		return Package{}, err
	}
	version, err := registryString(key, "DisplayVersion")
	if err != nil {
		return Package{}, err
	}
	// Uninstall keys are case insensitive. A digest gives them a stable ID
	// even when a publisher chose a path or other free-form text for its key.
	id := sha256.Sum256([]byte(strings.ToLower(entry)))
	return Package{ID: "arp:" + hex.EncodeToString(id[:]), Name: name, Version: version}, nil
}

func registryString(key syscall.Handle, name string) (string, error) {
	p, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return "", err
	}
	var data [maxFieldBytes + 1]uint16
	var kind uint32
	size := uint32(len(data) * 2)
	err = syscall.RegQueryValueEx(key, p, nil, &kind, (*byte)(unsafe.Pointer(&data[0])), &size) // audit:ok synchronous byte buffer with its byte length
	if errors.Is(err, syscall.ERROR_FILE_NOT_FOUND) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if (kind != syscall.REG_SZ && kind != syscall.REG_EXPAND_SZ) || size%2 != 0 || size > uint32(len(data)*2) {
		return "", errors.New("invalid registry string")
	}
	value := syscall.UTF16ToString(data[:size/2])
	if value != "" && !validInventoryField(value) {
		return "", errors.New("invalid uninstall metadata")
	}
	return value, nil
}
