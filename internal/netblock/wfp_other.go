//go:build !windows || !cgo

package netblock

import "errors"

func openWFP() (filterSession, error) {
	return nil, errors.New("Windows Filtering Platform requires a Windows cgo build")
}

func windowsProtectedAddresses() ([]string, error) {
	return nil, errors.New("Windows protected peers are unavailable on this build")
}
