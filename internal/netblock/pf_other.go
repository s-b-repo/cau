//go:build !darwin || !cgo

package netblock

import (
	"context"
	"errors"
)

func openPF() (peerLeases, []string, error) {
	return nil, nil, errors.New("macOS PF response requires a macOS cgo build")
}

func RunPFBroker(context.Context) error {
	return errors.New("macOS firewall service requires a macOS cgo build")
}
