//go:build !windows && !darwin

package procscan

import "errors"

func terminateDesktop(Process) error {
	return errors.New("native process termination is unavailable on this platform")
}
