//go:build !cgo

package desktop

import "errors"

func processImage(int) string    { return "" }
func processIDs() []int          { return nil }
func processCreation(int) uint64 { return 0 }

func TerminateMacProcess(int, uint64, string) error {
	return errors.New("macOS process termination requires a cgo build")
}
