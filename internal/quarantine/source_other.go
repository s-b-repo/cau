//go:build !windows && (!cgo || (!linux && !darwin))

package quarantine

import (
	"crypto/sha256"
	"os"

	"github.com/s-b-repo/cau/internal/safefs"
)

type quarantineSource struct {
	file *os.File
}

func openQuarantineSource(path string, _ bool) (*quarantineSource, error) {
	file, _, err := safefs.OpenNoFollow(path)
	if err != nil {
		return nil, err
	}
	return &quarantineSource{file: file}, nil
}

func (s *quarantineSource) close() { s.file.Close() }

func IsStagingDir(string) bool  { return false }
func IsStagingFile(string) bool { return false }

func (*quarantineSource) remove(os.FileInfo, int64, [sha256.Size]byte) error {
	return ErrSafeRemovalUnavailable
}
