//go:build linux || darwin

package inventory

import (
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"syscall"
	"time"

	"github.com/s-b-repo/cau/internal/safefs"
)

const maxQueryBytes = 8 << 20

func runQuery(ctx context.Context, limit int, in io.Reader, executable string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, executable, args...)
	cmd.Env = []string{"LC_ALL=C", "PATH=/usr/bin:/bin:/usr/sbin:/sbin"}
	cmd.WaitDelay = time.Second
	out := &queryOutput{limit: limit}
	cmd.Stdout = out
	cmd.Stdin = in
	err := cmd.Run()
	if out.overflow {
		return nil, safefs.ErrTooLarge
	}
	if err != nil {
		return nil, err
	}
	return out.buffer.Bytes(), nil
}

type queryOutput struct {
	buffer   bytes.Buffer
	limit    int
	overflow bool
}

func (b *queryOutput) Write(p []byte) (int, error) {
	if len(p) > b.limit-b.buffer.Len() {
		b.overflow = true
		return 0, safefs.ErrTooLarge
	}
	return b.buffer.Write(p)
}

func readRootFile(root *os.Root, path string, limit int64) ([]byte, error) {
	f, err := root.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, safefs.ErrNotRegular
	}
	return safefs.ReadAll(f, info, limit)
}
