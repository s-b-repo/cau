// Package nativecmd runs fixed platform utilities with bounded output.
package nativecmd

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os/exec"
	"time"
)

// Unix runs an absolute system path with a fixed locale and search path.
func Unix(ctx context.Context, path string, args ...string) ([]byte, bool, error) {
	return run(ctx, path, unixEnvironment(), nil, false, args...)
}

// UnixInput passes bounded input to an absolute system utility.
func UnixInput(ctx context.Context, input io.Reader, path string, args ...string) ([]byte, bool, error) {
	return run(ctx, path, unixEnvironment(), input, false, args...)
}

// UnixCombined is for tools that report results on both output streams.
func UnixCombined(ctx context.Context, path string, args ...string) ([]byte, error) {
	output, _, err := run(ctx, path, unixEnvironment(), nil, true, args...)
	return output, err
}

func unixEnvironment() []string {
	return []string{"LC_ALL=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
}

func run(ctx context.Context, path string, env []string, input io.Reader, combined bool, args ...string) ([]byte, bool, error) {
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Env = env
	cmd.Stdin = input
	cmd.WaitDelay = time.Second
	stdout, stderr := limitedBuffer{limit: 4 << 20}, limitedBuffer{limit: 4 << 10}
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if combined {
		cmd.Stderr = &stdout
	}
	err := cmd.Run()
	if stdout.truncated || stderr.truncated {
		return nil, true, errors.New("native output exceeded collection limit")
	}
	return stdout.buffer.Bytes(), len(bytes.TrimSpace(stderr.buffer.Bytes())) != 0, err
}

type limitedBuffer struct {
	buffer    bytes.Buffer
	limit     int
	truncated bool
}

func (b *limitedBuffer) Write(data []byte) (int, error) {
	n := len(data)
	if remaining := b.limit - b.buffer.Len(); n > remaining {
		b.truncated = true
		data = data[:remaining]
	}
	_, err := b.buffer.Write(data)
	return n, err
}
