package persist

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/s-b-repo/cau/internal/nativecmd"
	"github.com/s-b-repo/cau/internal/parallel"
	"github.com/s-b-repo/cau/internal/safefs"
)

const maxLaunchJobsPerRoot = 512

func readNativeStartup(ctx context.Context) startupSnapshot {
	result := startupSnapshot{source: "macos-launchd-plists"}
	dirs := []string{"/Library/LaunchDaemons", "/Library/LaunchAgents"}
	home, err := os.UserHomeDir()
	if err == nil {
		dirs = append(dirs, filepath.Join(home, "Library", "LaunchAgents"))
	} else {
		result.incomplete = append(result.incomplete, "current account LaunchAgents")
	}
	for _, path := range dirs {
		rows, incomplete := launchdDirectory(ctx, path)
		result.entries = append(result.entries, rows...)
		result.incomplete = append(result.incomplete, incomplete...)
	}
	return result
}

func launchdDirectory(ctx context.Context, path string) ([]nativeStartup, []string) {
	root, err := os.OpenRoot(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, []string{path}
	}
	defer root.Close()
	dir, err := root.Open(".")
	if err != nil {
		return nil, []string{path}
	}
	defer dir.Close()
	entries, err := dir.ReadDir(maxLaunchJobsPerRoot + 1)
	var incomplete []string
	if (err != nil && !errors.Is(err, io.EOF)) || len(entries) > maxLaunchJobsPerRoot {
		incomplete = append(incomplete, path)
		entries = entries[:min(len(entries), maxLaunchJobsPerRoot)]
	}
	var names []string
	for _, entry := range entries {
		if !strings.EqualFold(filepath.Ext(entry.Name()), ".plist") {
			continue
		}
		if !entry.Type().IsRegular() {
			incomplete = append(incomplete, filepath.Join(path, entry.Name()))
			continue
		}
		names = append(names, entry.Name())
	}
	rows := make([]nativeStartup, len(names))
	parallel.For(len(names), 4, func(i int) {
		if ctx.Err() == nil {
			rows[i] = launchJob(ctx, root, path, names[i])
		}
	})
	valid := rows[:0]
	for i, row := range rows {
		if row.Path == "" {
			incomplete = append(incomplete, filepath.Join(path, names[i]))
			continue
		}
		valid = append(valid, row)
	}
	return valid, incomplete
}

func launchJob(ctx context.Context, root *os.Root, dir, name string) nativeStartup {
	file, err := root.OpenFile(name, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nativeStartup{}
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nativeStartup{}
	}
	data, err := safefs.ReadAll(file, info, maxFileBytes)
	if err != nil {
		return nativeStartup{}
	}
	out, warned, err := nativecmd.UnixInput(ctx, bytes.NewReader(data), "/usr/bin/plutil", "-convert", "json", "-o", "-", "-")
	if err != nil || warned {
		return nativeStartup{}
	}
	row, err := parseLaunchJob(out)
	if err != nil {
		return nativeStartup{}
	}
	row.Path = filepath.Join(dir, name)
	if filepath.Base(dir) == "LaunchDaemons" {
		row.Technique = "T1543.004"
	}
	return row
}
