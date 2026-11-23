//go:build !linux

package scanner

import "os"

func fileChangeTime(os.FileInfo) int { return 0 }
