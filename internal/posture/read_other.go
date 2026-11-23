//go:build !windows && !darwin

package posture

import (
	"context"
	"runtime"
)

func read(context.Context) Report {
	return newReport(runtime.GOOS, "none", "none", unsupported)
}
