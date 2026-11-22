//go:build !windows

package patches

import "context"

func collectWindows(context.Context, *Assessment) {}
