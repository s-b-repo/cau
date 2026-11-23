//go:build !windows && !darwin

package persist

import "context"

func readNativeStartup(context.Context) startupSnapshot {
	return startupSnapshot{source: "unsupported", incomplete: []string{"no native startup provider for this OS"}}
}
