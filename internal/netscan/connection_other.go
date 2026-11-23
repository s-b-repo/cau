//go:build !windows && !darwin

package netscan

import "context"

func nativeConnections(context.Context) connectionSnapshot {
	return connectionSnapshot{source: "unsupported", coverage: "unsupported", warnings: []string{"no native connection provider for this OS"}}
}
