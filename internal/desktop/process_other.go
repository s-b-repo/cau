//go:build !windows && !darwin

package desktop

import "context"

func readProcesses(context.Context) ProcessSnapshot {
	return ProcessSnapshot{Source: "unsupported", Unavailable: true, Warnings: []string{"no native process provider for this OS"}}
}
