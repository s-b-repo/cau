package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/s-b-repo/cau/internal/netblock"
	"github.com/s-b-repo/cau/internal/report"
)

func runService(args []string) (int, bool) {
	if len(args) == 0 || args[0] != "--macos-firewall-service" {
		return 0, false
	}
	if len(args) != 1 {
		return report.ExitUsage, true
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM) // audit:ok launchd service context cancelled on shutdown
	defer stop()
	if err := netblock.RunPFBroker(ctx); err != nil {
		return fail(os.Stderr, report.ExitRunFailed, "macOS firewall service: %v", err), true
	}
	return report.ExitOK, true
}
