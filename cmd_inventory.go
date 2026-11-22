package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/s-b-repo/cau/internal/inventory"
	"github.com/s-b-repo/cau/internal/report"
)

func cmdInventory(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("inventory", flag.ContinueOnError)
	fs.SetOutput(stderr)
	format := fs.String("format", "text", "output format: text or json")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: cau inventory [--format text|json]")
		fmt.Fprintln(stderr, "Report registered system software from local package and installer records.")
		fmt.Fprintln(stderr, "Exit codes: 0 complete, 2 incomplete or unavailable, 3 failed, 4 usage.")
	}
	if err := fs.Parse(interspersed(fs, args)); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return report.ExitOK
		}
		return report.ExitUsage
	}
	if fs.NArg() > 0 || (*format != "text" && *format != "json") {
		fs.Usage()
		return report.ExitUsage
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM) // audit:ok standalone CLI root context, cancelled by signals
	defer stop()
	snapshot := inventory.Collect(ctx)
	var err error
	if *format == "json" {
		err = writeJSON(stdout, snapshot)
	} else {
		err = writeInventoryText(stdout, snapshot)
	}
	if err != nil {
		return fail(stderr, report.ExitRunFailed, "write inventory: %v", err)
	}
	if !snapshot.Complete() {
		return report.ExitScanFailed
	}
	return report.ExitOK
}

func writeInventoryText(w io.Writer, s inventory.Snapshot) error {
	if _, err := fmt.Fprintf(w, "Software inventory for %s at %s\n", s.OS, s.ObservedAt.Format(time.RFC3339)); err != nil {
		return err
	}
	for _, c := range s.Collections {
		if _, err := fmt.Fprintf(w, "%s (%s) %s, %d records\n", c.Provider, c.Scope, c.Status, len(c.Packages)); err != nil {
			return err
		}
		if c.Reason != "" {
			if _, err := fmt.Fprintln(w, c.Reason); err != nil {
				return err
			}
		}
		for _, pkg := range c.Packages {
			if _, err := fmt.Fprintf(w, "  %s\t%s\t%s\n", report.TermSafe(pkg.ID), report.TermSafe(pkg.Name), report.TermSafe(pkg.Version)); err != nil {
				return err
			}
		}
	}
	return nil
}
