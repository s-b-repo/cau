package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/s-b-repo/cau/internal/patches"
	"github.com/s-b-repo/cau/internal/report"
)

func cmdPatches(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("patches", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprint(stderr, `Usage: cau patches [flags]

Report OS update and restart readiness from local evidence. On APT systems,
list upgrades from an ordinary upgrade simulation using the cached indexes.

Flags:
  --format <fmt>  text or json (default text)

Exit codes: 0 complete assessment, 2 incomplete or unsupported, 3 output error,
4 usage. Check the restart and metadata states separately.
`)
	}
	format := fs.String("format", "text", "output format: text or json")
	if err := fs.Parse(interspersed(fs, args)); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return report.ExitOK
		}
		return report.ExitUsage
	}
	if *format != "text" && *format != "json" {
		return fail(stderr, report.ExitUsage, "--format must be text or json")
	}
	if fs.NArg() != 0 {
		return fail(stderr, report.ExitUsage, "patches accepts no positional arguments")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM) // audit:ok standalone CLI root context, cancelled by signals
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, patches.Timeout)
	defer cancel()
	return writePatchAssessment(stdout, stderr, *format, patches.Assess(ctx))
}

func writePatchAssessment(stdout, stderr io.Writer, format string, result patches.Assessment) int {
	var err error
	if format == "json" {
		err = writeJSON(stdout, result)
	} else {
		var text strings.Builder
		fmt.Fprintf(&text, "OS %s\n", strings.TrimSpace(result.OS.ID+" "+result.OS.Version+" "+result.OS.Build))
		fmt.Fprintf(&text, "Assessment %s (%s) at %s\n", result.AssessmentStatus, result.Source, result.ObservedAt.Format(time.RFC3339))
		fmt.Fprintf(&text, "Metadata %s", result.Metadata.Status)
		if result.Metadata.OldestIndexAt != nil {
			fmt.Fprintf(&text, " (oldest known index %s)", result.Metadata.OldestIndexAt.Format(time.RFC3339))
		}
		if result.Metadata.LastSuccessfulSearchAt != nil {
			fmt.Fprintf(&text, " (last successful Automatic Updates search %s)", result.Metadata.LastSuccessfulSearchAt.Format(time.RFC3339))
		}
		fmt.Fprintln(&text)
		if result.AssessedAt != nil {
			fmt.Fprintf(&text, "Updates reported %d\n", len(result.Updates))
		}
		if result.DeferredUpdates != nil {
			fmt.Fprintf(&text, "Deferred by APT %d\n", *result.DeferredUpdates)
		}
		for _, update := range result.Updates {
			if update.Revision > 0 {
				fmt.Fprintf(&text, "  %s revision %d\n", update.ID, update.Revision)
			} else {
				fmt.Fprintf(&text, "  %s [%s] %s -> %s\n", update.ID, update.Architecture, update.InstalledVersion, update.CandidateVersion)
			}
		}
		fmt.Fprintf(&text, "Restart %s (%s)\n", result.Restart.State, result.Restart.Reason)
		for _, warning := range result.Warnings {
			fmt.Fprintf(&text, "  [note] %s\n", warning)
		}
		_, err = io.WriteString(stdout, text.String())
	}
	if err != nil {
		return fail(stderr, report.ExitRunFailed, "write patch assessment: %v", err)
	}
	if result.AssessmentStatus != patches.Complete {
		return report.ExitScanFailed
	}
	return report.ExitOK
}
