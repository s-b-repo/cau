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

	"github.com/s-b-repo/cau/internal/posture"
	"github.com/s-b-repo/cau/internal/report"
)

func cmdPosture(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("posture", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprint(stderr, `Usage: cau posture [flags]

Read the application firewall and FileVault on macOS, or Windows Firewall and
BitLocker on Windows. This command reports settings without modifying them.

Flags:
  --format <fmt>   text or json (default text)

Exit codes: 0 settings observed, 2 incomplete or unsupported, 3 output error,
4 usage.
`)
	}
	format := fs.String("format", "text", "output format: text or json")
	if err := fs.Parse(interspersed(fs, args)); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return report.ExitOK
		}
		return report.ExitUsage
	}
	if fs.NArg() != 0 || (*format != "text" && *format != "json") {
		fs.Usage()
		return report.ExitUsage
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM) // audit:ok standalone CLI context cancelled by signals
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	settings := posture.Read(ctx)
	var err error
	if *format == "json" {
		err = writeJSON(stdout, settings)
	} else {
		var output strings.Builder
		fmt.Fprintf(&output, "Firewall %s (%s)\n", settings.Firewall.Status, settings.Firewall.Source)
		for _, profile := range settings.Firewall.Profiles {
			fmt.Fprintf(&output, "  %s enabled=%t\n", profile.Name, profile.Enabled)
		}
		disk := settings.DiskEncryption
		fmt.Fprintf(&output, "Disk encryption %s (%s)\n  protection=%s volume=%s\n",
			disk.Status, disk.Source, disk.Protection, disk.Volume)
		_, err = io.WriteString(stdout, output.String())
	}
	if err != nil {
		return fail(stderr, report.ExitRunFailed, "write security posture: %v", err)
	}
	if !settings.Complete() {
		return report.ExitScanFailed
	}
	return report.ExitOK
}
