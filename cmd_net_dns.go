package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/s-b-repo/cau/internal/netscan"
	"github.com/s-b-repo/cau/internal/report"
)

func cmdNetDNS(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("net dns", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprint(stderr, `Usage: cau net dns [flags]

Read local resolver configuration and compare its addresses with an optional
policy. This command reads local configuration and sends no DNS traffic.

Flags:
  --format <fmt>   text or json (default text)
  --expect <ip>    expected nameserver address, repeat for multiple addresses
  --scope <scope>  client or Linux systemd-upstream (default client)
  --etc-root <dir> override /etc (testing)
  --run-root <dir> override /run (testing)

Exit codes: 0 complete, 1 policy drift, 2 incomplete or unsupported,
3 output error, 4 usage.
`)
	}
	format := fs.String("format", "text", "output format: text or json")
	scope := fs.String("scope", netscan.DNSClientScope, "policy comparison scope")
	etc := fs.String("etc-root", "", "override /etc (testing)")
	run := fs.String("run-root", "", "override /run (testing)")
	var expected []string
	fs.Func("expect", "expected nameserver address (repeatable)", func(raw string) error {
		address, ok := netscan.DNSAddress(raw)
		if !ok {
			return errors.New("expected a literal IPv4 or IPv6 address")
		}
		expected = append(expected, address)
		return nil
	})
	if err := fs.Parse(interspersed(fs, args)); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return report.ExitOK
		}
		return report.ExitUsage
	}
	if fs.NArg() != 0 || (*format != "text" && *format != "json") ||
		(*scope != netscan.DNSClientScope && *scope != netscan.DNSUpstreamScope) ||
		(*scope != netscan.DNSClientScope && len(expected) == 0) {
		fs.Usage()
		return report.ExitUsage
	}
	var result netscan.DNSPosture
	if (runtime.GOOS == "linux" && (*etc != "" || *run != "")) || (*etc != "" && *run != "") {
		result = netscan.ReadDNSPosture(*etc, *run)
	} else {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM) // audit:ok standalone CLI context cancelled by signals
		defer stop()
		ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		result = netscan.ReadHostDNSPosture(ctx)
	}
	if len(expected) != 0 {
		result.Compare(*scope, expected)
	}
	var err error
	if *format == "json" {
		err = writeJSON(stdout, result)
	} else {
		var out strings.Builder
		writeDNSResolverStatus(&out, result.Client)
		fmt.Fprintf(&out, "Local resolver setting %s\n", result.Stub)
		if result.Upstreams != nil {
			writeDNSResolverStatus(&out, *result.Upstreams)
		}
		if check := result.Policy; check != nil {
			fmt.Fprintf(&out, "Policy %s (%s)\n", check.Status, check.Scope)
			if len(check.Missing) != 0 {
				fmt.Fprintf(&out, "  Missing %s\n", report.TermSafe(strings.Join(check.Missing, ", ")))
			}
			if len(check.Unexpected) != 0 {
				fmt.Fprintf(&out, "  Unexpected %s\n", report.TermSafe(strings.Join(check.Unexpected, ", ")))
			}
		}
		_, err = io.WriteString(stdout, out.String())
	}
	if err != nil {
		return fail(stderr, report.ExitRunFailed, "write resolver posture: %v", err)
	}
	if result.Policy != nil && result.Policy.Status == "drift" {
		return report.ExitThreat
	}
	if !result.Complete() || (result.Policy != nil && result.Policy.Status == "unknown") {
		return report.ExitScanFailed
	}
	return report.ExitOK
}

func writeDNSResolverStatus(out *strings.Builder, source netscan.DNSResolverSource) {
	fmt.Fprintf(out, "%s %s\n", source.Path, source.Status)
	if source.Reason != "" {
		fmt.Fprintln(out, source.Reason)
	}
	for _, address := range source.Nameservers {
		fmt.Fprintf(out, "  %s\n", report.TermSafe(address))
	}
}
