package persist

import (
	"context"
	"encoding/json"
	"path/filepath"
	"runtime"
	"slices"
	"strings"

	"github.com/s-b-repo/cau/internal/desktop"
	"github.com/s-b-repo/cau/scanner/tradecraft"
)

const (
	nativeStartupLimit        = 8192
	nativeStartupCommandLimit = 16384
)

type nativeStartup struct {
	Path       string `json:"path"`
	Technique  string `json:"technique"`
	Command    string `json:"command"`
	Executable string `json:"executable"`
}

type startupSnapshot struct {
	source     string
	entries    []nativeStartup
	incomplete []string
}

func scanDesktop(opts Options, threshold int) *Result {
	parent := opts.Context
	if parent == nil {
		parent = context.Background() // audit:ok compatibility for callers without a context, bounded below
	}
	ctx, cancel := context.WithTimeout(parent, desktop.Timeout)
	defer cancel()
	snapshot := readNativeStartup(ctx)
	result := &Result{Root: "host", Source: snapshot.source, Threshold: threshold, Incomplete: snapshot.incomplete}
	for _, row := range snapshot.entries {
		if len(row.Command) > nativeStartupCommandLimit || row.Path == "" {
			result.Incomplete = append(result.Incomplete, snapshot.source+" entry")
			continue
		}
		result.Checked++
		if runtime.GOOS == "windows" && row.Executable == "" {
			row.Executable = windowsStartupImage(row.Command)
		}
		if f, ok := startupFinding(row); ok {
			result.Findings = append(result.Findings, f)
		}
	}
	sortFindings(result.Findings)
	slices.Sort(result.Incomplete)
	result.Incomplete = slices.Compact(result.Incomplete)
	return result
}

func windowsStartupImage(command string) string {
	command = strings.TrimSpace(command)
	if after, quoted := strings.CutPrefix(command, `"`); quoted {
		path, _, closed := strings.Cut(after, `"`)
		if closed {
			return path
		}
		return ""
	}
	path, _, _ := strings.Cut(command, " ")
	if strings.EqualFold(filepath.Ext(path), ".exe") {
		return path
	}
	return ""
}

func startupFinding(row nativeStartup) (Finding, bool) {
	if row.Command == "" {
		return Finding{}, false
	}
	result := Finding{Path: row.Path, Technique: row.Technique, Evidence: trunc(row.Command, 240)}
	if filepath.IsAbs(row.Executable) {
		result.Executable = filepath.Clean(row.Executable)
	}
	for _, finding := range tradecraft.Analyze([]byte(row.Command), tradecraft.Options{}).Findings {
		if finding.Score >= tradecraft.DefaultThreshold && finding.Score > result.Score {
			result.Score, result.Detail = finding.Score, finding.Detail
			result.Class = "persist.native." + strings.TrimPrefix(finding.Class, "tradecraft.")
		}
	}
	if result.Score == 0 {
		for _, temp := range []string{"/tmp/", "/var/tmp/", "/private/tmp/", "/private/var/tmp/"} {
			if strings.HasPrefix(result.Executable, temp) {
				result.Class, result.Score = "persist.native.temporary-executable", 6
				result.Detail = "a startup job points to an executable in a shared temporary directory"
				break
			}
		}
	}
	return result, result.Score > 0
}

func parseLaunchJob(data []byte) (nativeStartup, error) {
	var job struct {
		Program          string
		ProgramArguments []string
	}
	if err := json.Unmarshal(data, &job); err != nil {
		return nativeStartup{}, err
	}
	exe := job.Program
	if exe == "" && len(job.ProgramArguments) > 0 {
		exe = job.ProgramArguments[0]
	}
	command := strings.Join(job.ProgramArguments, " ")
	if job.Program != "" {
		command = strings.TrimSpace(job.Program + " " + command)
	}
	return nativeStartup{Technique: "T1543.001", Executable: exe, Command: command}, nil
}
