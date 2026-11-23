// Package desktop collects read-only endpoint snapshots on macOS and Windows.
package desktop

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"
	"unicode"
)

const (
	Timeout          = 15 * time.Second
	maxProcessRows   = 32768
	maxCommandLength = 16384
)

type Process struct {
	PID     int    `json:"pid"`
	Parent  int    `json:"ppid"`
	Name    string `json:"name"`
	Image   string `json:"image"`
	Command string `json:"command"`
	Created uint64 `json:"created"`
}

type ProcessSnapshot struct {
	Source      string
	Rows        []Process
	Partial     int
	Unavailable bool
	Warnings    []string
}

func Processes(ctx context.Context) ProcessSnapshot {
	return readProcesses(ctx)
}

func processSnapshot(source string, output []byte, warned bool, err error, parse func([]byte) ([]Process, int, error)) ProcessSnapshot {
	result := ProcessSnapshot{Source: source}
	if err != nil {
		result.Warnings = []string{"native process query did not complete"}
		result.Unavailable = true
		return result
	}
	rows, malformed, err := parse(output)
	if err != nil || len(rows) == 0 {
		result.Warnings = []string{"native process output could not be read"}
		result.Unavailable = true
		return result
	}
	if warned || malformed > 0 {
		result.Warnings = append(result.Warnings, "native process output was partial")
	}
	result.Partial = malformed
	seen := make(map[int]bool, len(rows))
	for _, row := range rows {
		if row.PID <= 0 || row.Parent < 0 || seen[row.PID] {
			result.Partial++
			continue
		}
		seen[row.PID] = true
		if row.Command == "" || len(row.Command) > maxCommandLength {
			row.Command = ""
			result.Partial++
		}
		result.Rows = append(result.Rows, row)
	}
	if result.Partial > 0 && len(result.Warnings) == 0 {
		result.Warnings = []string{"command line unavailable for some processes"}
	}
	return result
}

func parseWindowsProcesses(output []byte) ([]Process, int, error) {
	var rows []Process
	err := json.Unmarshal(output, &rows)
	if len(rows) > maxProcessRows {
		return rows[:maxProcessRows], len(rows) - maxProcessRows, err
	}
	return rows, 0, err
}

func parseMacProcesses(output []byte) ([]Process, int, error) {
	var rows []Process
	bad := 0
	for line := range strings.Lines(string(output)) {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if len(rows) == maxProcessRows {
			bad++
			break
		}
		pidField, rest := splitProcessField(line)
		parentField, command := splitProcessField(rest)
		pid, pidErr := strconv.Atoi(pidField)
		parent, parentErr := strconv.Atoi(parentField)
		if pidErr != nil || parentErr != nil {
			bad++
			continue
		}
		name, _ := splitProcessField(command)
		rows = append(rows, Process{PID: pid, Parent: parent, Name: name, Command: command})
	}
	if len(rows) == 0 && bad > 0 {
		return nil, bad, errors.New("no valid process rows")
	}
	return rows, bad, nil
}

func splitProcessField(line string) (string, string) {
	index := strings.IndexFunc(line, unicode.IsSpace)
	if index < 0 {
		index = len(line)
	}
	return line[:index], strings.TrimSpace(line[index:])
}
