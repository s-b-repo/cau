package persist

import (
	"runtime"
	"testing"
)

func TestDesktopLaunchJobArguments(t *testing.T) {
	row, err := parseLaunchJob([]byte(`{"Program":"/private/tmp/a helper","ProgramArguments":["helper","--status"]}`))
	if err != nil || row.Executable != "/private/tmp/a helper" || row.Command != "/private/tmp/a helper helper --status" {
		t.Fatalf("failed to preserve the configured path: %+v, %v", row, err)
	}
	if runtime.GOOS == "windows" {
		return
	}
	row.Path = "/Library/LaunchAgents/org.cau.test.plist"
	finding, observed := startupFinding(row)
	if !observed || finding.Class != "persist.native.temporary-executable" || finding.Score >= DefaultThreshold ||
		finding.Executable != "/private/tmp/a helper" {
		t.Fatalf("incorrect launch job observation: %+v", finding)
	}
}
