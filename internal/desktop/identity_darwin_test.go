//go:build cgo

package desktop

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestDesktopMacProcessIdentity(t *testing.T) {
	pid := os.Getpid()
	executable := processImage(pid)
	created := processCreation(pid)
	if !slices.Contains(processIDs(), pid) || !filepath.IsAbs(executable) || created == 0 {
		t.Fatalf("missing libproc identity for the test process, image=%q created=%d", executable, created)
	}
	for _, input := range []struct {
		created uint64
		path    string
	}{
		{created + 1, executable},
		{created, executable + ".other"},
	} {
		if err := TerminateMacProcess(pid, input.created, input.path); err == nil ||
			!strings.Contains(err.Error(), "changed since collection") {
			t.Fatalf("identity check did not refuse the stale process: %v", err)
		}
	}
}
