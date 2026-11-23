//go:build windows || (darwin && cgo)

package desktop

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestDesktopProcessProviderSeesCurrentProcess(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), QueryTimeout())
	defer cancel()
	result := Processes(ctx)
	for _, row := range result.Rows {
		if row.PID == os.Getpid() {
			if row.Command == "" || !filepath.IsAbs(row.Image) {
				t.Fatalf("current process is missing command or image evidence: %+v", row)
			}
			return
		}
	}
	t.Fatalf("provider %s did not observe its own process: %v", result.Source, result.Warnings)
}
