package desktop

import (
	"context"
	"path/filepath"

	"github.com/s-b-repo/cau/internal/nativecmd"
	"github.com/s-b-repo/cau/internal/parallel"
)

func readProcesses(ctx context.Context) ProcessSnapshot {
	// A PID reused while ps is running must not join its old command line
	// to the new process's identity.
	created := make(map[int]uint64)
	for _, pid := range processIDs() {
		if ctx.Err() != nil {
			break
		}
		created[pid] = processCreation(pid)
	}
	out, warned, err := nativecmd.Unix(ctx, "/bin/ps", "-axww", "-o", "pid=", "-o", "ppid=", "-o", "command=")
	result := processSnapshot("macos-ps", out, warned, err, parseMacProcesses)
	parallel.For(len(result.Rows), 4, func(i int) {
		if ctx.Err() == nil {
			row := &result.Rows[i]
			image := processImage(row.PID)
			if start := created[row.PID]; filepath.IsAbs(image) && start != 0 && processCreation(row.PID) == start {
				row.Image = image
				row.Name = filepath.Base(image)
				row.Created = start
			}
		}
	})
	return result
}
