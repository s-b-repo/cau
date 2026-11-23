package posture

import (
	"context"

	"github.com/s-b-repo/cau/internal/nativecmd"
)

func read(ctx context.Context) Report {
	result := newReport("darwin", "application-firewall", "filevault", unavailable)
	firewall, warned, err := nativecmd.Unix(ctx, "/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate")
	if err == nil && !warned {
		readMacFirewall(&result.Firewall, string(firewall))
	}
	disk, warned, err := nativecmd.Unix(ctx, "/usr/bin/fdesetup", "status")
	if err == nil && !warned {
		readFileVault(&result.DiskEncryption, string(disk))
	}
	return result
}
