package netscan

import (
	"context"

	"github.com/s-b-repo/cau/internal/nativecmd"
)

func nativeConnections(ctx context.Context) connectionSnapshot {
	out, warned, err := nativecmd.Unix(ctx, "/usr/sbin/lsof", "-nP", "-iTCP", "-iUDP", "-F0pcfPnT")
	rows, bad := parseMacConnections(out)
	return collectedConnections("macos-lsof", rows, bad, warned, err)
}
