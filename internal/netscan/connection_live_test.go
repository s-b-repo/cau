//go:build darwin || windows

package netscan

import (
	"context"
	"net"
	"os"
	"testing"

	"github.com/s-b-repo/cau/internal/desktop"
)

func TestDesktopConnectionProviderSeesLoopbackListener(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	ctx, cancel := context.WithTimeout(context.Background(), desktop.QueryTimeout())
	defer cancel()
	snapshot := nativeConnections(ctx)
	for _, row := range snapshot.sockets {
		if row.PID == os.Getpid() && row.Local == (Endpoint{IP: "127.0.0.1", Port: port}) && row.listening() {
			return
		}
	}
	t.Fatalf("provider %s did not report the loopback listener on %d (%s): %v", snapshot.source, port, snapshot.coverage, snapshot.warnings)
}
