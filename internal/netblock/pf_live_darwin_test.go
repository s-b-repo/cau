//go:build cgo

package netblock

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/s-b-repo/cau/internal/nativecmd"
)

func TestPFNativeAnchor(t *testing.T) {
	if os.Getenv("CAU_TEST_NATIVE_PF") != "1" {
		t.Skip("requires a disposable macOS runner with root access to PF")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	// The test anchor is not attached to the main ruleset. Verify the
	// kernel accepts both families without changing the runner's traffic.
	anchor := fmt.Sprintf("org.cau.native-smoke-%d", os.Getpid())
	t.Cleanup(func() {
		if err := macPFApplyAnchor(context.Background(), anchor, nil); err != nil {
			t.Errorf("clear native test anchor: %v", err)
		}
	})
	read := func() string {
		t.Helper()
		output, _, err := nativecmd.Unix(ctx, pfctl, "-a", anchor, "-sr")
		if err != nil {
			t.Fatalf("read native test anchor: %v", err)
		}
		return string(output)
	}
	v4 := netip.MustParseAddr("198.51.100.104")
	v6 := netip.MustParseAddr("2001:db8::104")
	if err := macPFApplyAnchor(ctx, anchor, []netip.Addr{v4, v6}); err != nil {
		t.Fatal(err)
	}
	rules := read()
	for _, peer := range []netip.Addr{v4, v6} {
		if strings.Count(rules, peer.String()) != 2 {
			t.Fatalf("missing inbound or outbound rule for %s:\n%s", peer, rules)
		}
	}
	if err := macPFApplyAnchor(ctx, anchor, nil); err != nil {
		t.Fatal(err)
	}
	if rules := strings.TrimSpace(read()); rules != "" {
		t.Fatalf("native anchor still holds rules after cleanup:\n%s", rules)
	}
}
