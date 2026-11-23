//go:build cgo

package netblock

/*
#include <launch.h>
#include <stdlib.h>
#include <unistd.h>

static int cau_firewall_listener(int *listener) {
	int *fds = NULL;
	size_t count = 0;
	int status = launch_activate_socket("PeerBlocks", &fds, &count);
	if (status != 0) return status;
	if (count != 1) {
		for (size_t i = 0; i < count; ++i) close(fds[i]);
		free(fds);
		return -1;
	}
	*listener = fds[0];
	free(fds);
	return 0;
}
*/
import "C"

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/s-b-repo/cau/internal/nativecmd"
	"github.com/s-b-repo/cau/internal/netscan"
)

func openPF() (peerLeases, []string, error) {
	info, err := os.Lstat(pfSocket)
	if err != nil {
		return nil, nil, errors.New("macOS peer firewall requires the CAU launchd firewall service")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0o600 {
		return nil, nil, errors.New("macOS firewall socket must be root-owned and mode 0600")
	}
	conn, err := net.DialTimeout("unix", pfSocket, 3*time.Second)
	if err != nil {
		return nil, nil, fmt.Errorf("connect to macOS firewall service: %w", err)
	}
	client, protected, err := openPFClient(conn)
	if err != nil {
		return nil, nil, err
	}
	return client, protected, nil
}

func RunPFBroker(ctx context.Context) error {
	if os.Geteuid() != 0 {
		return errors.New("macOS firewall service requires root")
	}
	var fd C.int
	if status := C.cau_firewall_listener(&fd); status != 0 {
		return fmt.Errorf("open launchd firewall socket: status %d", int(status))
	}
	file := os.NewFile(uintptr(fd), "CAU launchd firewall socket")
	listener, err := net.FileListener(file)
	closeErr := file.Close()
	if err != nil {
		return err
	}
	defer listener.Close()
	if closeErr != nil {
		return closeErr
	}
	driver := pfDriver{ready: macPFReady, protected: macPFProtected, apply: macPFApply}
	// A restart always clears CAU-owned rules before accepting a new session.
	if err := driver.apply(ctx, nil); err != nil {
		return fmt.Errorf("clear stale macOS peer filters: %w", err)
	}
	stopped := context.AfterFunc(ctx, func() { _ = listener.Close() })
	defer stopped()
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		if err := servePFConnection(ctx, conn, driver); err != nil {
			return err // launchd restarts the broker and clears the anchor
		}
	}
}

const pfctl = "/sbin/pfctl"

func macPFReady(ctx context.Context) error {
	status, _, err := nativecmd.Unix(ctx, pfctl, "-si")
	if err != nil || !strings.Contains(string(status), "Status: Enabled") {
		return errors.New("macOS PF must be enabled before opening a CAU filter session")
	}
	rules, _, err := nativecmd.Unix(ctx, pfctl, "-sr")
	if err != nil {
		return errors.New("could not verify macOS PF rules")
	}
	for line := range strings.Lines(string(rules)) {
		switch strings.TrimSpace(line) {
		case `anchor "org.cau.peer-blocks" quick all`, `anchor "org.cau.peer-blocks" quick`:
			return nil
		}
	}
	return errors.New("the main macOS PF ruleset needs the quick org.cau.peer-blocks anchor")
}

func macPFProtected(ctx context.Context) ([]string, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, errors.New("could not verify macOS interface addresses")
	}
	var peers []string
	for _, addr := range addrs {
		parsed, err := netip.ParsePrefix(addr.String())
		if err != nil {
			return nil, errors.New("macOS returned an invalid interface address")
		}
		peers = append(peers, parsed.Addr().Unmap().String())
	}
	for _, family := range []string{"inet", "inet6"} {
		output, warned, err := nativecmd.Unix(ctx, "/usr/sbin/netstat", "-rn", "-f", family)
		if err != nil || warned {
			return nil, errors.New("could not verify macOS default routes")
		}
		gateways, err := pfGateways(string(output))
		if err != nil {
			return nil, err
		}
		for _, address := range gateways {
			peers = append(peers, address.String())
		}
	}
	dns := netscan.ReadHostDNSPosture(ctx)
	if !dns.Complete() {
		return nil, errors.New("could not verify macOS DNS resolver addresses")
	}
	for _, address := range dns.Client.Nameservers {
		ip, err := netip.ParseAddr(address)
		if err != nil {
			return nil, errors.New("macOS returned an invalid DNS resolver address")
		}
		peers = append(peers, ip.WithZone("").Unmap().String())
	}
	slices.Sort(peers)
	return slices.Compact(peers), nil
}

func macPFApply(ctx context.Context, peers []netip.Addr) error {
	if len(peers) > 0 {
		if err := macPFReady(ctx); err != nil {
			return err
		}
	}
	return macPFApplyAnchor(ctx, pfAnchor, peers)
}

func macPFApplyAnchor(ctx context.Context, anchor string, peers []netip.Addr) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if _, _, err := nativecmd.UnixInput(ctx, strings.NewReader(pfRules(peers)), pfctl, "-a", anchor, "-f", "-"); err != nil {
		return fmt.Errorf("apply the CAU-owned macOS PF anchor: %w", err)
	}
	return nil
}
