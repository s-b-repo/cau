package netblock

import (
	"bufio"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"
)

const (
	pfAnchor       = "org.cau.peer-blocks"
	pfSocket       = "/var/run/org.cau.peer-blocks.sock"
	pfMaxBlocks    = 512
	pfMaxReason    = 512
	pfMaxMessage   = 1 << 20
	pfMaxLifetime  = 24 * time.Hour
	pfOperationTTL = 20 * time.Second
)

type peerLeases interface {
	block(netip.Addr, string, time.Duration) (Entry, error)
	remove(netip.Addr) error
	list() ([]Entry, error)
	expiryError() error
	close() error
}

type pfRequest struct {
	Action   string        `json:"action"`
	Address  netip.Addr    `json:"address,omitempty"`
	Lifetime time.Duration `json:"lifetime,omitempty"`
	Reason   string        `json:"reason,omitempty"`
}

type pfReply struct {
	Error     string   `json:"error,omitempty"`
	Closed    bool     `json:"closed,omitempty"`
	Protected []string `json:"protected,omitempty"`
	Entry     Entry    `json:"entry"`
	Entries   []Entry  `json:"entries,omitempty"`
}

type pfClient struct {
	mu     sync.Mutex
	conn   net.Conn
	reader *bufio.Scanner
	fault  error
}

func openPFClient(conn net.Conn) (*pfClient, []string, error) {
	client := &pfClient{conn: conn, reader: bufio.NewScanner(conn)} // audit:ok exchange checks Scanner.Err after Scan
	client.reader.Buffer(nil, pfMaxMessage)
	reply, err := client.query(pfRequest{Action: "open"})
	if err != nil {
		_ = client.close()
		return nil, nil, err
	}
	return client, reply.Protected, nil
}

func (c *pfClient) query(request pfRequest) (pfReply, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn == nil {
		if c.fault != nil {
			return pfReply{}, c.fault
		}
		return pfReply{}, errors.New("macOS firewall session has closed")
	}
	reply, err := c.exchange(request)
	if err != nil {
		c.fault = err
		_ = c.conn.Close()
		c.conn = nil
		return pfReply{}, err
	}
	if reply.Error != "" {
		err := errors.New(reply.Error)
		if reply.Closed {
			c.fault = err
			_ = c.conn.Close()
			c.conn = nil
		}
		return pfReply{}, err
	}
	return reply, nil
}

func (c *pfClient) exchange(request pfRequest) (pfReply, error) {
	var reply pfReply
	if err := c.conn.SetDeadline(time.Now().Add(pfOperationTTL)); err != nil {
		return reply, err
	}
	if err := json.NewEncoder(c.conn).Encode(request); err != nil {
		return reply, err
	}
	if !c.reader.Scan() {
		if err := c.reader.Err(); err != nil {
			return reply, err
		}
		return reply, io.ErrUnexpectedEOF
	}
	err := json.Unmarshal(c.reader.Bytes(), &reply)
	return reply, err
}

func (c *pfClient) block(ip netip.Addr, reason string, lifetime time.Duration) (Entry, error) {
	if len(reason) > pfMaxReason {
		reason = reason[:pfMaxReason]
	}
	reply, err := c.query(pfRequest{Action: "block", Address: ip, Lifetime: lifetime, Reason: reason})
	return reply.Entry, err
}

func (c *pfClient) remove(ip netip.Addr) error {
	_, err := c.query(pfRequest{Action: "unblock", Address: ip})
	return err
}

func (c *pfClient) list() ([]Entry, error) {
	reply, err := c.query(pfRequest{Action: "list"})
	return reply.Entries, err
}

func (c *pfClient) expiryError() error {
	_, err := c.query(pfRequest{Action: "ping"})
	return err
}

func (c *pfClient) close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn == nil {
		return nil
	}
	// Acknowledging close lets the caller distinguish cleared rules from
	// a broken broker. EOF also clears rules if CAU exits unexpectedly.
	reply, err := c.exchange(pfRequest{Action: "close"})
	closeErr := c.conn.Close()
	c.conn = nil
	if err == nil && reply.Error != "" {
		err = errors.New(reply.Error)
	}
	return errors.Join(err, closeErr)
}

type pfDriver struct {
	ready     func(context.Context) error
	protected func(context.Context) ([]string, error)
	apply     func(context.Context, []netip.Addr) error
}

func servePFConnection(ctx context.Context, conn net.Conn, driver pfDriver) (err error) {
	defer conn.Close()
	if err := conn.SetReadDeadline(time.Now().Add(pfOperationTTL)); err != nil {
		return err
	}
	active := make(map[netip.Addr]Entry)
	opened := false
	defer func() {
		if opened {
			// The service's parent context can be cancelled during normal
			// shutdown. Give scoped cleanup an independent, bounded deadline.
			cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), pfOperationTTL)
			defer cancel()
			err = errors.Join(err, driver.apply(cleanup, nil))
		}
	}()
	requests := make(chan pfRequest)
	readResult := make(chan error, 1)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		readResult <- readPFRequests(ctx, conn, requests)
		close(requests)
	}()
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
			if err := expirePFRules(ctx, driver, active, time.Now()); err != nil {
				return fmt.Errorf("expire macOS peer filters: %w", err)
			}
		case request, ok := <-requests:
			if !ok {
				return <-readResult
			}
			if err := expirePFRules(ctx, driver, active, time.Now()); err != nil {
				return fmt.Errorf("expire macOS peer filters: %w", err)
			}
			call, cancelCall := context.WithTimeout(ctx, pfOperationTTL)
			reply, closed := handlePFRequest(call, driver, active, &opened, request)
			cancelCall()
			if opened {
				if err := conn.SetReadDeadline(time.Time{}); err != nil {
					return err
				}
			}
			if err := conn.SetWriteDeadline(time.Now().Add(pfOperationTTL)); err != nil {
				return err
			}
			if err := json.NewEncoder(conn).Encode(reply); err != nil {
				return err
			}
			if closed {
				return nil
			}
		}
	}
}

func readPFRequests(ctx context.Context, conn net.Conn, requests chan<- pfRequest) error {
	scanner := bufio.NewScanner(conn)
	scanner.Buffer(nil, 4096)
	for scanner.Scan() {
		var request pfRequest
		if err := json.Unmarshal(scanner.Bytes(), &request); err != nil {
			return err
		}
		select {
		case requests <- request:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return scanner.Err()
}

func handlePFRequest(ctx context.Context, driver pfDriver, active map[netip.Addr]Entry, opened *bool, req pfRequest) (pfReply, bool) {
	fail := func(err error) (pfReply, bool) { return pfReply{Error: err.Error()}, false }
	if !*opened && req.Action != "open" && req.Action != "close" {
		return fail(errors.New("macOS firewall session has not opened"))
	}
	switch req.Action {
	case "open":
		if *opened {
			return fail(errors.New("macOS firewall session is already open"))
		}
		if err := driver.ready(ctx); err != nil {
			return fail(err)
		}
		protected, err := driver.protected(ctx)
		if err != nil {
			return fail(err)
		}
		*opened = true
		return pfReply{Protected: protected}, false
	case "block":
		ip := req.Address.Unmap()
		if !ip.IsValid() || ip.Zone() != "" || req.Lifetime <= 0 || req.Lifetime > pfMaxLifetime || len(req.Reason) > pfMaxReason {
			return fail(errors.New("invalid macOS firewall block address or lifetime"))
		}
		peers, err := driver.protected(ctx)
		if err != nil {
			return fail(err)
		}
		protected := make(map[string]bool, len(peers))
		for _, address := range peers {
			protected[address] = true
		}
		if err := Check(ip.String(), protected); err != nil {
			return fail(err)
		}
		if _, known := active[ip]; !known && len(active) >= pfMaxBlocks {
			return fail(errors.New("macOS firewall block limit reached"))
		}
		entry, err := putPFRule(ctx, driver, active, ip, req.Lifetime, req.Reason)
		if err != nil {
			// A failed tool call can leave the result ambiguous. Close this
			// session and clear the entire owned anchor before taking another.
			return pfReply{Error: err.Error(), Closed: true}, true
		}
		return pfReply{Entry: entry}, false
	case "unblock":
		ip := req.Address.Unmap()
		if !ip.IsValid() || ip.Zone() != "" {
			return fail(errors.New("invalid macOS firewall unblock address"))
		}
		if _, found := active[ip]; found {
			if err := removePFRules(ctx, driver, active, func(candidate netip.Addr, _ Entry) bool { return ip == candidate }); err != nil {
				return pfReply{Error: err.Error(), Closed: true}, true
			}
		}
		return pfReply{}, false
	case "list":
		entries := make([]Entry, 0, len(active))
		for _, entry := range active {
			entries = append(entries, entry)
		}
		slices.SortFunc(entries, func(a, b Entry) int { return cmp.Compare(a.Addr, b.Addr) })
		return pfReply{Entries: entries}, false
	case "ping":
		return pfReply{}, false
	case "close":
		if *opened {
			if err := driver.apply(ctx, nil); err != nil {
				return pfReply{Error: err.Error(), Closed: true}, true
			}
			clear(active)
			*opened = false
		}
		return pfReply{}, true
	default:
		return fail(errors.New("invalid macOS firewall operation"))
	}
}

func putPFRule(ctx context.Context, driver pfDriver, active map[netip.Addr]Entry, ip netip.Addr, lifetime time.Duration, reason string) (Entry, error) {
	if _, known := active[ip]; !known {
		peers := []netip.Addr{ip}
		for peer := range active {
			peers = append(peers, peer)
		}
		if err := driver.apply(ctx, peers); err != nil {
			return Entry{}, err
		}
	}
	entry := Entry{Addr: ip.String(), Reason: reason, Expires: time.Now().Add(lifetime).UTC()}
	active[ip] = entry
	return entry, nil
}

func expirePFRules(ctx context.Context, driver pfDriver, active map[netip.Addr]Entry, now time.Time) error {
	return removePFRules(ctx, driver, active, func(_ netip.Addr, entry Entry) bool {
		return !entry.Expires.After(now)
	})
}

func removePFRules(ctx context.Context, driver pfDriver, active map[netip.Addr]Entry, remove func(netip.Addr, Entry) bool) error {
	var keep []netip.Addr
	for peer, entry := range active {
		if !remove(peer, entry) {
			keep = append(keep, peer)
		}
	}
	if len(keep) == len(active) {
		return nil
	}
	if err := driver.apply(ctx, keep); err != nil {
		return err
	}
	for peer, entry := range active {
		if remove(peer, entry) {
			delete(active, peer)
		}
	}
	return nil
}

func pfRules(peers []netip.Addr) string {
	slices.SortFunc(peers, netip.Addr.Compare)
	var rules strings.Builder
	for _, peer := range peers {
		family := "inet"
		if peer.Is6() {
			family = "inet6"
		}
		fmt.Fprintf(&rules, "block drop in quick %s from %s to any\nblock drop out quick %s from any to %s\n", family, peer, family, peer)
	}
	return rules.String()
}
