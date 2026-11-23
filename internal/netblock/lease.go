package netblock

import (
	"cmp"
	"errors"
	"net/netip"
	"slices"
	"sync"
	"time"
)

// A session owns only the filters it creates. Closing the native session
// releases every filter, including after a process crash.
type filterSession interface {
	add(netip.Addr) ([2]uint64, error)
	remove([2]uint64) error
	close() error
}

type leasedBlock struct {
	entry Entry
	ids   [2]uint64
	timer *time.Timer
}

type filterLeases struct {
	mu      sync.Mutex
	session filterSession
	entries map[netip.Addr]*leasedBlock
	fault   error
}

const maxLeasedBlocks = 4096

func newFilterLeases(session filterSession) *filterLeases {
	return &filterLeases{session: session, entries: make(map[netip.Addr]*leasedBlock)}
}

func (l *filterLeases) block(ip netip.Addr, reason string, ttl time.Duration) (Entry, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.session == nil || l.fault != nil {
		return Entry{}, l.sessionError()
	}
	if ttl <= 0 {
		return Entry{}, errors.New("a firewall session block needs a positive lifetime")
	}
	previous := l.entries[ip]
	var ids [2]uint64
	if previous != nil {
		previous.timer.Stop()
		ids = previous.ids
	} else {
		if len(l.entries) >= maxLeasedBlocks {
			return Entry{}, errors.New("firewall session block limit reached")
		}
		var err error
		ids, err = l.session.add(ip)
		if err != nil {
			return Entry{}, err
		}
	}
	block := &leasedBlock{entry: Entry{Addr: ip.String(), Reason: reason, Expires: time.Now().Add(ttl).UTC()}, ids: ids}
	l.entries[ip] = block
	block.timer = time.AfterFunc(ttl, func() {
		l.mu.Lock()
		defer l.mu.Unlock()
		if l.entries[ip] == block && l.session != nil && l.fault == nil {
			if err := l.removeLocked(ip, block); err != nil {
				// A failed expiry must release the whole session. If closing
				// also fails, this timer keeps retrying until the session closes.
				l.fault = err
				l.closeAfterExpiryError()
			}
		}
	})
	return block.entry, nil
}

func (l *filterLeases) closeAfterExpiryError() {
	if l.session == nil {
		return
	}
	if err := l.closeLocked(); err != nil {
		time.AfterFunc(time.Second, func() {
			l.mu.Lock()
			defer l.mu.Unlock()
			l.closeAfterExpiryError()
		})
	}
}

func (l *filterLeases) sessionError() error {
	if l.fault != nil {
		return l.fault
	}
	return errors.New("firewall session has closed")
}

func (l *filterLeases) remove(ip netip.Addr) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if block := l.entries[ip]; block != nil {
		return l.removeLocked(ip, block)
	}
	return nil
}

func (l *filterLeases) removeLocked(ip netip.Addr, block *leasedBlock) error {
	if err := l.session.remove(block.ids); err != nil {
		return err
	}
	block.timer.Stop()
	delete(l.entries, ip)
	return nil
}

func (l *filterLeases) list() ([]Entry, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	entries := make([]Entry, 0, len(l.entries))
	for _, block := range l.entries {
		entries = append(entries, block.entry)
	}
	slices.SortFunc(entries, func(a, b Entry) int { return cmp.Compare(a.Addr, b.Addr) })
	return entries, l.fault
}

func (l *filterLeases) expiryError() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.fault
}

func (l *filterLeases) close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.closeLocked()
}

func (l *filterLeases) closeLocked() error {
	if l.session == nil {
		return nil
	}
	if err := l.session.close(); err != nil {
		return err
	}
	for _, block := range l.entries {
		block.timer.Stop()
	}
	clear(l.entries)
	l.session = nil
	return nil
}
