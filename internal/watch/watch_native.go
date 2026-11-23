//go:build windows || (darwin && cgo)

package watch

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
)

// Native backends subscribe recursively. Bound the number of independent
// subscriptions even when the caller supplies a larger Linux directory limit.
const maxNativeRoots = 128

type nativeWatch struct {
	events    chan Event
	done      chan struct{}
	closeOnce sync.Once
	truncated atomic.Bool
	lost      chan struct{}
	roots     []string
	firstErr  error
}

func newNativeWatch(paths []string, limit int) *nativeWatch {
	w := &nativeWatch{events: make(chan Event, 1024), done: make(chan struct{}), lost: make(chan struct{}, 1)}
	if limit <= 0 || limit > maxNativeRoots {
		limit = maxNativeRoots
	}
	for _, path := range paths {
		info, err := os.Stat(path)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			w.attachmentError(err)
			continue
		}
		if !info.IsDir() {
			w.attachmentError(&os.PathError{Op: "watch", Path: path, Err: errors.New("expected a directory")})
			continue
		}
		absolute, err := filepath.Abs(path)
		if err != nil {
			w.attachmentError(err)
			continue
		}
		root, err := filepath.EvalSymlinks(absolute)
		if err != nil {
			w.attachmentError(err)
			continue
		}
		duplicate := false
		for _, existing := range w.roots {
			if samePath(existing, root) {
				duplicate = true
				break
			}
		}
		if duplicate {
			continue
		}
		if len(w.roots) == limit {
			w.truncated.Store(true)
			break
		}
		w.roots = append(w.roots, root)
	}
	return w
}

func (w *nativeWatch) attachmentError(err error) {
	w.truncated.Store(true)
	if w.firstErr == nil {
		w.firstErr = err
	}
}

// Dirs counts directly subscribed directories. Each subscription is recursive.
func (w *nativeWatch) Dirs() int { return len(w.roots) }

func (w *nativeWatch) Truncated() bool { return w.truncated.Load() }

func (w *nativeWatch) Run(fn func(Event)) error {
	for {
		select {
		case <-w.done:
			return nil
		case <-w.lost:
			fn(Event{Overflow: true})
		case event := <-w.events:
			fn(event)
		}
	}
}

func (w *nativeWatch) publish(event Event) {
	if !event.Overflow {
		select {
		case w.events <- event:
			return
		default:
		}
	}
	select {
	case w.lost <- struct{}{}:
	default:
	}
}

func (w *nativeWatch) reportPath(root, path string, checkDirectory bool) {
	relative, err := filepath.Rel(root, path)
	if err != nil || !filepath.IsLocal(relative) || relative == "." {
		return
	}
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		w.publish(Event{Path: path})
		return
	}
	if err != nil || (!info.Mode().IsRegular() && !info.IsDir()) {
		return
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || !samePath(resolved, path) {
		return
	}
	if info.IsDir() {
		if checkDirectory {
			// A complete directory tree can move in with a single event.
			w.publish(Event{Overflow: true})
		}
		return
	}
	w.publish(Event{Path: path})
}

func samePath(a, b string) bool {
	if filepath.Separator == '\\' {
		return strings.EqualFold(a, b)
	}
	return a == b
}
