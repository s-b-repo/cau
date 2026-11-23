//go:build cgo

package watch

/*
#cgo LDFLAGS: -framework CoreServices -framework CoreFoundation
#include <CoreServices/CoreServices.h>
#include <stdint.h>
#include <stdlib.h>

extern void cauFileEvent(uintptr_t, char *, uint32_t);

static void deliverEvents(ConstFSEventStreamRef stream, void *context,
    size_t count, void *paths, const FSEventStreamEventFlags flags[],
    const FSEventStreamEventId ids[]) {
    char **names = (char **)paths;
    for (size_t i = 0; i < count; i++) {
        cauFileEvent((uintptr_t)context, names[i], flags[i]);
    }
}

static FSEventStreamRef startWatch(CFArrayRef roots, uintptr_t context) {
    FSEventStreamContext data = {0, (void *)context, NULL, NULL, NULL};
    FSEventStreamRef stream = FSEventStreamCreate(NULL, deliverEvents, &data,
        roots, kFSEventStreamEventIdSinceNow, 0.1,
        kFSEventStreamCreateFlagFileEvents | kFSEventStreamCreateFlagWatchRoot);
    if (stream) {
        FSEventStreamScheduleWithRunLoop(stream, CFRunLoopGetCurrent(), kCFRunLoopDefaultMode);
        if (!FSEventStreamStart(stream)) {
            FSEventStreamInvalidate(stream);
            FSEventStreamRelease(stream);
            return NULL;
        }
    }
    return stream;
}

static CFMutableArrayRef watchPaths(void) {
    return CFArrayCreateMutable(NULL, 0, &kCFTypeArrayCallBacks);
}

static int appendWatchPath(CFMutableArrayRef roots, const char *name) {
    CFStringRef path = CFStringCreateWithFileSystemRepresentation(NULL, name);
    if (!path) {
        return 0;
    }
    CFArrayAppendValue(roots, path);
    CFRelease(path);
    return 1;
}
*/
import "C"

import (
	"errors"
	"path/filepath"
	"runtime"
	"runtime/cgo"
	"unsafe"
)

type Watcher struct {
	*nativeWatch
	finished chan struct{}
}

func New(roots []string, maxDirs int) (*Watcher, error) {
	w := &Watcher{nativeWatch: newNativeWatch(roots, maxDirs), finished: make(chan struct{})}
	if len(w.roots) == 0 {
		if w.firstErr != nil {
			return nil, w.firstErr
		}
		close(w.finished)
		return w, nil
	}
	started := make(chan error, 1)
	go w.stream(started)
	if err := <-started; err != nil {
		_ = w.Close()
		return nil, err
	}
	return w, nil
}

func (w *Watcher) stream(started chan<- error) {
	defer close(w.finished)
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	roots := C.watchPaths()
	if roots == 0 {
		started <- errors.New("could not allocate FSEvents roots")
		return
	}
	defer C.CFRelease(C.CFTypeRef(roots))
	for _, root := range w.roots {
		name := C.CString(root)
		ok := C.appendWatchPath(roots, name)
		C.free(unsafe.Pointer(name)) // audit:ok releases the matching C.CString allocation
		if ok == 0 {
			started <- errors.New("could not encode FSEvents root")
			return
		}
	}
	handle := cgo.NewHandle(w)
	defer handle.Delete()
	stream := C.startWatch(C.CFArrayRef(roots), C.uintptr_t(handle))
	if stream == nil {
		started <- errors.New("could not start the FSEvents stream")
		return
	}
	defer C.FSEventStreamRelease(stream)
	defer C.FSEventStreamInvalidate(stream)
	defer C.FSEventStreamStop(stream)
	started <- nil
	for {
		select {
		case <-w.done:
			return
		default:
		}
		if C.CFRunLoopRunInMode(C.kCFRunLoopDefaultMode, 0.25, 0) == C.kCFRunLoopRunFinished {
			w.truncated.Store(true)
			w.publish(Event{Overflow: true})
			return
		}
	}
}

//export cauFileEvent
func cauFileEvent(context C.uintptr_t, path *C.char, flags C.uint32_t) {
	w := cgo.Handle(context).Value().(*Watcher)
	if flags&C.kFSEventStreamEventFlagRootChanged != 0 {
		w.truncated.Store(true)
	}
	if flags&(C.kFSEventStreamEventFlagMustScanSubDirs|C.kFSEventStreamEventFlagRootChanged|
		C.kFSEventStreamEventFlagMount|C.kFSEventStreamEventFlagUnmount|C.kFSEventStreamEventFlagEventIdsWrapped) != 0 {
		w.publish(Event{Overflow: true})
		return
	}
	if flags&C.kFSEventStreamEventFlagItemIsSymlink != 0 {
		return
	}
	directoryChange := flags&C.kFSEventStreamEventFlagItemIsDir != 0 &&
		flags&(C.kFSEventStreamEventFlagItemCreated|C.kFSEventStreamEventFlagItemRenamed) != 0
	if !directoryChange && flags&C.kFSEventStreamEventFlagItemIsFile == 0 {
		return
	}
	name := filepath.Clean(C.GoString(path))
	for _, root := range w.roots {
		relative, err := filepath.Rel(root, name)
		if err == nil && filepath.IsLocal(relative) {
			w.reportPath(root, name, directoryChange)
			return
		}
	}
}

func (w *Watcher) Close() error {
	w.closeOnce.Do(func() {
		close(w.done)
		<-w.finished
	})
	return nil
}
