package watch

import (
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"unsafe"
)

const windowsWatchMask = syscall.FILE_NOTIFY_CHANGE_FILE_NAME | syscall.FILE_NOTIFY_CHANGE_DIR_NAME |
	syscall.FILE_NOTIFY_CHANGE_ATTRIBUTES | syscall.FILE_NOTIFY_CHANGE_SIZE | syscall.FILE_NOTIFY_CHANGE_LAST_WRITE

const errNotifyEnumDir syscall.Errno = 1022

var (
	watchKernel32       = syscall.NewLazyDLL("kernel32.dll")
	createWatchEvent    = watchKernel32.NewProc("CreateEventW")
	getOverlappedResult = watchKernel32.NewProc("GetOverlappedResult")
)

type Watcher struct {
	*nativeWatch
	directories []*windowsWatchDir
	workers     sync.WaitGroup
}

type windowsWatchDir struct {
	path   string
	handle syscall.Handle
	io     syscall.Overlapped
	buffer *[16 << 10]byte
	pin    runtime.Pinner
	mu     sync.Mutex // serializes submission, cancellation and handle release
}

func New(roots []string, maxDirs int) (*Watcher, error) {
	w := &Watcher{nativeWatch: newNativeWatch(roots, maxDirs)}
	active := w.roots[:0]
	for _, path := range w.roots {
		dir, err := openWatchDir(path)
		if err != nil {
			w.attachmentError(&os.PathError{Op: "watch", Path: path, Err: err})
			continue
		}
		w.directories = append(w.directories, dir)
		active = append(active, path)
	}
	w.roots = active
	if len(active) == 0 && w.firstErr != nil {
		return nil, w.firstErr
	}
	for _, dir := range w.directories {
		w.workers.Add(1)
		go w.readDirectory(dir)
	}
	return w, nil
}

func openWatchDir(path string) (*windowsWatchDir, error) {
	apiPath := path
	if !strings.HasPrefix(path, `\\?\`) {
		if strings.HasPrefix(path, `\\`) {
			apiPath = `\\?\UNC\` + path[2:]
		} else {
			apiPath = `\\?\` + path
		}
	}
	name, err := syscall.UTF16PtrFromString(apiPath)
	if err != nil {
		return nil, err
	}
	handle, err := syscall.CreateFile(name, syscall.FILE_LIST_DIRECTORY,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE,
		nil, syscall.OPEN_EXISTING, syscall.FILE_FLAG_BACKUP_SEMANTICS|syscall.FILE_FLAG_OVERLAPPED|syscall.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, err
	}
	var info syscall.ByHandleFileInformation
	if err := syscall.GetFileInformationByHandle(handle, &info); err != nil {
		syscall.CloseHandle(handle)
		return nil, err
	}
	if info.FileAttributes&syscall.FILE_ATTRIBUTE_REPARSE_POINT != 0 || info.FileAttributes&syscall.FILE_ATTRIBUTE_DIRECTORY == 0 {
		syscall.CloseHandle(handle)
		return nil, errors.New("watch root changed during attachment")
	}
	event, _, err := createWatchEvent.Call(0, 1, 0, 0)
	if event == 0 {
		syscall.CloseHandle(handle)
		return nil, err
	}
	dir := &windowsWatchDir{path: path, handle: handle, buffer: new([16 << 10]byte)}
	dir.io.HEvent = syscall.Handle(event)
	// Windows may retain both addresses until the overlapped operation completes.
	dir.pin.Pin(&dir.io)
	dir.pin.Pin(dir.buffer)
	if err := dir.submit(); err != nil {
		dir.release()
		return nil, err
	}
	return dir, nil
}

func (dir *windowsWatchDir) submit() error {
	err := syscall.ReadDirectoryChanges(dir.handle, &dir.buffer[0], uint32(len(dir.buffer)),
		true, windowsWatchMask, nil, &dir.io, 0)
	if errors.Is(err, syscall.ERROR_IO_PENDING) {
		return nil
	}
	return err
}

func (dir *windowsWatchDir) release() {
	dir.mu.Lock()
	defer dir.mu.Unlock()
	syscall.CloseHandle(dir.io.HEvent)
	syscall.CloseHandle(dir.handle)
	dir.handle = 0
	dir.pin.Unpin()
}

func (w *Watcher) readDirectory(dir *windowsWatchDir) {
	defer w.workers.Done()
	defer dir.release()
	for {
		var size uint32
		ok, _, err := getOverlappedResult.Call(uintptr(dir.handle), uintptr(unsafe.Pointer(&dir.io)), uintptr(unsafe.Pointer(&size)), 1) // audit:ok synchronous Win32 call with a pinned OVERLAPPED and a DWORD output
		runtime.KeepAlive(dir)
		select {
		case <-w.done:
			return
		default:
		}
		switch {
		case ok != 0 && size > 0 && size <= uint32(len(dir.buffer)):
			if !dir.parseEvents(dir.buffer[:size], w) {
				w.publish(Event{Overflow: true})
			}
		case ok != 0 || errors.Is(err, errNotifyEnumDir):
			w.publish(Event{Overflow: true})
		default:
			w.truncated.Store(true)
			w.publish(Event{Overflow: true})
			return
		}
		// Close either cancels this request or stops it from being submitted.
		dir.mu.Lock()
		select {
		case <-w.done:
			dir.mu.Unlock()
			return
		default:
			err = dir.submit()
		}
		dir.mu.Unlock()
		if err != nil {
			w.truncated.Store(true)
			w.publish(Event{Overflow: true})
			return
		}
	}
}

func (dir *windowsWatchDir) parseEvents(data []byte, w *Watcher) bool {
	var nameBuffer [8 << 10]uint16
	for len(data) >= 12 {
		next := binary.LittleEndian.Uint32(data)
		action := binary.LittleEndian.Uint32(data[4:])
		length := binary.LittleEndian.Uint32(data[8:])
		if length == 0 || length%2 != 0 || length > uint32(len(data)-12) || length > 2*uint32(len(nameBuffer)) ||
			(next != 0 && (next < 12+length || next > uint32(len(data)) || next%4 != 0)) {
			return false
		}
		name := nameBuffer[:length/2]
		for i := range name {
			name[i] = binary.LittleEndian.Uint16(data[12+i*2:])
		}
		relative := syscall.UTF16ToString(name)
		if filepath.IsLocal(relative) {
			w.reportPath(dir.path, filepath.Join(dir.path, relative),
				action == syscall.FILE_ACTION_ADDED || action == syscall.FILE_ACTION_RENAMED_NEW_NAME)
		}
		if next == 0 {
			return true
		}
		data = data[next:]
	}
	return false
}

func (w *Watcher) Close() error {
	w.closeOnce.Do(func() {
		close(w.done)
		for _, dir := range w.directories {
			dir.mu.Lock()
			if dir.handle != 0 {
				_ = syscall.CancelIoEx(dir.handle, &dir.io)
			}
			dir.mu.Unlock()
		}
		w.workers.Wait()
	})
	return nil
}
