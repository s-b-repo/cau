package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"unsafe"

	"github.com/s-b-repo/cau/internal/report"
)

const (
	ownProcess         = 0x10
	serviceStopped     = 1
	serviceStarting    = 2
	serviceStopping    = 3
	serviceRunning     = 4
	controlStop        = 1
	controlInterrogate = 4
	controlShutdown    = 5
	acceptStop         = 1
	acceptShutdown     = 4
	serviceSpecificErr = 1066
)

var (
	serviceAPI             = syscall.NewLazyDLL("advapi32.dll")
	startServiceDispatcher = serviceAPI.NewProc("StartServiceCtrlDispatcherW")
	registerServiceHandler = serviceAPI.NewProc("RegisterServiceCtrlHandlerExW")
	setServiceStatus       = serviceAPI.NewProc("SetServiceStatus")
)

type serviceStatus struct {
	serviceType, state, controls, win32Exit, serviceExit, checkpoint, waitHint uint32
}

type serviceTableEntry struct {
	name  *uint16
	start uintptr
}

type defendService struct {
	mu     sync.Mutex
	handle uintptr
	state  uint32
	stop   chan struct{}
}

func runService(args []string) (int, bool) {
	if len(args) == 0 || args[0] != "--windows-service" {
		return 0, false
	}
	if len(args) < 2 || !filepath.IsAbs(args[1]) {
		return fail(os.Stderr, report.ExitUsage, "usage: cau --windows-service <absolute log directory> [defend flags]"), true
	}

	service := &defendService{stop: make(chan struct{})}
	name, _ := syscall.UTF16PtrFromString("CauDefend")
	handler := syscall.NewCallback(service.control)
	finished := make(chan int, 1)
	entry := syscall.NewCallback(func(_, _ uintptr) uintptr {
		handle, _, callErr := registerServiceHandler.Call(uintptr(unsafe.Pointer(name)), handler, 0) // audit:ok Win32 reads the terminated UTF-16 name during the call
		if handle == 0 {
			fmt.Fprintln(os.Stderr, "register Windows service control handler:", callErr)
			finished <- report.ExitRunFailed
			return 0
		}
		service.mu.Lock()
		service.handle = handle
		service.setState(serviceStarting, 0)
		service.mu.Unlock()
		code := service.defend(args[1], args[2:])
		service.mu.Lock()
		service.setState(serviceStopped, code)
		service.mu.Unlock()
		finished <- code
		return 0
	})
	table := [2]serviceTableEntry{{name: name, start: entry}, {}}
	ok, _, err := startServiceDispatcher.Call(uintptr(unsafe.Pointer(&table[0]))) // audit:ok Win32 reads the terminated service table before returning
	runtime.KeepAlive(table)
	if ok == 0 {
		return fail(os.Stderr, report.ExitRunFailed, "connect Windows Service Control Manager: %v", err), true
	}
	// The SCM can return as soon as the callback advertises SERVICE_STOPPED.
	return <-finished, true
}

func (s *defendService) defend(logDir string, args []string) (code int) {
	root, err := os.OpenRoot(logDir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "open Windows service log directory:", err)
		return report.ExitRunFailed
	}
	defer root.Close()
	status, err := openServiceLog(root, "defend.log")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return report.ExitRunFailed
	}
	defer func() {
		if err := status.Close(); err != nil {
			code = fail(os.Stderr, report.ExitRunFailed, "close Windows service diagnostics: %v", err)
		}
	}()
	incidents, err := openServiceLog(root, "incidents.jsonl")
	if err != nil {
		fmt.Fprintln(status, err)
		return report.ExitRunFailed
	}
	defer func() {
		if err := incidents.Close(); err != nil {
			code = fail(status, report.ExitRunFailed, "close Windows service incident log: %v", err)
		}
	}()
	args = append(append([]string(nil), args...), "--format=json")
	return runDefend(args, incidents, status, s.stop, func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.state == serviceStarting {
			s.setState(serviceRunning, 0)
		}
	})
}

func openServiceLog(root *os.Root, name string) (*os.File, error) {
	file, err := root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY|os.O_APPEND, 0o600)
	if !errors.Is(err, fs.ErrExist) {
		return file, err
	}
	return root.OpenFile(name, os.O_WRONLY|os.O_APPEND, 0)
}

func (s *defendService) control(command, _, _, _ uintptr) uintptr {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch command {
	case controlStop, controlShutdown:
		if s.state == serviceRunning {
			s.setState(serviceStopping, 0)
			close(s.stop)
		}
	case controlInterrogate:
		if s.state != 0 && s.state != serviceStopped {
			s.setState(s.state, 0)
		}
	}
	return 0
}

// The caller holds mu across the transition and the SCM notification.
func (s *defendService) setState(state uint32, code int) {
	s.state = state
	status := serviceStatus{serviceType: ownProcess, state: state}
	switch state {
	case serviceStarting, serviceStopping:
		status.checkpoint, status.waitHint = 1, 30000
	case serviceRunning:
		status.controls = acceptStop | acceptShutdown
	case serviceStopped:
		if code != 0 {
			status.win32Exit, status.serviceExit = serviceSpecificErr, uint32(code)
		}
	}
	setServiceStatus.Call(s.handle, uintptr(unsafe.Pointer(&status))) // audit:ok Win32 reads the complete fixed-size service status during the call
	runtime.KeepAlive(&status)
}
