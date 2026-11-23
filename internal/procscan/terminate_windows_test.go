package procscan

import (
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"
)

func TestDesktopTerminationChecksIdentity(t *testing.T) {
	const fixture = "CAU_TEST_PROCESS_TERMINATION"
	if os.Getenv(fixture) == "1" {
		time.Sleep(30 * time.Second)
		return
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	child := exec.Command(self, "-test.run=^TestDesktopTerminationChecksIdentity$")
	child.Env = append(os.Environ(), fixture+"=1")
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if child.ProcessState == nil {
			_ = child.Process.Kill()
			_ = child.Wait()
		}
	}()
	handle, err := syscall.OpenProcess(processQueryLimitedInformation, false, uint32(child.Process.Pid))
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.CloseHandle(handle)
	var created, exited, kernel, user syscall.Filetime
	if err := syscall.GetProcessTimes(handle, &created, &exited, &kernel, &user); err != nil {
		t.Fatal(err)
	}
	ticks := uint64(created.HighDateTime)<<32 | uint64(created.LowDateTime)
	process := Process{PID: child.Process.Pid, Exe: self, nativeCreated: ticks + 10}
	if err := terminateDesktop(process); err == nil {
		t.Fatal("terminated the fixture using a stale creation time")
	}
	process.nativeCreated = ticks
	process.Exe += ".other"
	if err := terminateDesktop(process); err == nil {
		t.Fatal("terminated the fixture with a mismatched image")
	}
	process.Exe = self
	if err := terminateDesktop(process); err != nil {
		t.Fatal(err)
	}
	if err := child.Wait(); err == nil || child.ProcessState.ExitCode() != 1 {
		t.Fatalf("fixture exit was not the response exit: %v", err)
	}
}
