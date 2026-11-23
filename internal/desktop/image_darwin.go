//go:build cgo

package desktop

/*
#include <libproc.h>
#include <mach/mach.h>
#include <sys/proc_info.h>

static uint64_t cau_process_creation(int pid) {
	struct proc_bsdinfo info = {0};
	if (proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, (int)sizeof(info)) != (int)sizeof(info)) {
		return 0;
	}
	return info.pbi_start_tvsec * 1000000 + info.pbi_start_tvusec;
}

static kern_return_t cau_open_process_task(int pid, mach_port_t *task) {
	return task_for_pid(mach_task_self(), pid, task);
}

static kern_return_t cau_close_process_task(mach_port_t task) {
	return mach_port_deallocate(mach_task_self(), task);
}
*/
import "C"

import (
	"errors"
	"fmt"
	"path/filepath"
	"unsafe"
)

func processImage(pid int) string {
	var buf [C.PROC_PIDPATHINFO_MAXSIZE]C.char
	size := C.proc_pidpath(C.int(pid), unsafe.Pointer(&buf[0]), C.uint32_t(len(buf))) // audit:ok synchronous libproc write into an array bounded by its byte length
	if size <= 0 || size >= C.int(len(buf)) {
		return ""
	}
	return C.GoString(&buf[0])
}

func processIDs() []int {
	var pids [maxProcessRows + 1]C.int
	n := C.proc_listpids(C.PROC_ALL_PIDS, 0, unsafe.Pointer(&pids[0]), C.int(unsafe.Sizeof(pids))) // audit:ok synchronous libproc write bounded by the size of the PID array
	if n <= 0 || n >= C.int(unsafe.Sizeof(pids)) {
		return nil
	}
	var result []int
	for _, pid := range pids[:int(n)/int(unsafe.Sizeof(pids[0]))] {
		if pid > 0 {
			result = append(result, int(pid))
		}
	}
	return result
}

func processCreation(pid int) uint64 {
	return uint64(C.cau_process_creation(C.int(pid)))
}

// TerminateMacProcess requires macOS to grant a task control right to the
// caller. Holding the right makes termination independent of subsequent PID
// reuse. The right is released without reading or writing the task's memory.
func TerminateMacProcess(pid int, created uint64, executable string) error {
	if pid <= 4 || pid > 1<<31-1 || created == 0 || !filepath.IsAbs(executable) {
		return errors.New("process identity or image was unavailable during collection")
	}
	if processImage(pid) != executable || processCreation(pid) != created {
		return errors.New("process creation time or image changed since collection")
	}
	var task C.mach_port_t
	if status := C.cau_open_process_task(C.int(pid), &task); status != 0 {
		return fmt.Errorf("macOS did not grant process termination access: Mach status %d", int(status))
	}
	defer C.cau_close_process_task(task)
	var heldPID C.int
	if status := C.pid_for_task(task, &heldPID); status != 0 || int(heldPID) != pid {
		return errors.New("the task handle and requested process do not match")
	}
	if processImage(pid) != executable || processCreation(pid) != created {
		return errors.New("process creation time or image changed since collection")
	}
	if status := C.task_terminate(task); status != 0 {
		return fmt.Errorf("macOS could not terminate the task: Mach status %d", int(status))
	}
	return nil
}
