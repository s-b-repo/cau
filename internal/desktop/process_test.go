package desktop

import "testing"

func TestDesktopProcessSnapshots(t *testing.T) {
	windows := processSnapshot("windows-cim-process", []byte(`[
		{"pid":100,"ppid":20,"name":"worker.exe","image":"C:\\Program Files\\Acme\\worker.exe","command":"worker.exe --status"},
		{"pid":200,"ppid":4,"name":"protected.exe","command":null},
		{"pid":100,"ppid":3,"name":"duplicate.exe","command":"duplicate.exe"}
	]`), false, nil, parseWindowsProcesses)
	if windows.Unavailable || windows.Partial != 2 || len(windows.Rows) != 2 || windows.Rows[0].Command != "worker.exe --status" ||
		windows.Rows[1].Command != "" || len(windows.Warnings) == 0 {
		t.Fatalf("incorrect Windows process coverage: %+v", windows)
	}
	macos := processSnapshot("macos-ps", []byte(" 24  1 /usr/bin/false --example\nnot a row\n"), false, nil, parseMacProcesses)
	if macos.Unavailable || macos.Partial != 1 || len(macos.Rows) != 1 || macos.Rows[0].Name != "/usr/bin/false" ||
		macos.Rows[0].Image != "" {
		t.Fatalf("incorrect macOS process data: %+v", macos)
	}
}
