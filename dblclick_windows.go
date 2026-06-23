//go:build windows

package main

import (
	"syscall"
	"unsafe"
)

// launchedByDoubleClick returns true when the program owns its console alone —
// i.e. it was double-clicked from Explorer rather than run from an existing
// terminal. If GetConsoleProcessList reports just one attached process (us),
// the console will vanish on exit, so we should pause.
func launchedByDoubleClick() bool {
	modkernel32 := syscall.NewLazyDLL("kernel32.dll")
	proc := modkernel32.NewProc("GetConsoleProcessList")
	var pids [4]uint32
	ret, _, _ := proc.Call(
		uintptr(unsafe.Pointer(&pids[0])),
		uintptr(len(pids)),
	)
	return ret == 1
}
