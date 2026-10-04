package server

import (
	"syscall"
	"testing"
)

func TestSetNonDumpable(t *testing.T) {
	get := func() uintptr {
		v, _, e := syscall.RawSyscall(syscall.SYS_PRCTL, syscall.PR_GET_DUMPABLE, 0, 0)
		if e != 0 {
			t.Fatal(e)
		}
		return v
	}
	old := get()
	t.Cleanup(func() { syscall.RawSyscall(syscall.SYS_PRCTL, syscall.PR_SET_DUMPABLE, old, 0) })
	if err := setNonDumpable(); err != nil {
		t.Fatal(err)
	}
	if v := get(); v != 0 {
		t.Fatalf("dumpable %d", v)
	}
}
