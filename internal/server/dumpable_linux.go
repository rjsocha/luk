package server

import "syscall"

// setNonDumpable makes the process non-dumpable: no core dump, and no
// other process of the same user may attach to it or read its memory
// through /proc.
func setNonDumpable() error {
	if _, _, e := syscall.RawSyscall(syscall.SYS_PRCTL, syscall.PR_SET_DUMPABLE, 0, 0); e != 0 {
		return e
	}
	return nil
}
