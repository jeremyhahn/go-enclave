package amdsev_test

import (
	"errors"
	"fmt"
	"syscall"
	"time"
)

// groupKillWait bounds how long terminateGroup waits for the group to go
// after SIGKILL, which the kernel delivers at once; the wait covers the
// parent reaping the members.
const groupKillWait = 30 * time.Second

// terminateGroup ends every process of process group pgid: SIGTERM to the
// group, up to grace for the members to exit, then SIGKILL to the group. It
// returns once no process of the group is left, reaped included, or an error
// if one is still there groupKillWait after SIGKILL. A group already gone is
// not an error.
func terminateGroup(pgid int, grace time.Duration) error {
	if pgid <= 1 {
		return fmt.Errorf("process group %d: not a launched group", pgid)
	}
	if err := syscall.Kill(-pgid, syscall.SIGTERM); errors.Is(err, syscall.ESRCH) {
		return nil
	}
	if groupGone(pgid, grace) {
		return nil
	}
	if err := syscall.Kill(-pgid, syscall.SIGKILL); errors.Is(err, syscall.ESRCH) {
		return nil
	}
	if groupGone(pgid, groupKillWait) {
		return nil
	}
	return fmt.Errorf("process group %d still has members %v after SIGKILL", pgid, groupKillWait)
}

// groupGone polls until process group pgid has no member, reaped included,
// or wait passes.
func groupGone(pgid int, wait time.Duration) bool {
	deadline := time.Now().Add(wait)
	for {
		if errors.Is(syscall.Kill(-pgid, 0), syscall.ESRCH) {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(10 * time.Millisecond)
	}
}
