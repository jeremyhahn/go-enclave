package amdsev_test

import (
	"bufio"
	"errors"
	"os/exec"
	"syscall"
	"testing"
	"time"
)

// startGroup starts script under sh in a process group of its own and reaps
// the shell in the background, as the hardware test does with the guest
// launcher. script prints a line once it has forked its children, so the
// group holds descendants and not only the shell.
func startGroup(t *testing.T, script string) int {
	t.Helper()
	cmd := exec.Command("sh", "-c", script)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	pgid := cmd.Process.Pid
	if _, err := bufio.NewReader(stdout).ReadString('\n'); err != nil {
		_ = syscall.Kill(-pgid, syscall.SIGKILL)
		_ = cmd.Wait()
		t.Fatalf("the group's ready line: %v", err)
	}
	go func() { _ = cmd.Wait() }()
	return pgid
}

func assertGroupGone(t *testing.T, pgid int) {
	t.Helper()
	if err := syscall.Kill(-pgid, 0); !errors.Is(err, syscall.ESRCH) {
		_ = syscall.Kill(-pgid, syscall.SIGKILL)
		t.Fatalf("process group %d still has members: kill(-pgid, 0) = %v", pgid, err)
	}
}

func TestTerminateGroup_EndsEveryProcessOfTheGroup(t *testing.T) {
	pgid := startGroup(t, "sleep 600 & sleep 600 & echo ready; wait")
	if err := terminateGroup(pgid, 5*time.Second); err != nil {
		t.Fatal(err)
	}
	assertGroupGone(t, pgid)
}

func TestTerminateGroup_KillsAGroupThatIgnoresSIGTERM(t *testing.T) {
	pgid := startGroup(t, "trap '' TERM; sleep 600 & sleep 600 & echo ready; wait")
	if err := terminateGroup(pgid, 200*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	assertGroupGone(t, pgid)
}

func TestTerminateGroup_AGoneGroupIsNotAnError(t *testing.T) {
	pgid := startGroup(t, "sleep 600 & sleep 600 & echo ready; wait")
	if err := terminateGroup(pgid, time.Second); err != nil {
		t.Fatal(err)
	}
	if err := terminateGroup(pgid, time.Second); err != nil {
		t.Fatalf("a second call on a gone group: %v", err)
	}
}
