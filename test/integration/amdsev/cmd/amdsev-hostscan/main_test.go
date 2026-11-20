package main

import (
	"bytes"
	"encoding/hex"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
)

func TestAmdSev_RunRefusesBadArguments(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"no arguments", nil, "usage"},
		{"a pid that is not a number", []string{"qemu", "00"}, "not a process id"},
		{"a zero pid", []string{"0", "00"}, "not a process id"},
		{"an odd needle", []string{"1", "abc"}, "hex"},
		{"an empty needle", []string{"1", ""}, "hex"},
		{"the scanner itself", []string{strconv.Itoa(os.Getpid()), "00"}, "scanner itself"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			if rc := run(tc.args, &out, &errOut); rc != 2 || !strings.Contains(errOut.String(), tc.want) {
				t.Fatalf("rc %d, stderr %q; want 2 naming %q", rc, errOut.String(), tc.want)
			}
		})
	}
}

// TestRunFoundAndNotFound scans a child shell whose $0 is a marker string.
func TestAmdSev_RunFoundAndNotFound(t *testing.T) {
	marker := "amdsev-hostscan-test-marker-5e1f"
	cmd := exec.Command("sh", "-c", "read -r x", marker)
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = in.Close(); _ = cmd.Wait() })
	pid := strconv.Itoa(cmd.Process.Pid)
	// The child's maps exist once exec is done; the marker is in its argv.
	var out, errOut bytes.Buffer
	rc := run([]string{pid, hex.EncodeToString([]byte(marker))}, &out, &errOut)
	if rc != 1 || !strings.Contains(out.String(), "found in pid "+pid) {
		t.Fatalf("marker: rc %d, stdout %q, stderr %q; want 1, found", rc, out.String(), errOut.String())
	}
	out.Reset()
	errOut.Reset()
	rc = run([]string{pid, "f00dfacecafe5e1f00dfacecafe5e1f0"}, &out, &errOut)
	if rc != 0 || !strings.Contains(out.String(), "not found in pid "+pid) {
		t.Fatalf("absent needle: rc %d, stdout %q, stderr %q; want 0, not found", rc, out.String(), errOut.String())
	}
}
