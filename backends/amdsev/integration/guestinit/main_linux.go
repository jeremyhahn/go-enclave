// Command guestinit is /init of the SEV-SNP kit's guest initrd. As PID 1 it
// mounts /dev, /proc, /sys, configfs and /tmp, lifts RLIMIT_MEMLOCK, loads the
// kit's modules (the TSM report interface and the sev-guest driver) in order,
// runs /amdsev.test as root with the selection the kernel command line gives
// (package guestcfg), prints `amdsev-guest: exit <status>` and powers the
// guest off. scripts/amd-sev-snp/guest-image.sh builds it static.
package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"

	"golang.org/x/sys/unix"

	"github.com/jeremyhahn/go-enclave/backends/amdsev/integration/guestcfg"
)

// moduleInitCompressedFile is finit_module's MODULE_INIT_COMPRESSED_FILE:
// the kernel decompresses the .ko.zst itself.
const moduleInitCompressedFile = 4

func main() {
	status := run()
	fmt.Printf("%s%d\n", guestcfg.ExitMarker, status)
	_ = os.Stdout.Sync()
	unix.Sync()
	_ = unix.Reboot(unix.LINUX_REBOOT_CMD_POWER_OFF)
	os.Exit(status)
}

// run does the init's work and returns the status to report.
func run() int {
	fail := func(format string, a ...any) int {
		fmt.Printf("guestinit: "+format+"\n", a...)
		return 2
	}
	for _, m := range mounts {
		if err := os.MkdirAll(m.dir, 0o750); err != nil {
			return fail("mkdir %s: %v", m.dir, err)
		}
		if err := unix.Mount(m.source, m.dir, m.fstype, 0, ""); err != nil && err != unix.EBUSY {
			return fail("mount %s on %s: %v", m.fstype, m.dir, err)
		}
	}
	lim := unix.Rlimit{Cur: unix.RLIM_INFINITY, Max: unix.RLIM_INFINITY}
	if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &lim); err != nil {
		return fail("RLIMIT_MEMLOCK: %v", err)
	}
	mods, err := modulesInOrder("/modules")
	if err != nil {
		return fail("%v", err)
	}
	for _, m := range mods {
		if err := loadModule(m); err != nil {
			return fail("load %s: %v", filepath.Base(m), err)
		}
	}
	cmdline, err := os.ReadFile("/proc/cmdline")
	if err != nil {
		return fail("%v", err)
	}
	cfg, err := guestcfg.Parse(string(cmdline))
	if err != nil {
		return fail("%v", err)
	}
	fmt.Printf("guestinit: mode %s, %d modules, running %s\n", cfg.Mode, len(mods), cfg.Run)
	// The binary is the initrd's own; its arguments are flag/value pairs from
	// the command line guest.sh writes, passed as argv without a shell.
	cmd := exec.CommandContext(context.Background(), "/amdsev.test", testArgs(cfg)...) //nolint:gosec // fixed binary, argv only
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stdout
	cmd.Env = []string{"PATH=/", "HOME=/tmp", "TMPDIR=/tmp", "GOTRACEBACK=all"}
	cmd.Dir = "/tmp"
	if err := cmd.Run(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return ee.ExitCode()
		}
		return fail("/amdsev.test: %v", err)
	}
	return 0
}

type mount struct{ source, dir, fstype string }

var mounts = []mount{
	{"devtmpfs", "/dev", "devtmpfs"},
	{"proc", "/proc", "proc"},
	{"sysfs", "/sys", "sysfs"},
	{"configfs", "/sys/kernel/config", "configfs"},
	{"tmpfs", "/tmp", "tmpfs"},
}

func loadModule(path string) error {
	f, err := os.Open(path) //nolint:gosec // a file of the kit's initrd
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	return unix.FinitModule(int(f.Fd()), "", moduleInitCompressedFile)
}

// testArgs are /amdsev.test's arguments for cfg.
func testArgs(cfg guestcfg.Config) []string {
	return []string{"-test.run", cfg.Run, "-test.v", "-test.count=1", "-test.timeout=" + strconv.Itoa(int(cfg.Hold.Seconds())+1200) + "s"}
}
