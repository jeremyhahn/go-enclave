package inteltdx

// The kernel interfaces the backend reaches, as docs/backends/intel-tdx.md
// "Hardware, firmware and kernel requirements" lists them.
const (
	// guestDevice is the TDX guest driver's misc device (Linux 6.2).
	guestDevice = "/dev/tdx_guest"
	// tsmReportRoot is the configfs-tsm report tree (Linux 6.7).
	tsmReportRoot = "/sys/kernel/config/tsm/report"
	// tsmProvider is the provider a TD's report directory names; it is also
	// the name of outblob's format.
	tsmProvider = "tdx_guest"
)
