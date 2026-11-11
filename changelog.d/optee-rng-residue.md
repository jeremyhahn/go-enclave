### Fixed

- The residue sweep in backendtest no longer plants the copy it looks for. It matched with bytes.Contains, which holds a short needle whole in registers while it compares. A signal that arrived during the scan made the kernel save those registers into a signal frame on a Go-heap stack, and the next sweep reported them, so the arm-trustzone conformance test failed some of the time on its 32-byte random handle. The sweep now compares one byte of the needle at a time. The residue check is as strict as before. Nothing changes for Go callers.
