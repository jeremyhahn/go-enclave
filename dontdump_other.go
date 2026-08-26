// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-enclave.
//
// go-enclave is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

//go:build !linux

package enclave

// excludeFromCoreDump is a no-op where the platform offers no per-mapping
// equivalent of MADV_DONTDUMP.
//
// It reports success rather than failure deliberately: refusing to build any
// enclave at all on such a platform would remove mlock, the guard pages and the
// canary as well, which is strictly worse than losing one of the four. On these
// platforms the process-wide RLIMIT_CORE hardening is the whole story, and
// [CoreDumpsDisabled] reports whether it took.
func excludeFromCoreDump([]byte) error { return nil }
