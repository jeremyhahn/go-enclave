// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

package enclave

import "golang.org/x/sys/unix"

// Linux (and Android) excludes by madvise alone. MADV_DONTDUMP exists since
// Linux 3.4 and MADV_DONTFORK since 2.6.16, so a refusal is a denial.
const (
	// coreDumpMapFlags is empty: the exclusion is the madvise.
	coreDumpMapFlags = 0
	coreDumpAdvice   = unix.MADV_DONTDUMP
	forkAdvice       = unix.MADV_DONTFORK
)
