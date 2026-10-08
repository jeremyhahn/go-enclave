// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

//go:build darwin || dragonfly || freebsd || netbsd || openbsd

package enclave

import "golang.org/x/sys/unix"

// The BSDs here are darwin (and ios), DragonFly, FreeBSD, NetBSD and OpenBSD.
// CI runs Linux only, so this path is not exercised on a real BSD;
// classifyRlimit is shared with Linux and unit-tested against both sentinels.

// rlimInfinity is RLIM_INFINITY on the BSDs: the largest int64, not Linux's
// all-bits-set. A test pins its conversion to uint64.
const rlimInfinity = uint64(unix.RLIM_INFINITY)

// memlockRLimitEnforced is always true: the BSDs have no CAP_IPC_LOCK to bypass
// RLIMIT_MEMLOCK. Darwin in practice reports RLIM_INFINITY, which classifies as
// unlimited.
func memlockRLimitEnforced() bool { return true }
