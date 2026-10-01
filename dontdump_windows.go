// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

//go:build windows

package enclave

// excludeFromCoreDump is a no-op on Windows. The one per-region exclusion
// Windows has was evaluated and is deliberately NOT used; this records why, so
// the decision is not re-made by someone who finds the API and not the limit.
//
// The API is WerRegisterExcludedMemoryBlock (wer.dll, Windows 10 1703 and
// later), paired with WerUnregisterExcludedMemoryBlock. Per its documentation
// it removes a block from the Windows Error Reporting report and nothing else:
// a dump written by another process through MiniDumpWriteDump — procdump, a
// debugger, anything holding PROCESS_VM_READ — still contains the pages, and
// VirtualLock does not change that. It was rejected for a structural reason,
// not for that partial coverage:
//
//   - It is CAPPED. Registration fails with
//     HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER) once the process's
//     registered entries exceed WER_MAX_REGISTERED_ENTRIES — 512 in werapi.h
//     — and that pool is SHARED with every other WER registration made by any
//     code in the process (WerRegisterCustomMetadata documents the same limit;
//     WerRegisterMemoryBlock and WerRegisterFile document a shared limit on
//     registered blocks and files). Every enclave is its own VirtualAlloc reservation, fenced by
//     its own guard pages, so it needs its own entry: the cap is a cap on live
//     enclaves.
//
//   - Failing closed, as Linux does on a refused madvise, would therefore make
//     the 513th live enclave — or the 13th, if a crash-reporting SDK in the
//     same process holds 500 entries — fail with [ErrLockedMemoryUnavailable].
//     That ceiling is invisible to [Allocator] budgets and [LockedSize], is set
//     partly by code this package does not own, and runs the other way too:
//     enclaves holding the shared pool make SOME OTHER library's WER
//     registration fail. A failure in one subsystem reaching into another is
//     the exact property this package was built to remove (see mapping.go,
//     "Why this is not memguard").
//
//   - Registering best effort instead — ignore the refusal, keep the enclave —
//     would make the exclusion silently partial: some enclaves excluded, some
//     not, nothing to tell them apart. That is the attempted-and-forgotten
//     pattern every other platform's exclusion here was written to replace.
//
// So on Windows no enclave page is excluded from any dump, there is no
// process-wide control either ([CoreDumpsDisabled] reports
// [ErrCoreDumpLimitUnsupported]), and dump exposure has to be governed by host
// policy: WER LocalDumps configuration and who may open the process.
//
// It reports success for the reason dontdump_other.go gives: refusing every
// allocation would remove the lock, the guard pages and the canary too, which
// is strictly worse than losing the one control the platform cannot give
// without a shared, capped resource.
func excludeFromCoreDump([]byte) error { return nil }
