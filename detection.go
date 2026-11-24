// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

package enclave

import (
	"context"
	"slices"
	"strings"
)

// Backend detection: main asks which registered backend is the most secure
// one this host can run, and hands upstream that one. The design is
// docs/backend-detection/architecture.md.

// ProbeResult records what [Detect] found for one registered backend.
type ProbeResult struct {
	// Backend is the name the backend is registered under.
	Backend string
	// Rank is what its [Prober.Rank] reported, or 0 when it is no Prober.
	Rank int
	// Err is nil when the backend is usable on this host, and otherwise why
	// Detect passed it over: a [*CapabilityError] for
	// [CapabilityProbe] when the backend is no [Prober], or a [*ProbeError]
	// carrying what its Probe returned.
	Err error
}

// Detect probes every registered backend ([Register]) and returns the most
// secure one usable on this host: of the [Prober] backends whose Probe returns
// nil, the one with the highest [Prober.Rank]. When none ranks above the
// locked-memory backend, it returns [DefaultBackend], so it always returns a
// backend and never fails. A tie goes to the locked-memory backend, then to
// the name first in byte order: a backend must rank strictly above another to
// be selected in its place.
//
// The results have one entry per registered backend, the default included, in
// name order, which is also the order Detect probes them in. Each says the
// backend's rank and, for one passed over as unusable, why; a usable backend
// other than the one returned was outranked.
//
// Detect runs only when called: importing this package probes nothing and
// registers nothing. It reads the registry once and then probes without
// holding it, passing ctx to every Probe; a backend registered meanwhile waits
// for the next call. Detect does not recover a panic raised by a Probe. It is
// safe for concurrent use.
func Detect(ctx context.Context) (Backend, []ProbeResult) {
	backendsMu.RLock()
	candidates := make([]Backend, 0, len(backends))
	for _, b := range backends {
		candidates = append(candidates, b)
	}
	backendsMu.RUnlock()
	slices.SortFunc(candidates, func(a, b Backend) int { return strings.Compare(a.Name(), b.Name()) })

	selected, selectedRank := DefaultBackend(), lockedMemoryRank
	results := make([]ProbeResult, 0, len(candidates))
	for _, b := range candidates {
		result := probe(ctx, b)
		results = append(results, result)
		if result.Err == nil && result.Rank > selectedRank {
			selected, selectedRank = b, result.Rank
		}
	}
	return selected, results
}

// probe ranks and probes one registered backend.
func probe(ctx context.Context, b Backend) ProbeResult {
	name := b.Name()
	p, ok := b.(Prober)
	if !ok {
		return ProbeResult{Backend: name, Err: &CapabilityError{Backend: name, Capability: CapabilityProbe}}
	}
	result := ProbeResult{Backend: name, Rank: p.Rank()}
	if err := p.Probe(ctx); err != nil {
		result.Err = &ProbeError{Backend: name, Cause: err}
	}
	return result
}
