package amdsev

import (
	"context"
	"maps"
	"slices"
	"sync"

	enclave "github.com/jeremyhahn/go-enclave"
)

// Name is the backend's name, what [Backend.Name] returns.
const Name = "amd-sev"

// EvidenceFormat is the [enclave.Evidence] format [Backend.Attest] returns:
// the firmware's ATTESTATION_REPORT, byte for byte.
const EvidenceFormat = "sev-snp-report"

// rank is the backend's [enclave.Prober] rank: above the secretmem backend's
// 1, since the SNP firmware keeps guest memory from the host.
const rank = 2

// aes256KeySize is the key length [enclave.AlgorithmAES256GCM] takes.
const aes256KeySize = 32

var (
	_ enclave.Importer   = (*Backend)(nil)
	_ enclave.Attester   = (*Backend)(nil)
	_ enclave.Confiner   = (*Backend)(nil)
	_ enclave.Sweeper    = (*Backend)(nil)
	_ enclave.Prober     = (*Backend)(nil)
	_ enclave.ByteAccess = (*handle)(nil)
	_ enclave.Freezer    = (*handle)(nil)
)

// Backend is the amd-sev backend. Build it with [New]; the zero value names,
// ranks and probes, so main may register one for Detect, but confines
// nothing.
type Backend struct {
	confined bool

	mu      sync.Mutex
	handles map[*handle]struct{}
}

// New returns the backend after the probe's check: one report request over a
// fresh nonce, answered with a report that carries it. Outside an SNP guest
// it returns an [*SNPGuestError] naming the failing step ([ErrSNPGuestUnavailable]
// off Linux on amd64), or ctx.Err(); a backend that cannot attest is never
// built. ctx bounds only waiting; a nil ctx never ends.
func New(ctx context.Context) (*Backend, error) {
	if err := probe(ctx, tsmReportRoot); err != nil {
		return nil, err
	}
	return &Backend{confined: true}, nil
}

// Name returns "amd-sev".
func (*Backend) Name() string { return Name }

// Rank returns 2.
func (*Backend) Rank() int { return rank }

// Probe requests one report over a fresh nonce and checks it carries the
// nonce, as [New] does; it verifies nothing else and leaves no configfs-tsm
// entry behind.
func (*Backend) Probe(ctx context.Context) error { return probe(ctx, tsmReportRoot) }

// ConfinesProcess reports true for a backend [New] built: construction
// succeeded only inside an SNP guest, whose private memory holds the whole
// process.
func (b *Backend) ConfinesProcess() bool { return b.confined }

// Attest returns the SNP firmware's report binding nonce (1 to 64 bytes) in
// REPORT_DATA, as [EvidenceFormat] evidence. A nonce of another length is
// [enclave.ErrInvalidNonce] before any request; a missing interface is an
// [*SNPGuestError]; a request that fails, a report of the wrong size, one
// without the nonce or one another writer raced is an [*SNPReportError].
// It verifies nothing: the relying party's verifier does.
func (*Backend) Attest(ctx context.Context, nonce []byte) (enclave.Evidence, error) {
	if len(nonce) == 0 || len(nonce) > ReportDataSize {
		return enclave.Evidence{}, enclave.ErrInvalidNonce
	}
	out, err := requestReport(ctx, tsmReportRoot, nonce, reportError)
	if err != nil {
		return enclave.Evidence{}, err
	}
	r, err := ParseReport(out)
	if err != nil {
		return enclave.Evidence{}, err
	}
	if !r.HasReportData(nonce) {
		return enclave.Evidence{}, reportError("report-data", ErrReportDataMismatch)
	}
	return enclave.Evidence{Format: EvidenceFormat, Data: out}, nil
}

// Import moves material into a memory enclave ([enclave.NewMemory]) in the
// guest's private memory and wipes material on every return path. It accepts
// every purpose: [enclave.PurposeMaterial], and the key purposes for
// [enclave.AlgorithmAES256GCM] with a 32-byte key, whose handles give
// [enclave.ByteAccess] so the caller wraps in this process. Another algorithm
// is a [*enclave.CapabilityError] naming [enclave.CapabilityImport], and a key
// of another length [enclave.ErrInvalidImport].
func (b *Backend) Import(ctx context.Context, material []byte, opts ...enclave.ImportOption) (enclave.Handle, error) {
	spec, err := enclave.NewImportSpec(opts...)
	if err != nil {
		clear(material)
		return nil, err
	}
	if spec.Purpose != enclave.PurposeMaterial {
		if spec.Algorithm != enclave.AlgorithmAES256GCM {
			clear(material)
			return nil, &enclave.CapabilityError{Backend: Name, Capability: enclave.CapabilityImport}
		}
		if len(material) != aes256KeySize {
			clear(material)
			return nil, enclave.ErrInvalidImport
		}
	}
	if err := ctxErr(ctx); err != nil {
		clear(material)
		return nil, err
	}
	m, err := enclave.NewMemory(material)
	if err != nil {
		return nil, err
	}
	h := &handle{b: b, m: m}
	b.mu.Lock()
	if b.handles == nil {
		b.handles = make(map[*handle]struct{})
	}
	b.handles[h] = struct{}{}
	b.mu.Unlock()
	return h, nil
}

// Sweep destroys every live handle the backend made and returns how many it
// could not, with the first such error. A destroyed handle waits out its
// in-flight borrows, which are bounded by their callers, so ctx is unused.
func (b *Backend) Sweep(context.Context) (int, error) {
	b.mu.Lock()
	hs := slices.Collect(maps.Keys(b.handles))
	b.mu.Unlock()
	held := 0
	var first error
	for _, h := range hs {
		if err := h.Destroy(); err != nil {
			held++
			if first == nil {
				first = err
			}
		}
	}
	return held, first
}

// forget drops a destroyed handle from the sweep set.
func (b *Backend) forget(h *handle) {
	b.mu.Lock()
	delete(b.handles, h)
	b.mu.Unlock()
}

// handle is an imported memory enclave, reporting the backend that made it.
type handle struct {
	b *Backend
	m enclave.ByteAccess
}

func (h *handle) Size() int                             { return h.m.Size() }
func (h *handle) IsAlive() bool                         { return h.m.IsAlive() }
func (h *handle) Backend() enclave.Backend              { return h.b }
func (h *handle) WithBytes(fn func([]byte) error) error { return h.m.WithBytes(fn) }
func (h *handle) EqualTo(other []byte) (bool, error)    { return h.m.EqualTo(other) }

// Destroy wipes and releases the memory enclave, with its errors; once it
// succeeds the handle leaves the sweep set.
func (h *handle) Destroy() error {
	if err := h.m.Destroy(); err != nil {
		return err
	}
	h.b.forget(h)
	return nil
}

// Freeze makes the memory enclave read-only.
func (h *handle) Freeze() error {
	f, ok := h.m.(enclave.Freezer)
	if !ok {
		return &enclave.CapabilityError{Backend: Name, Capability: enclave.CapabilityFreeze}
	}
	return f.Freeze()
}
