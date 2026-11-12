package enclave

import (
	"errors"
	"testing"
	"unsafe"
)

// bareBackend is a Backend with nothing but a name: no Importer, no Confiner.
type bareBackend struct{}

func (bareBackend) Name() string { return "named-only" }

// confinedBackend is a Backend that reports whether it confines the process.
type confinedBackend struct {
	bareBackend
	confines bool
}

func (b confinedBackend) ConfinesProcess() bool { return b.confines }

func TestSealerHelpersUseBackend(t *testing.T) {
	imp := &fakeImporter{}
	for _, tc := range []struct {
		name     string
		mode     Mode
		backend  Backend
		wantErr  error
		wantCap  bool
		importer Importer
	}{
		{name: "nil backend", mode: ModeRootKey, backend: nil, wantErr: ErrInvalidBackend},
		{name: "typed nil backend", mode: ModeRootKey, backend: (*fakeImporter)(nil), wantErr: ErrInvalidBackend},
		{name: "locked memory", mode: ModeRootKey, backend: lockedMemory{}},
		{name: "per-operation without importer", mode: ModePerOperation, backend: bareBackend{}},
		{name: "root key without importer", mode: ModeRootKey, backend: bareBackend{}, wantCap: true},
		{name: "root key with importer", mode: ModeRootKey, backend: imp, importer: imp},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &sealerState{mode: tc.mode}
			err := s.useBackend(tc.backend)
			switch {
			case tc.wantErr != nil:
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("useBackend = %v, want %v", err, tc.wantErr)
				}
				if s.backend != nil {
					t.Fatalf("useBackend kept the refused backend %v", s.backend)
				}
				return
			case tc.wantCap:
				var ce *CapabilityError
				if !errors.As(err, &ce) || ce.Capability != CapabilityImport || ce.Backend != tc.backend.Name() {
					t.Fatalf("useBackend = %v, want a CapabilityError for CapabilityImport", err)
				}
			case err != nil:
				t.Fatalf("useBackend = %v, want nil", err)
			}
			if s.backend != tc.backend {
				t.Fatalf("backend = %v, want %v", s.backend, tc.backend)
			}
			if s.importer != tc.importer {
				t.Fatalf("importer = %v, want %v", s.importer, tc.importer)
			}
		})
	}
}

func TestSealerHelpersKeySchedulesCovered(t *testing.T) {
	for _, tc := range []struct {
		name     string
		erases   bool
		state    sealerState
		wantName string // "" means covered
	}{
		{name: "erasure available", erases: true, state: sealerState{mode: ModeRootKey}},
		{name: "confining backend", state: sealerState{mode: ModeRootKey, backend: confinedBackend{confines: true}}},
		{name: "non-confining backend", state: sealerState{mode: ModePerOperation, backend: confinedBackend{}}, wantName: "dek"},
		{name: "root key without importer", state: sealerState{mode: ModeRootKey}, wantName: "wrapping-key"},
		{name: "root key with importer", state: sealerState{mode: ModeRootKey, backend: bareBackend{}, importer: &fakeImporter{}}, wantName: "dek"},
		{name: "per operation", state: sealerState{mode: ModePerOperation}, wantName: "dek"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			swapSeam(t, &erasesKeySchedules, tc.erases)
			err := tc.state.keySchedulesCovered()
			if tc.wantName == "" {
				if err != nil {
					t.Fatalf("keySchedulesCovered = %v, want nil", err)
				}
				return
			}
			var ke *KeyScheduleExposedError
			if !errors.As(err, &ke) || ke.Name != tc.wantName {
				t.Fatalf("keySchedulesCovered = %v, want a KeyScheduleExposedError naming %q", err, tc.wantName)
			}
		})
	}
}

func TestSealerHelpersIsNilInterface(t *testing.T) {
	var x int
	for _, tc := range []struct {
		name string
		v    any
		want bool
	}{
		{"nil", nil, true},
		{"nil pointer", (*int)(nil), true},
		{"nil map", map[string]int(nil), true},
		{"nil chan", (chan int)(nil), true},
		{"nil func", (func())(nil), true},
		{"nil slice", []byte(nil), true},
		{"nil unsafe pointer", unsafe.Pointer(nil), true},
		{"pointer", &x, false},
		{"map", map[string]int{}, false},
		{"slice", []byte{}, false},
		{"unsafe pointer", unsafe.Pointer(&x), false},
		{"int", 0, false},
		{"struct", lockedMemory{}, false},
	} {
		if got := isNilInterface(tc.v); got != tc.want {
			t.Errorf("isNilInterface(%s) = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestSealerHelpersNilReceiver(t *testing.T) {
	for _, tc := range []struct {
		name string
		s    *envelopeSealer
	}{
		{"nil sealer", nil},
		{"zero sealer", &envelopeSealer{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if m := tc.s.Mode(); m != 0 {
				t.Errorf("Mode = %v, want the zero Mode", m)
			}
			if err := tc.s.usable(); !errors.Is(err, ErrSealerNotConstructed) {
				t.Errorf("usable = %v, want ErrSealerNotConstructed", err)
			}
			tc.s.releaseBlob([]byte("blob")) // must not panic
		})
	}
}

func TestSealerHelpersDestroyOrRetain(t *testing.T) {
	b := newStickyImporter()
	h, err := b.Import(t.Context(), make([]byte, 32))
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	s := &sealerState{}
	failure := errors.New("operation failed")

	if got := s.destroyOrRetain(failure, nil); got != failure {
		t.Fatalf("destroyOrRetain(nil handle) = %v, want the failure unchanged", got)
	}
	if got := s.destroyOrRetain(failure, (*stickyHandle)(nil)); got != failure {
		t.Fatalf("destroyOrRetain(typed nil handle) = %v, want the failure unchanged", got)
	}

	b.refuse.Store(true)
	err = s.destroyOrRetain(failure, h)
	requireCleanupFailure(t, err, failure)
	var ce *CleanupError
	if !errors.As(err, &ce) || ce.Failure != failure {
		t.Fatalf("CleanupError.Failure = %v, want %v", ce, failure)
	}
	if len(s.retained) != 1 || s.retained[0] != h {
		t.Fatalf("retained = %v, want the refused handle", s.retained)
	}

	s.mu.Lock()
	err = s.releaseRetainedLocked()
	s.mu.Unlock()
	requireCleanupFailure(t, err)
	if len(s.retained) != 1 {
		t.Fatalf("retained = %v after a refused retry, want the handle kept", s.retained)
	}

	b.refuse.Store(false)
	s.mu.Lock()
	err = s.releaseRetainedLocked()
	s.mu.Unlock()
	if err != nil {
		t.Fatalf("releaseRetainedLocked = %v, want nil once Destroy succeeds", err)
	}
	if len(s.retained) != 0 {
		t.Fatalf("retained = %v, want empty", s.retained)
	}
	if len(b.live()) != 0 {
		t.Fatal("the released handle still holds its material")
	}

	// A handle whose Destroy succeeds is not retained, and the failure
	// passes through unchanged.
	h2, err := b.Import(t.Context(), make([]byte, 32))
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	s.mu.Lock()
	got := s.destroyOrRetainLocked(failure, h2)
	s.mu.Unlock()
	if got != failure || len(s.retained) != 0 {
		t.Fatalf("destroyOrRetainLocked = %v with %d retained, want the failure and none", got, len(s.retained))
	}
}

func TestSealerHelpersBackendName(t *testing.T) {
	b := newStickyImporter()
	for _, tc := range []struct {
		name string
		h    Handle
		want string
	}{
		{"nil backend", &stickyHandle{}, ""},
		{"backend", &stickyHandle{b: b}, b.Name()},
	} {
		if got := backendName(tc.h); got != tc.want {
			t.Errorf("backendName(%s) = %q, want %q", tc.name, got, tc.want)
		}
	}
}
