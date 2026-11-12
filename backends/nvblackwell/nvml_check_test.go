package nvblackwell

import (
	"errors"
	"testing"
)

// passingSnapshot is what NVML reports on a host the probe accepts: one
// Blackwell GPU, CC on, DevTools off, no multi-GPU mode, ready set.
func passingSnapshot() nvmlSnapshot {
	return nvmlSnapshot{
		Architectures: []uint32{archBlackwell},
		CCFeature:     ccFeatureEnabled,
		DevToolsMode:  devToolsModeOff,
		MultiGPUMode:  multiGPUModeNone,
		GPUsReady:     gpusReadyTrue,
	}
}

// TestCheckSnapshotAccepts covers the one snapshot the probe passes.
func TestCheckSnapshotAccepts(t *testing.T) {
	if err := checkSnapshot(passingSnapshot()); err != nil {
		t.Fatalf("checkSnapshot(passing) = %v, want nil", err)
	}
}

// TestCheckSnapshotRefusesConfCompute covers every snapshot refused with a
// ConfComputeError: no GPU, CC off, DevTools on, more GPUs than Q6 allows, a
// multi-GPU mode, and the ready state unset.
func TestCheckSnapshotRefusesConfCompute(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*nvmlSnapshot)
		want   ConfComputeError
		text   string
	}{
		{
			name:   "no GPU",
			mutate: func(s *nvmlSnapshot) { s.Architectures = nil },
			want:   ConfComputeError{Device: SystemWide, Setting: "GPU count", Value: "0"},
			text:   `nvblackwell: GPU confidential computing is not usable: system: GPU count is "0"`,
		},
		{
			name:   "CC off",
			mutate: func(s *nvmlSnapshot) { s.CCFeature = 0 },
			want:   ConfComputeError{Device: SystemWide, Setting: "CC feature", Value: "disabled"},
			text:   `nvblackwell: GPU confidential computing is not usable: system: CC feature is "disabled"`,
		},
		{
			name:   "DevTools on",
			mutate: func(s *nvmlSnapshot) { s.DevToolsMode = 1 },
			want:   ConfComputeError{Device: SystemWide, Setting: "DevTools mode", Value: "on"},
			text:   `nvblackwell: GPU confidential computing is not usable: system: DevTools mode is "on"`,
		},
		{
			name: "two GPUs",
			mutate: func(s *nvmlSnapshot) {
				s.Architectures = []uint32{archBlackwell, archBlackwell}
			},
			want: ConfComputeError{Device: SystemWide, Setting: "GPU count", Value: "2"},
			text: `nvblackwell: GPU confidential computing is not usable: system: GPU count is "2"`,
		},
		{
			name:   "protected PCIe multi-GPU mode",
			mutate: func(s *nvmlSnapshot) { s.MultiGPUMode = 1 },
			want:   ConfComputeError{Device: SystemWide, Setting: "multi-GPU mode", Value: "protected PCIe"},
			text:   `nvblackwell: GPU confidential computing is not usable: system: multi-GPU mode is "protected PCIe"`,
		},
		{
			name:   "unknown multi-GPU mode",
			mutate: func(s *nvmlSnapshot) { s.MultiGPUMode = 7 },
			want:   ConfComputeError{Device: SystemWide, Setting: "multi-GPU mode", Value: "7"},
			text:   `nvblackwell: GPU confidential computing is not usable: system: multi-GPU mode is "7"`,
		},
		{
			name:   "ready state unset",
			mutate: func(s *nvmlSnapshot) { s.GPUsReady = 0 },
			want:   ConfComputeError{Device: SystemWide, Setting: "GPUs ready state", Value: "not ready"},
			text:   `nvblackwell: GPU confidential computing is not usable: system: GPUs ready state is "not ready"`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			snap := passingSnapshot()
			tc.mutate(&snap)
			err := checkSnapshot(snap)
			var ce *ConfComputeError
			if !errors.As(err, &ce) || *ce != tc.want {
				t.Fatalf("checkSnapshot = %v, want %+v", err, tc.want)
			}
			if !errors.Is(err, ErrConfComputeUnavailable) {
				t.Errorf("checkSnapshot = %v, want it to match ErrConfComputeUnavailable", err)
			}
			if err.Error() != tc.text {
				t.Errorf("checkSnapshot text = %q, want %q", err.Error(), tc.text)
			}
		})
	}
}

// TestCheckSnapshotRefusesArchitecture covers a GPU that is not Blackwell:
// the error names that GPU and its architecture, ahead of any CC setting.
func TestCheckSnapshotRefusesArchitecture(t *testing.T) {
	const hopper = 9
	snap := passingSnapshot()
	snap.Architectures = []uint32{archBlackwell, hopper}
	snap.CCFeature = 0
	err := checkSnapshot(snap)
	var ae *GPUArchitectureError
	if !errors.As(err, &ae) || ae.Device != 1 || ae.Architecture != hopper {
		t.Fatalf("checkSnapshot = %v, want a *GPUArchitectureError for gpu 1, architecture %d", err, hopper)
	}
	if !errors.Is(err, ErrUnsupportedGPU) || errors.Is(err, ErrConfComputeUnavailable) {
		t.Errorf("checkSnapshot = %v, want it to match ErrUnsupportedGPU only", err)
	}
	const text = "nvblackwell: the GPU is not a Blackwell part: gpu 1: architecture 9"
	if err.Error() != text {
		t.Errorf("checkSnapshot text = %q, want %q", err.Error(), text)
	}
}
