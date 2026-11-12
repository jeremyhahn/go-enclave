//go:build !linux

package nvblackwell

// gatherGPUEvidence refuses off linux, as probeHost does.
func gatherGPUEvidence([32]byte) ([]gpuEvidence, error) {
	return nil, probeHost()
}
