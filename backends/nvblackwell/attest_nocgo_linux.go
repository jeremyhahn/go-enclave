//go:build linux && !cgo

package nvblackwell

// gatherGPUEvidence refuses in a build without cgo, as probeNVML does.
func gatherGPUEvidence([32]byte) ([]gpuEvidence, error) {
	return nil, probeNVML()
}
