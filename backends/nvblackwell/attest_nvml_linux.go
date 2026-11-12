//go:build linux && cgo

package nvblackwell

import (
	"bytes"
	"fmt"

	"github.com/NVIDIA/go-nvml/pkg/nvml"
)

// gatherGPUEvidence loads NVML, checks the snapshot again in the same NVML
// session, then asks every GPU for its attestation report over nonce and for
// its certificate chains. NVML is shut down whenever Init succeeded.
func gatherGPUEvidence(nonce [32]byte) ([]gpuEvidence, error) {
	if ret := nvml.Init(); ret != nvml.SUCCESS {
		return nil, &NVMLError{Call: "nvmlInit_v2", Return: int(ret)}
	}
	gpus, err := gpuEvidenceInSession(nonce)
	if ret := nvml.Shutdown(); ret != nvml.SUCCESS && err == nil {
		err = &NVMLError{Call: "nvmlShutdown", Return: int(ret)}
	}
	if err != nil {
		return nil, err
	}
	return gpus, nil
}

func gpuEvidenceInSession(nonce [32]byte) ([]gpuEvidence, error) {
	snap, err := gatherNVML()
	if err != nil {
		return nil, err
	}
	if err := checkSnapshot(snap); err != nil {
		return nil, err
	}
	gpus := make([]gpuEvidence, 0, len(snap.Architectures))
	for i := range len(snap.Architectures) {
		dev, ret := nvml.DeviceGetHandleByIndex(i)
		if ret != nvml.SUCCESS {
			return nil, &GPUAttestationError{Device: i, Cause: &NVMLError{Call: "nvmlDeviceGetHandleByIndex_v2", Return: int(ret)}}
		}
		g, err := deviceEvidence(dev, nonce)
		if err != nil {
			return nil, &GPUAttestationError{Device: i, Cause: err}
		}
		gpus = append(gpus, g)
	}
	return gpus, nil
}

// deviceEvidence copies one GPU's report and chains out of NVML's buffers,
// refusing a size NVML reports beyond its own buffer.
func deviceEvidence(dev nvml.Device, nonce [32]byte) (gpuEvidence, error) {
	var g gpuEvidence
	report := nvml.ConfComputeGpuAttestationReport{Nonce: nonce}
	if ret := dev.GetConfComputeGpuAttestationReport(&report); ret != nvml.SUCCESS {
		return g, &NVMLError{Call: "nvmlDeviceGetConfComputeGpuAttestationReport", Return: int(ret)}
	}
	var err error
	if g.Report, err = sized(report.AttestationReport[:], report.AttestationReportSize, "attestation report"); err != nil {
		return g, err
	}
	if report.IsCecAttestationReportPresent != 0 {
		if g.CECReport, err = sized(report.CecAttestationReport[:], report.CecAttestationReportSize, "CEC attestation report"); err != nil {
			return g, err
		}
	}
	cert, ret := dev.GetConfComputeGpuCertificate()
	if ret != nvml.SUCCESS {
		return g, &NVMLError{Call: "nvmlDeviceGetConfComputeGpuCertificate", Return: int(ret)}
	}
	if g.CertChain, err = sized(cert.CertChain[:], cert.CertChainSize, "certificate chain"); err != nil {
		return g, err
	}
	if g.AttestationCertChain, err = sized(cert.AttestationCertChain[:], cert.AttestationCertChainSize, "attestation certificate chain"); err != nil {
		return g, err
	}
	return g, nil
}

// sized returns a copy of buf's first n bytes; n of 0 or beyond buf is an
// error naming what.
func sized(buf []byte, n uint32, what string) ([]byte, error) {
	if n == 0 || uint64(n) > uint64(len(buf)) {
		return nil, fmt.Errorf("%s size %d outside 1 to %d", what, n, len(buf))
	}
	return bytes.Clone(buf[:n]), nil
}
