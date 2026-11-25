package amdsev

import (
	"errors"
	"os"
	"syscall"
	"testing"
)

func TestGuestErrorContract(t *testing.T) {
	cause := &os.PathError{Op: "open", Path: devicePath, Err: syscall.ENOENT}
	next := &GuestError{Path: tsmRoot, Op: "provider", Cause: &ProviderError{Provider: "tdx_guest"}}
	err := error(&GuestError{Path: devicePath, Op: "open", Cause: cause, Next: next})

	if !errors.Is(err, ErrSNPGuestUnavailable) {
		t.Fatal("GuestError does not match ErrSNPGuestUnavailable")
	}
	if !errors.Is(err, syscall.ENOENT) {
		t.Fatal("GuestError does not unwrap to its OS error")
	}
	if !errors.Is(err, ErrWrongProvider) {
		t.Fatal("GuestError does not unwrap to Next's cause")
	}
	if errors.Is(err, ErrReportRefused) {
		t.Fatal("GuestError matches a sentinel it does not carry")
	}
	var ge *GuestError
	if !errors.As(err, &ge) || ge.Op != "open" {
		t.Fatalf("errors.As: %v", ge)
	}
	var pe *ProviderError
	if !errors.As(err, &pe) || pe.Provider != "tdx_guest" {
		t.Fatalf("errors.As ProviderError: %v", pe)
	}
	want := `amdsev: not an SEV-SNP guest: open "/dev/sev-guest": open /dev/sev-guest: no such file or directory; ` +
		`amdsev: not an SEV-SNP guest: provider "/sys/kernel/config/tsm/report": ` +
		`amdsev: the configfs-tsm provider is not sev_guest: "tdx_guest"`
	if got := err.Error(); got != want {
		t.Fatalf("Error() = %q, want %q", got, want)
	}
}

func TestGuestErrorBare(t *testing.T) {
	err := &GuestError{Op: "platform"}
	if got, want := err.Error(), "amdsev: not an SEV-SNP guest: platform"; got != want {
		t.Fatalf("Error() = %q, want %q", got, want)
	}
	if len(err.Unwrap()) != 0 {
		t.Fatal("bare GuestError unwraps to something")
	}
}

func TestReportErrorContract(t *testing.T) {
	err := error(&ReportError{Status: 22, Size: 0})
	if !errors.Is(err, ErrReportRefused) || errors.Is(err, ErrWrongProvider) {
		t.Fatal("ReportError matches the wrong sentinel")
	}
	if got, want := err.Error(), "amdsev: the SEV-SNP firmware refused the report request: status 22, report size 0"; got != want {
		t.Fatalf("Error() = %q, want %q", got, want)
	}
}

func TestPolicyErrorContract(t *testing.T) {
	err := error(&PolicyError{Policy: 0xa0000})
	if !errors.Is(err, ErrDebugPolicy) || errors.Is(err, ErrReportRefused) {
		t.Fatal("PolicyError matches the wrong sentinel")
	}
	if got, want := err.Error(), "amdsev: the SEV-SNP guest policy allows debugging: policy 0xa0000"; got != want {
		t.Fatalf("Error() = %q, want %q", got, want)
	}
}

func TestProviderErrorContract(t *testing.T) {
	err := error(&ProviderError{Provider: "tdx_guest"})
	if !errors.Is(err, ErrWrongProvider) || errors.Is(err, ErrReportRefused) {
		t.Fatal("ProviderError matches the wrong sentinel")
	}
}
