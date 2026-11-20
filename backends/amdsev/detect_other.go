//go:build !linux

package amdsev

// hostOS has no SEV-SNP guest driver off Linux: detection reports the
// platform.
func hostOS() guestOS { return guestOS{} }
