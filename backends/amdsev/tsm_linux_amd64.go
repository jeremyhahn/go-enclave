package amdsev

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
)

// requestReport makes one report through configfs-tsm under root: it creates
// its own entry, checks the provider is sev_guest, writes data to inblob,
// reads outblob, checks that generation did not move, and removes the entry
// on every path. A missing or refusing interface (mkdir, provider) is an
// [*SNPGuestError]; a later step's failure is what fail makes of it, so the
// probe reports "not here" and Attest "this request failed". ctx is checked
// between steps: each configfs access is one bounded syscall.
func requestReport(ctx context.Context, root string, data []byte, fail func(string, error) error) ([]byte, error) {
	if err := ctxErr(ctx); err != nil {
		return nil, err
	}
	entry, err := os.MkdirTemp(root, "amdsev-")
	if err != nil {
		return nil, guestError("mkdir", err)
	}
	out, err := readEntry(ctx, entry, data, fail)
	if rerr := os.Remove(entry); rerr != nil && err == nil {
		return nil, fail("rmdir", rerr)
	}
	return out, err
}

// readEntry runs the report request on a fresh entry.
func readEntry(ctx context.Context, entry string, data []byte, fail func(string, error) error) ([]byte, error) {
	provider, err := readAttr(entry, "provider")
	if err != nil {
		return nil, guestError("provider", err)
	}
	if string(bytes.TrimSpace(provider)) != providerSEVGuest {
		return nil, guestError("provider", ErrProviderMismatch)
	}
	if err := ctxErr(ctx); err != nil {
		return nil, err
	}
	if err := writeAttr(filepath.Join(entry, "inblob"), data); err != nil {
		return nil, fail("inblob", err)
	}
	before, err := readAttr(entry, "generation")
	if err != nil {
		return nil, fail("generation", err)
	}
	if err := ctxErr(ctx); err != nil {
		return nil, err
	}
	out, err := readAttr(entry, "outblob")
	if err != nil {
		return nil, fail("outblob", err)
	}
	after, err := readAttr(entry, "generation")
	if err != nil {
		return nil, fail("generation", err)
	}
	if !bytes.Equal(before, after) {
		return nil, fail("generation", ErrGenerationMoved)
	}
	return out, nil
}

// writeAttr writes b to an existing configfs attribute in one write. A
// binary attribute commits on close, so the close error is the write's.
func writeAttr(path string, b []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY, 0) //nolint:gosec // an attribute of this process's own configfs-tsm entry
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// readAttr reads the attribute name of a configfs-tsm entry this process made.
func readAttr(entry, name string) ([]byte, error) {
	return os.ReadFile(filepath.Join(entry, name)) //nolint:gosec // entry is this process's own configfs-tsm entry, name a fixed attribute
}
