package tpm

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/google/go-tpm/tpm2"
)

// A command an interrupt cuts off may still run to completion in the TPM,
// and the handle it creates is then known only to the TPM. Behind the
// kernel's resource manager, reopening the device flushes it. On a device
// without one, the provider holds the TPM's only connection, so a call
// lists the TPM's transient objects and loaded sessions before its first
// command; after an interrupt, the reclaim reopens the stream, lists them
// again, and flushes each handle the first list lacks. A reclaim that
// fails stays due, and the next call finishes it before sending a command.

// maxListedHandles bounds one handle list: a TPM holds a few transient
// objects and sessions, and this many leaves room for any TPM.
const maxListedHandles = 256

// begin lists the TPM's handles before the call's first command, on a
// device without a resource manager.
func (c *call) begin() error {
	if c.p.dev.managed() {
		return nil
	}
	hs, err := c.p.list(c.ctx)
	if err != nil {
		if c.ctx.Err() != nil {
			return c.ctx.Err()
		}
		return err
	}
	c.before, c.listed = hs, true
	return nil
}

// reclaim reopens a device an interrupted call left out of step and, when a
// reclaim is due, flushes the handles the interrupted call may have created.
// The caller holds the semaphore and bounds ctx.
func (p *KeyProtector) reclaim(ctx context.Context) error {
	if err := p.dev.reopen(ctx); err != nil {
		return err
	}
	if !p.reclaimDue {
		return nil
	}
	hs, err := p.list(ctx)
	if err != nil {
		return err
	}
	for _, h := range hs {
		if slices.Contains(p.baseline, h) {
			continue
		}
		if err := p.retry(ctx, func() error { return p.dev.flush(ctx, h) }); err != nil {
			return mapResult(cmdFlushContext, err)
		}
	}
	p.reclaimDue, p.baseline = false, nil
	return nil
}

// list returns the TPM's transient objects and loaded sessions.
func (p *KeyProtector) list(ctx context.Context) ([]tpm2.TPMHandle, error) {
	var hs []tpm2.TPMHandle
	err := p.retry(ctx, func() (err error) {
		hs, err = p.dev.handles(ctx)
		return err
	})
	if err != nil {
		return nil, &CommandError{Command: "TPM2_GetCapability", Err: err}
	}
	return hs, nil
}

// retry sends one command, and again while the TPM asks to, up to the
// provider's attempts and while ctx lasts. It returns the last error.
func (p *KeyProtector) retry(ctx context.Context, send func() error) error {
	for attempt := 1; ; attempt++ {
		err := send()
		if !retryable(err) || attempt >= p.attempts {
			return err
		}
		t := time.NewTimer(p.backoff << (attempt - 1))
		select {
		case <-ctx.Done():
			t.Stop()
			return err
		case <-t.C:
		}
	}
}

// retryable reports whether the TPM asked for the command again.
func retryable(err error) bool {
	var rc tpm2.TPMRC
	return errors.As(err, &rc) &&
		(errors.Is(rc, tpm2.TPMRCRetry) || errors.Is(rc, tpm2.TPMRCYielded) || errors.Is(rc, tpm2.TPMRCTesting))
}

// handles lists the TPM's transient objects and loaded sessions with
// TPM2_GetCapability, at most maxListedHandles of each.
func (d *tpmDevice) handles(ctx context.Context) ([]tpm2.TPMHandle, error) {
	var hs []tpm2.TPMHandle
	for _, ht := range []tpm2.TPMHT{tpm2.TPMHTTransient, tpm2.TPMHTLoadedSession} {
		listed, err := d.listType(ctx, ht)
		if err != nil {
			return nil, err
		}
		hs = append(hs, listed...)
	}
	return hs, nil
}

// listType lists the handles of one type, following MoreData.
func (d *tpmDevice) listType(ctx context.Context, ht tpm2.TPMHT) ([]tpm2.TPMHandle, error) {
	defer d.t.wipe()
	var hs []tpm2.TPMHandle
	next := uint32(ht) << 24
	for left := uint32(maxListedHandles); left > 0; {
		rsp, err := tpm2.GetCapability{
			Capability:    tpm2.TPMCapHandles,
			Property:      next,
			PropertyCount: left,
		}.Execute(d.t.bind(ctx))
		if err != nil {
			return nil, err
		}
		got, err := rsp.CapabilityData.Data.Handles()
		if err != nil {
			return nil, err
		}
		// The TPM lists handles in ascending order from next: one of
		// another type, below next or out of order is not taken, so a
		// device repeating a page cannot list a handle twice.
		n := len(hs)
		for _, h := range got.Handle {
			if uint32(h)>>24 == uint32(ht) && uint32(h) >= next && left > 0 {
				hs = append(hs, h)
				next = uint32(h) + 1
				left--
			}
		}
		if !rsp.MoreData || len(hs) == n {
			return hs, nil
		}
	}
	return hs, nil
}

func (d *tpmDevice) managed() bool { return d.rm }

func (d *tpmDevice) outOfStep() bool { return d.t.outOfStep.Load() }
