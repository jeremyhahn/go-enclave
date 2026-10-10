// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// SPDX-License-Identifier: MIT
//
// This file is part of go-enclave. Use of this source code is governed by the
// MIT license that can be found in the LICENSE file.

//go:build integration

package enclave_test

import (
	"context"
	"crypto/rand"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	enclave "github.com/jeremyhahn/go-enclave"
	"github.com/jeremyhahn/go-enclave/providertest"
)

// Covers providertest's failure paths, which the conformance run of a sound
// provider (provider_test.go) never takes: each case here runs
// providertest.TestProvider, in the devcontainer, against a provider that breaks
// one property of the seam (provider_fakes_test.go), and requires the run to
// report that property, by type, and nothing else. What a case reaches that a
// unit test cannot is the real thing underneath: locked memory for the
// suite's destinations and the residue sweep through /proc/self/mem.

var (
	perOperation = []enclave.Mode{enclave.ModePerOperation}
	rootKey      = []enclave.Mode{enclave.ModeRootKey}
	bothModes    = []enclave.Mode{enclave.ModeRootKey, enclave.ModePerOperation}
)

// scenario is one provider and the verdict TestProvider must reach on it.
type scenario struct {
	name     string
	modes    []enclave.Mode // defaults to ModePerOperation
	provider providerFor

	// sweep runs the residue sweep; otherwise the run skips it, which keeps a
	// case about another property from being about the sweep too.
	sweep       bool
	publicKey   bool
	forge       func(p enclave.KeyProtector, key []byte) ([]byte, error)
	skipForgery string
	singleUse   string

	// want is the set of properties the run must report as failed: exactly
	// these, or at least these when loose (a fault whose other consequences
	// are not the point).
	want  []string
	loose bool
	// unmeasured is the set of properties the run must report as not measured.
	unmeasured []string
}

func runScenarios(t *testing.T, scenarios []scenario) {
	t.Helper()
	for _, sc := range scenarios {
		t.Run(sc.name, func(t *testing.T) {
			l := &lab{}
			defer l.release(t)

			cfg := providertest.Config{
				New:              sc.provider(l),
				Modes:            sc.modes,
				PublicKey:        sc.publicKey,
				Forge:            sc.forge,
				SkipForgery:      sc.skipForgery,
				SingleUseRoot:    sc.singleUse,
				Logf:             t.Logf,
				SkipResidueSweep: "",
			}
			if cfg.Modes == nil {
				cfg.Modes = perOperation
			}
			if !sc.sweep {
				cfg.SkipResidueSweep = "this case is about another property than retention by copy"
			}
			err := providertest.TestProvider(t.Context(), cfg)

			v := judge(err)
			ok := true
			missing, extra := sameSet(v.properties, sc.want)
			if len(missing) > 0 {
				ok = false
				t.Errorf("properties not reported: %q", missing)
			}
			if len(extra) > 0 && !sc.loose {
				ok = false
				t.Errorf("properties reported that this fault does not break: %q", extra)
			}
			missing, extra = sameSet(v.unmeasured, sc.unmeasured)
			if len(missing) > 0 || len(extra) > 0 {
				ok = false
				t.Errorf("not-measured properties: missing %q, unexpected %q", missing, extra)
			}
			if v.aborted {
				ok = false
				t.Error("the run reported itself aborted though its context never ended")
			}
			for _, o := range v.other {
				ok = false
				t.Errorf("a finding that is neither a PropertyError nor a NotMeasuredError: %v", o)
			}
			if !ok {
				t.Logf("the run reported:\n%v", err)
			}
		})
	}
}

// TestProviderConformance_InvalidConfigsAreRefusedBeforeAnyProviderRuns hands
// TestProvider each Config that cannot be run and requires ErrInvalidConfig and
// a *ConfigError naming the field at fault, with no provider built.
func TestProviderConformance_InvalidConfigsAreRefusedBeforeAnyProviderRuns(t *testing.T) {
	built := func() (any, error) {
		t.Error("Config.New was called for a Config that cannot run")
		return nil, errFake
	}
	forge := func(enclave.KeyProtector, []byte) ([]byte, error) { return nil, errFake }
	for _, tc := range []struct {
		name  string
		cfg   providertest.Config
		field string
	}{
		{"no provider constructor", providertest.Config{Modes: bothModes}, "New"},
		{"no modes", providertest.Config{New: built}, "Modes"},
		{"a mode that is none", providertest.Config{New: built, Modes: []enclave.Mode{enclave.Mode(99)}}, "Modes"},
		{"a public-key provider in root-key mode only", providertest.Config{New: built, Modes: rootKey, PublicKey: true}, "PublicKey"},
		{"a forgery in root-key mode only", providertest.Config{New: built, Modes: rootKey, Forge: forge}, "Forge"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := providertest.TestProvider(t.Context(), tc.cfg)
			var ce *providertest.ConfigError
			if !errors.Is(err, providertest.ErrInvalidConfig) || !errors.As(err, &ce) || ce.Field != tc.field {
				t.Fatalf("TestProvider = %v; want a *ConfigError for Config.%s matching ErrInvalidConfig", err, tc.field)
			}
			if !strings.HasPrefix(ce.Error(), "providertest: Config."+tc.field+" ") {
				t.Errorf("ConfigError renders %q", ce.Error())
			}
			if v := judge(err); len(v.properties) > 0 || v.aborted {
				t.Errorf("a Config that cannot run reported a property or an abort: %v", err)
			}
		})
	}
}

// TestProviderConformance_KeyProtectorFaultsAreEachReported runs the suite
// against KeyProtectors that each break one property of the per-operation half
// of the seam. Fakes that break a property every later step depends on (a
// Protect that fails, an Unprotect that writes the wrong bytes) take other
// properties down with them and are loose.
func TestProviderConformance_KeyProtectorFaultsAreEachReported(t *testing.T) {
	isolated(t, childOpts{}, func(t *testing.T) {
		runScenarios(t, []scenario{
			// The round trip, and the steps that depend on it.
			{name: "Protect fails", provider: keysWith(protectFails), sweep: true, loose: true,
				want: []string{propRoundTrip, propEnded, propResidue}},
			{name: "Protect returns an empty blob", provider: keysWith(protectReturnsNothing), sweep: true, loose: true,
				want: []string{propRoundTrip, propTamper, propResidue}},
			{name: "the blob is the key in the clear", provider: keysWith(blobIsTheKey), loose: true,
				want: []string{propRoundTrip}},
			{name: "Protect mutates the caller's key", provider: keysWith(protectMutatesItsInput), loose: true,
				want: []string{propRoundTrip}},
			{name: "Unprotect fails", provider: keysWith(unprotectFails), sweep: true, loose: true,
				want: []string{propRoundTrip, propResidue}},
			{name: "Unprotect writes the wrong bytes", provider: keysWith(unprotectWritesTheWrongBytes), sweep: true, loose: true,
				want: []string{propRoundTrip, propResidue}},

			// Retention by reference.
			{name: "Protect keeps the caller's slice and Unprotect recovers zeros from it",
				provider: keysWith(keepsTheCallersSlice(afterWipeRecoversZeros)), want: []string{propRetainKey}},
			{name: "Protect keeps the caller's slice and Unprotect fails once it is wiped",
				provider: keysWith(keepsTheCallersSlice(afterWipeFails)), want: []string{propRetainKey}},
			{name: "Protect keeps the caller's slice and Unprotect recovers something else from it",
				provider: keysWith(keepsTheCallersSlice(afterWipeRecoversOther)), want: []string{propRetainKey}},
			{name: "Unprotect writes its last destination again with its key",
				provider: keysWith(writesToTheLastDestination(rewriteWithItsOwnKey)), want: []string{propAfterWipe}},
			{name: "Unprotect writes its last destination again with the new key",
				provider: keysWith(writesToTheLastDestination(rewriteWithTheNewKey)), want: []string{propAfterWipe, propDisturb}},
			{name: "Unprotect writes its last destination again with garbage",
				provider: keysWith(writesToTheLastDestination(rewriteWithGarbage)), want: []string{propAfterWipe, propDisturb}},
			{name: "Unprotect zeroes its last destination",
				provider: keysWith(writesToTheLastDestination(rewriteWithZeros)), want: []string{propDisturb}},

			// Forgery and malformed input.
			{name: "Unprotect accepts blobs it did not produce",
				provider: keysWith(authenticatesNothingWhenTheDestinationFits), want: []string{propTamper}},
			{name: "Unprotect refuses a forgery as a device fault",
				provider: keysWith(misreportsAForgery), want: []string{propTamper}},
			{name: "Unprotect leaves the key behind in refusing a forgery",
				provider: keysWith(leaksOnRefusal), want: []string{propTamper}},
			{name: "Unprotect accepts a destination of the wrong length",
				provider: keysWith(acceptsAnyDestination), want: []string{propDstLength}},
			{name: "Unprotect refuses a destination of the wrong length as a device fault",
				provider: keysWith(misreportsAnyDestination), want: []string{propDstLength}},
			{name: "Unprotect leaves the key behind in a destination of the wrong length",
				provider: keysWith(leaksIntoAMisSizedDestination), want: []string{propDstLength}},

			// The context contract.
			{name: "Protect and Unprotect ignore the context",
				provider: keysWith(ignoresTheContext), want: []string{propEnded}},
			{name: "an ended context is refused as a forgery",
				provider: keysWith(refusesAnEndedContextAs(enclave.ErrSealedAuthentication)), want: []string{propEnded}},
			{name: "an ended context is refused with some other error",
				provider: keysWith(refusesAnEndedContextAs(errFake)), want: []string{propEnded}},
			{name: "Protect mutates the caller's key in refusing an ended context",
				provider: keysWith(protectMutatesOnRefusal), want: []string{propEnded}},
			{name: "Unprotect writes the key in refusing an ended context",
				provider: keysWith(writesWhileRefusingAnEndedContext), want: []string{propEnded}},
			{name: "refusing an ended context breaks the provider",
				provider: keysWith(isBrokenByARefusal), want: []string{propEnded}},

			// Concurrent use.
			{name: "concurrent Protects stage keys in a shared slot and read each other's",
				provider: keysWith(sharesStateAcrossCalls(contendedSlotHoldsAnotherKey)), want: []string{propConcurrent}},
			{name: "concurrent Protects read a slot another call has cleared",
				provider: keysWith(sharesStateAcrossCalls(contendedSlotHoldsZeros)), want: []string{propConcurrent}},
			{name: "concurrent Unprotects write garbage",
				provider: keysWith(sharesStateAcrossCalls(contendedUnprotectWritesGarbage)), want: []string{propConcurrent}},
			{name: "a Protect fails when another is in flight",
				provider: keysWith(sharesStateAcrossCalls(contendedProtectFails)), want: []string{propConcurrent}},
			{name: "an Unprotect fails when another is in flight",
				provider: keysWith(sharesStateAcrossCalls(contendedUnprotectFails)), want: []string{propConcurrent}},

			// Retention by copy, which only the sweep sees.
			{name: "Unprotect keeps a heap copy of the key",
				provider: keysWith(retainsACopyOfTheKey), sweep: true, want: []string{propResidue}},
		})
	})
}

// TestProviderConformance_RootUnsealerFaultsAreEachReported is the same for the
// root-key half of the seam.
func TestProviderConformance_RootUnsealerFaultsAreEachReported(t *testing.T) {
	isolated(t, childOpts{}, func(t *testing.T) {
		const oneShot = "the root is behind a one-shot handle, spent by its first unseal"
		runScenarios(t, []scenario{
			{name: "UnsealRoot fails", modes: rootKey, provider: rootsWith(unsealFailsFromCall(1)),
				want: []string{propRootFill, propRootRetain, propRootEnded}},
			{name: "a second UnsealRoot fails", modes: rootKey, provider: rootsWith(unsealFailsFromCall(2)),
				want: []string{propRootFill, propRootRetain}},
			{name: "a third UnsealRoot fails", modes: rootKey, provider: rootsWith(unsealFailsFromCall(3)),
				want: []string{propRootRetain}},
			{name: "UnsealRoot writes nothing", modes: rootKey, provider: rootsWith(unsealWritesNothing),
				want: []string{propRootFill, propRootRetain, propRootEnded}},
			{name: "UnsealRoot writes nothing and is single-use", modes: rootKey, provider: rootsWith(unsealWritesNothing),
				singleUse: oneShot, want: []string{propRootFill, propRootEnded}},
			{name: "the root is all zeros", modes: rootKey, provider: rootsWith(unsealWritesAPlaceholder(0)),
				singleUse: oneShot, want: []string{propRootFill, propRootEnded}},
			{name: "the root is one repeated byte", modes: rootKey, provider: rootsWith(unsealWritesAPlaceholder(0x42)),
				singleUse: oneShot, want: []string{propRootFill}},
			{name: "UnsealRoot writes half the destination", modes: rootKey, provider: rootsWith(unsealWritesHalf),
				want: []string{propRootFill}},
			{name: "UnsealRoot returns a different root each call", modes: rootKey, provider: rootsWith(unsealIsDifferentEachTime),
				want: []string{propRootFill}},
			{name: "UnsealRoot zeroes the destination it filled before", modes: rootKey,
				provider: rootsWith(keepsTheDestinations(forgetfulZeroesTheLast)), want: []string{propRootRetain}},
			{name: "UnsealRoot overwrites the destination it filled before", modes: rootKey,
				provider: rootsWith(keepsTheDestinations(forgetfulOverwritesTheLast)), want: []string{propRootRetain}},
			{name: "UnsealRoot writes into a destination the caller has wiped", modes: rootKey,
				provider: rootsWith(keepsTheDestinations(forgetfulRewritesWipedOnes)), want: []string{propRootRetain}},
			{name: "UnsealRoot ignores the context", modes: rootKey, provider: rootsWith(ignoresTheContextWhenUnsealing),
				want: []string{propRootEnded}},
			{name: "an ended context is refused as a forgery", modes: rootKey,
				provider: rootsWith(refusesAnEndedContextWhenUnsealingAs(enclave.ErrSealedAuthentication)), want: []string{propRootEnded}},
			{name: "an ended context is refused with some other error", modes: rootKey,
				provider: rootsWith(refusesAnEndedContextWhenUnsealingAs(errFake)), want: []string{propRootEnded}},
			{name: "UnsealRoot writes the root in refusing an ended context", modes: rootKey,
				provider: rootsWith(writesTheRootWhileRefusing), want: []string{propRootEnded}},
			{name: "refusing an ended context spends the root", modes: rootKey,
				provider: rootsWith(isSpentByARefusalWhenUnsealing), want: []string{propRootEnded}},

			// A single-use root that behaves passes: its refusals consume nothing.
			{name: "a single-use root that behaves", modes: rootKey, provider: rootsWith(unsealFailsFromCall(2)),
				singleUse: oneShot},
		})
	})
}

// TestProviderConformance_ForgedBlobCheck runs the forged-blob check on both
// sides: a bare public-key wrap that opens what an attacker builds, a provider
// whose forged-blob handling is wrong in each of the other ways, a provider
// that passes, and the runs that cannot measure it.
func TestProviderConformance_ForgedBlobCheck(t *testing.T) {
	isolated(t, childOpts{}, func(t *testing.T) {
		bare := func(leak bool) providerFor {
			return func(*lab) func() (any, error) { return func() (any, error) { return &bareWrap{leak: leak}, nil } }
		}
		forgeWithThePublicPad := func(_ enclave.KeyProtector, key []byte) ([]byte, error) { return bareWrapBlob(key), nil }
		forgeSomeOtherKey := func(_ enclave.KeyProtector, _ []byte) ([]byte, error) {
			other := make([]byte, keyLen)
			_, err := rand.Read(other)
			return bareWrapBlob(other), err
		}
		forgeFails := func(enclave.KeyProtector, []byte) ([]byte, error) { return nil, errFake }
		forgeNothing := func(enclave.KeyProtector, []byte) ([]byte, error) { return []byte{}, nil }
		forgeAtRandom := func(enclave.KeyProtector, []byte) ([]byte, error) {
			b := make([]byte, 64)
			_, err := rand.Read(b)
			return b, err
		}
		forgeWithABadTag := func(_ enclave.KeyProtector, key []byte) ([]byte, error) {
			blob := bareWrapBlob(key)
			blob[len(blob)-1] ^= 0x01
			return blob, nil
		}

		runScenarios(t, []scenario{
			{name: "a sound provider refuses a blob forged at random", provider: keysWith(nil), sweep: true,
				publicKey: true, forge: forgeAtRandom},
			{name: "a bare public-key wrap is not caught by the tampered-blob cases", provider: bare(false), sweep: true,
				publicKey: true, forge: forgeAtRandom},
			{name: "a bare public-key wrap opens the blob forged for the attacker's key", provider: bare(false), sweep: true,
				publicKey: true, forge: forgeWithThePublicPad, want: []string{propForged}},
			{name: "a bare public-key wrap opens a blob forged for some other key", provider: bare(false), sweep: true,
				publicKey: true, forge: forgeSomeOtherKey, want: []string{propForged}},
			{name: "Forge fails", provider: bare(false), publicKey: true, forge: forgeFails, want: []string{propForged}},
			{name: "Forge returns nothing", provider: bare(false), publicKey: true, forge: forgeNothing, want: []string{propForged}},
			{name: "a forgery is refused as a device fault", provider: keysWith(misreportsAForgery),
				forge: forgeAtRandom, want: []string{propTamper, propForged}},
			{name: "a forgery is refused after the key was written", provider: bare(true), sweep: true,
				forge: forgeWithABadTag, want: []string{propTamper, propForged}},
			{name: "a public-key provider without Forge is not measured", provider: keysWith(nil),
				publicKey: true, unmeasured: []string{propForged}},
			{name: "a public-key provider without Forge, with the forgery check skipped", provider: keysWith(nil),
				publicKey: true, skipForgery: "the provider is wrapped by a device this test cannot build blobs for"},
		})
	})
}

// TestProviderConformance_MissingProvidersAndSeamsAreReported claims modes the
// provider does not serve, serves modes it does not claim, and hands the suite
// no provider at all: each check that needs the provider reports it.
func TestProviderConformance_MissingProvidersAndSeamsAreReported(t *testing.T) {
	isolated(t, childOpts{}, func(t *testing.T) {
		keyProtectorProperties := []string{propRoundTrip, propRetainKey, propAfterWipe, propDisturb, propTamper,
			propDstLength, propEnded, propResidue}
		rootProperties := []string{propRootFill, propRootRetain, propRootEnded}
		everything := append(append([]string{propPairing}, keyProtectorProperties...), rootProperties...)

		returning := func(p func() (any, error)) providerFor {
			return func(*lab) func() (any, error) { return p }
		}
		var typedNil *keyFault

		runScenarios(t, []scenario{
			{name: "Config.New fails", modes: bothModes, sweep: true,
				provider: returning(func() (any, error) { return nil, errFake }), want: everything},
			{name: "Config.New returns nil", modes: bothModes, sweep: true,
				provider: returning(func() (any, error) { return nil, nil }), want: everything},
			{name: "Config.New returns a typed nil", modes: bothModes, sweep: true,
				provider: returning(func() (any, error) { return typedNil, nil }), want: everything},
			{name: "a KeyProtector claimed to serve ModeRootKey too", modes: bothModes, sweep: true,
				provider: keysWith(nil), want: append([]string{propPairing}, rootProperties...)},
			{name: "a RootUnsealer claimed to serve ModePerOperation", modes: perOperation, sweep: true,
				provider: rootsWith(nil), want: append([]string{propPairing}, keyProtectorProperties...)},
			{name: "a provider serving a mode it does not claim", modes: perOperation, sweep: true,
				provider: func(l *lab) func() (any, error) {
					return func() (any, error) {
						d := newDevice()
						l.adopt(d.soft)
						return d, nil
					}
				},
				want: []string{propPairing}},
		})
	})
}

// requireAborted requires err to be a run reported aborted for cause, carrying
// no finding against the provider.
func requireAborted(t *testing.T, err, cause error) {
	t.Helper()
	var ae *providertest.AbortedError
	if !errors.Is(err, providertest.ErrAborted) || !errors.Is(err, cause) || !errors.As(err, &ae) || !errors.Is(ae.Cause, cause) {
		t.Fatalf("TestProvider = %v; want an *AbortedError matching ErrAborted and %v", err, cause)
	}
	if !strings.HasPrefix(ae.Error(), providertest.ErrAborted.Error()+": ") {
		t.Errorf("AbortedError renders %q", ae.Error())
	}
	if v := judge(err); len(v.properties) > 0 || len(v.unmeasured) > 0 || len(v.other) > 0 {
		t.Errorf("a run whose context ended reported findings made after it did: %v", err)
	}
}

// TestProviderConformance_AnEndedRunContextAbortsTheRun ends the context a run
// is given before it starts, during its checks, and while a provider call that
// never returns is outstanding. In each the run reports ErrAborted, never a
// pass and never a finding made after the end.
func TestProviderConformance_AnEndedRunContextAbortsTheRun(t *testing.T) {
	isolated(t, childOpts{}, func(t *testing.T) {
		const skipped = "this case is about the run context, not retention by copy"

		t.Run("ended before the run", func(t *testing.T) {
			for _, tc := range []struct {
				name  string
				make  func() (context.Context, context.CancelFunc)
				cause error
			}{
				{"canceled", func() (context.Context, context.CancelFunc) {
					ctx, cancel := context.WithCancel(t.Context())
					cancel()
					return ctx, cancel
				}, context.Canceled},
				{"past its deadline", func() (context.Context, context.CancelFunc) {
					return context.WithDeadline(t.Context(), time.Unix(0, 0))
				}, context.DeadlineExceeded},
			} {
				ctx, cancel := tc.make()
				var built atomic.Int64
				err := providertest.TestProvider(ctx, providertest.Config{
					New:   func() (any, error) { built.Add(1); return enclave.NewSoftwareProvider(), nil },
					Modes: bothModes,
					Logf:  t.Logf,
				})
				cancel()
				requireAborted(t, err, tc.cause)
				if n := built.Load(); n != 0 {
					t.Errorf("%s: a run whose context had ended built %d providers", tc.name, n)
				}
			}
		})

		t.Run("ended inside the first provider call", func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			l := &lab{}
			defer l.release(t)
			err := providertest.TestProvider(ctx, providertest.Config{
				New: keysWith(func(_ *lab, f *keyFault) {
					f.protect = func(c context.Context, key []byte) ([]byte, error) {
						cancel()
						return f.soft.Protect(c, key)
					}
				})(l),
				Modes:            perOperation,
				SkipResidueSweep: skipped,
				Logf:             t.Logf,
			})
			requireAborted(t, err, context.Canceled)
		})

		t.Run("ended while the concurrency check runs", func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			l := &lab{}
			defer l.release(t)
			var armed atomic.Bool
			err := providertest.TestProvider(ctx, providertest.Config{
				New: keysWith(func(_ *lab, f *keyFault) {
					f.unprotect = func(c context.Context, blob, dst []byte) error {
						err := f.soft.Unprotect(c, blob, dst)
						if err == nil && armed.Load() {
							cancel()
						}
						return err
					}
				})(l),
				Modes:            perOperation,
				SkipResidueSweep: skipped,
				// The concurrency check follows the ended-context check.
				Logf: func(format string, args ...any) {
					t.Logf(format, args...)
					if strings.HasPrefix(format, "providertest: ended-context refusal checked") {
						armed.Store(true)
					}
				},
			})
			requireAborted(t, err, context.Canceled)
		})

		t.Run("ended as the residue sweep starts", func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			l := &lab{}
			defer l.release(t)
			var armed atomic.Bool
			honest := keysWith(nil)(l)
			err := providertest.TestProvider(ctx, providertest.Config{
				New: func() (any, error) {
					if armed.Load() {
						cancel()
					}
					return honest()
				},
				Modes: perOperation,
				// The residue sweep follows the concurrency check.
				Logf: func(format string, args ...any) {
					t.Logf(format, args...)
					if strings.HasPrefix(format, "providertest: %d goroutines recovered") {
						armed.Store(true)
					}
				},
			})
			requireAborted(t, err, context.Canceled)
		})

		// A provider that never returns from a call made with an ended
		// context cannot hold a run: the run is abandoned and reported
		// aborted, and the call is released by whoever owns what it touches.
		t.Run("a Protect that never returns", func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			l := &lab{}
			defer l.release(t)
			b := newBlocker(cancel)
			err := providertest.TestProvider(ctx, providertest.Config{
				New: keysWith(func(_ *lab, f *keyFault) {
					f.protect = func(c context.Context, key []byte) ([]byte, error) {
						if c.Err() != nil {
							return nil, b.hold(c)
						}
						return f.soft.Protect(c, key)
					}
				})(l),
				Modes:            perOperation,
				SkipResidueSweep: skipped,
				Logf:             t.Logf,
			})
			requireAborted(t, err, context.Canceled)
			b.finish(t)
		})

		t.Run("an Unprotect that never returns", func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			l := &lab{}
			defer l.release(t)
			b := newBlocker(cancel)
			err := providertest.TestProvider(ctx, providertest.Config{
				New: keysWith(func(_ *lab, f *keyFault) {
					f.unprotect = func(c context.Context, blob, dst []byte) error {
						if c.Err() != nil {
							return b.hold(c)
						}
						return f.soft.Unprotect(c, blob, dst)
					}
				})(l),
				Modes:            perOperation,
				SkipResidueSweep: skipped,
				Logf:             t.Logf,
			})
			requireAborted(t, err, context.Canceled)
			b.finish(t)
		})

		t.Run("an UnsealRoot that never returns", func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			l := &lab{}
			defer l.release(t)
			b := newBlocker(cancel)
			err := providertest.TestProvider(ctx, providertest.Config{
				New: rootsWith(func(_ *lab, f *rootFault) {
					f.unseal = func(c context.Context, dst []byte) error {
						if c.Err() != nil {
							return b.hold(c)
						}
						return f.soft.UnsealRoot(c, dst)
					}
				})(l),
				Modes: rootKey,
				Logf:  t.Logf,
			})
			requireAborted(t, err, context.Canceled)
			b.finish(t)
		})
	})
}

// TestProviderConformance_AnAbortedRunDoesNotReportTheUnmeasuredSweep ends the
// run's context just as the residue sweep begins in a child without locked
// memory. The sweep could not have run; the run is reported aborted, not as a
// property it failed to measure after its context was gone.
func TestProviderConformance_AnAbortedRunDoesNotReportTheUnmeasuredSweep(t *testing.T) {
	isolated(t, childOpts{memlockZero: true}, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		var armed atomic.Bool
		err := providertest.TestProvider(ctx, providertest.Config{
			New: func() (any, error) {
				if armed.Load() {
					cancel()
				}
				return &heapProtector{keys: map[string][]byte{}}, nil
			},
			Modes: perOperation,
			Logf: func(format string, args ...any) {
				t.Logf(format, args...)
				if strings.HasPrefix(format, "providertest: %d goroutines recovered") {
					armed.Store(true)
				}
			},
		})
		if !errors.Is(err, providertest.ErrAborted) {
			t.Fatalf("TestProvider = %v; want ErrAborted", err)
		}
		if v := judge(err); len(v.unmeasured) > 0 {
			t.Errorf("the run reported a property not measured after its context had ended: %v", err)
		}
	})
}

// TestProviderConformance_ShortLockedMemoryIsReportedNotMeasured runs the suite
// in a child with room for one locked mapping, which the residue sweep's second
// destination and the root checks' paired destinations need more of than
// there is. A suite that cannot allocate its own buffers says so: it neither
// passes nor blames the provider.
func TestProviderConformance_ShortLockedMemoryIsReportedNotMeasured(t *testing.T) {
	ceiling := enclave.LockedSize(enclave.RootKeyBytes)
	isolated(t, childOpts{memlock: ceiling}, func(t *testing.T) {
		t.Run("the residue sweep", func(t *testing.T) {
			err := providertest.TestProvider(t.Context(), providertest.Config{
				New:   func() (any, error) { return &heapProtector{keys: map[string][]byte{}}, nil },
				Modes: perOperation,
				Logf:  t.Logf,
			})
			v := judge(err)
			if !v.unmeasured[propResidue] || !errors.Is(err, providertest.ErrNotMeasured) {
				t.Errorf("TestProvider = %v; want the residue sweep reported not measured", err)
			}
			for _, o := range v.other {
				t.Errorf("a finding that is neither a PropertyError nor a NotMeasuredError: %v", o)
			}
		})

		t.Run("the root destinations", func(t *testing.T) {
			err := providertest.TestProvider(t.Context(), providertest.Config{
				New: func() (any, error) {
					r, err := newHeapRoot()
					return r, err
				},
				Modes: rootKey,
				Logf:  t.Logf,
			})
			v := judge(err)
			if !v.properties[propRootFill] || !v.properties[propRootRetain] || v.properties[propRootEnded] {
				t.Errorf("TestProvider = %v; want the paired and quadruple destinations of the fill and retention checks "+
					"reported failed, and the single destination of the ended-context check to have been allocated", err)
			}
		})
	})
}
