package audit

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/gdbsecurity/kt-witness/internal/store"
)

// EpochRef locates one epoch's construction proof.
type EpochRef struct {
	LogDirectory string
	PrevRoot     string // hex
	CurrRoot     string // hex
}

// Resolver is implemented by sources whose individual epochs can be audited.
type Resolver interface {
	Origin() string
	ResolveEpoch(ctx context.Context, epoch int64) (*EpochRef, error)
}

// Auditor verifies a sampled subset of epochs.
//
// It runs independently of the witness loop, and deliberately does not gate
// cosigning: a verification takes ~24 s and the witness must stay responsive.
// Tier A+ assertions continue on their own cadence; tier B results accumulate
// alongside them, and a failed verification poisons the log for both.
type Auditor struct {
	Store   *store.Store
	Beacon  *Beacon
	Sidecar *Sidecar
	Log     *slog.Logger

	// Rate is the fraction of epochs verified, published alongside results.
	Rate float64

	// Timeout bounds one epoch's verification.
	Timeout time.Duration

	// MaxEpochsPerRound bounds how many epochs are considered per pass, so a
	// long backlog does not monopolise a single round.
	MaxEpochsPerRound int64
}

// Run audits newly witnessed epochs for one source.
func (a *Auditor) Run(ctx context.Context, r Resolver) error {
	origin := r.Origin()

	if forked, err := a.Store.IsForked(origin); err != nil {
		return err
	} else if forked {
		return nil // already permanently withheld; nothing to add
	}

	rec, err := a.Store.Get(origin)
	if err != nil {
		return err
	}
	if rec == nil {
		return nil // nothing witnessed yet
	}

	from, err := a.Store.AuditProgress(origin)
	if err != nil {
		return err
	}
	if from == 0 {
		// Start where witnessing started rather than sweeping history we never
		// attested to.
		from = rec.Size - 1
	}

	limit := rec.Size
	if a.MaxEpochsPerRound > 0 && limit-from > a.MaxEpochsPerRound {
		limit = from + a.MaxEpochsPerRound
	}

	for epoch := from + 1; epoch <= limit; epoch++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// The beacon is drawn now, strictly after this epoch was published and
		// observed. Drawing it earlier would let the operator predict the
		// sample and misbehave only in the epochs we skip.
		round, err := a.Beacon.Latest(ctx)
		if err != nil {
			// Without unpredictable randomness we must not fall back to a
			// predictable rule; better to audit nothing this round.
			return fmt.Errorf("audit: %s: %w", origin, err)
		}

		selected, err := Selected(round.Randomness, epoch, a.Rate)
		if err != nil {
			return err
		}

		ar := &store.Audit{
			Origin:       origin,
			Epoch:        epoch,
			Sampled:      selected,
			Rate:         a.Rate,
			BeaconRound:  round.Number,
			BeaconSig:    round.Signature,
			BeaconRandom: round.Randomness,
			DecidedAt:    time.Now().UTC(),
		}

		if !selected {
			// Recorded anyway: the published record has to show the epochs we
			// declined, or no one can check we sampled at the claimed rate.
			if err := a.Store.RecordAudit(ar); err != nil {
				return err
			}
			if err := a.Store.SetAuditProgress(origin, epoch); err != nil {
				return err
			}
			continue
		}

		// Carry forward how many times we have already tried this epoch.
		if prior, err := a.Store.GetAudit(origin, epoch); err != nil {
			return err
		} else if prior != nil {
			ar.Attempts = prior.Attempts
		}
		ar.Attempts++

		ref, err := r.ResolveEpoch(ctx, epoch)
		if err != nil {
			return a.unavailable(ar, epoch, "fetch", err)
		}

		a.Log.Info("auditing epoch", "origin", origin, "epoch", epoch,
			"rate", a.Rate, "attempt", ar.Attempts)
		res, err := a.Sidecar.Verify(ctx, ref.LogDirectory, epoch, ref.PrevRoot, ref.CurrRoot, a.Timeout)
		if err != nil {
			return a.unavailable(ar, epoch, "fetch", err)
		}

		ar.Verified = res.OK
		ar.Error = res.Error
		ar.Kind = res.Kind
		ar.DurationMS = res.DownloadMS + res.DecodeMS + res.VerifyMS
		ar.Bytes = res.Bytes

		if err := a.Store.RecordAudit(ar); err != nil {
			return err
		}

		switch {
		case res.VerificationFailed():
			// The log's own proof does not reconstruct the root it published.
			// Unlike a missing object or a failed download, this cannot be a
			// misreading on our part: it is arithmetic.
			a.Log.Error("CONSTRUCTION AUDIT FAILED", "origin", origin, "epoch", epoch, "err", res.Error)
			f := &store.Fork{
				Origin: origin,
				Reason: fmt.Sprintf("construction audit failed at epoch %d: the published proof does not reconstruct the published root (%s)",
					epoch, res.Error),
				DetectedAt: time.Now().UTC(),
			}
			if err := a.Store.RecordFork(f); err != nil {
				return err
			}
			return fmt.Errorf("audit: %s: construction audit failed at epoch %d", origin, epoch)

		case !res.OK:
			// fetch/decode: we could not check.
			return a.unavailable(ar, epoch, res.Kind, fmt.Errorf("%s", res.Error))
		}

		a.Log.Info("epoch verified", "origin", origin, "epoch", epoch,
			"ms", ar.DurationMS, "mb", ar.Bytes/(1<<20))

		if err := a.Store.SetAuditProgress(origin, epoch); err != nil {
			return err
		}
	}
	return nil
}

// maxAttempts is how many times a sampled epoch is retried before it is
// recorded as unavailable.
const maxAttempts = 5

// unavailable handles an epoch we selected but could not check.
//
// Retrying forever would be the safer-looking choice, but it is not: progress
// never advances, the backlog grows without bound, and one permanently
// unfetchable proof — a pruned blob, say, if we fall behind the log's retention
// window — silently bricks tier B for that log. So after a bounded number of
// attempts the epoch is recorded honestly as sampled-but-unverified and we move
// on. That keeps published coverage truthful, which matters more than the
// appearance of completeness: a skipped-and-declared epoch is auditable, a
// stalled auditor is not.
//
// This applies only to fetch and decode failures. A verification failure is
// never routed here — that is arithmetic, and it poisons the log.
func (a *Auditor) unavailable(ar *store.Audit, epoch int64, kind string, cause error) error {
	ar.Verified = false
	ar.Kind = kind
	ar.Error = cause.Error()

	if ar.Attempts < maxAttempts {
		// Record the attempt, but leave progress unadvanced so we try again.
		if err := a.Store.RecordAudit(ar); err != nil {
			return err
		}
		return fmt.Errorf("audit: %s epoch %d unverifiable (%s), attempt %d/%d: %w",
			ar.Origin, epoch, kind, ar.Attempts, maxAttempts, cause)
	}

	ar.Kind = "unavailable"
	if err := a.Store.RecordAudit(ar); err != nil {
		return err
	}
	if err := a.Store.SetAuditProgress(ar.Origin, epoch); err != nil {
		return err
	}
	a.Log.Warn("epoch permanently unavailable; recorded as unverified and skipped",
		"origin", ar.Origin, "epoch", epoch, "attempts", ar.Attempts, "cause", cause)
	return nil
}
