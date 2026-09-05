package akd

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/gdbsecurity/kt-witness/internal/source"
)

// Extending the recorded history instead of re-walking it.
//
// Backfill lists the whole bucket: about 500 paginated requests and two minutes
// for half a million epochs. Doing that hourly to learn about a hundred new
// epochs is most of a full scan spent rediscovering what we already verified.
//
// The obvious fix — resume the listing from where it stopped — does not work,
// because object keys sort lexicographically rather than numerically: "99999"
// sorts after "624700", so there is no start-after that means "epochs above N".
// That is a real constraint and it is why the full walk exists.
//
// But it only blocks *pagination*. Each object is keyed by its epoch, so a
// single epoch can be fetched directly with prefix={epoch}/ — which is exactly
// what linkAt already does for the auditor. Extending the range is therefore
// (tip - from) cheap requests rather than a full scan, and the constraint turns
// out to bound how we page, not whether we can be incremental at all.

// BackfillFrom verifies published history from `from` up to the tip, assuming
// everything at or below `from` was verified by an earlier pass.
//
// The caller supplies `from` out of stored history, so this is only sound when
// that history came from this witness. It returns the extended range so the
// caller can widen what it has recorded.
func (s *Source) BackfillFrom(ctx context.Context, log *slog.Logger, from int64) (*source.BackfillResult, error) {
	tipLink, err := s.findTip(ctx, from)
	if err != nil {
		return nil, err
	}
	tip := tipLink.epoch
	if tip <= from {
		return &source.BackfillResult{From: from, To: from}, nil
	}

	// The epoch we already trust, to link the first new one against. Without it
	// the extension would start with an unchecked join — precisely the seam an
	// operator would choose to rewrite.
	prev, err := s.linkAt(ctx, from)
	if err != nil {
		return nil, fmt.Errorf("akd: re-reading epoch %d to anchor the extension: %w", from, err)
	}
	if prev == nil {
		// The anchor has gone. Absence is not evidence — retention could
		// explain it — so this asks for a full walk rather than concluding
		// anything.
		return nil, fmt.Errorf("akd: epoch %d is no longer published; a full backfill is needed", from)
	}

	res := &source.BackfillResult{From: from, To: from, Epochs: 1}
	for epoch := from + 1; epoch <= tip; epoch++ {
		select {
		case <-ctx.Done():
			return res, ctx.Err()
		default:
		}

		cur, err := s.linkAt(ctx, epoch)
		if err != nil {
			return nil, err
		}
		if cur == nil {
			// A hole. Not evidence: retention limits and partial writes both
			// look like this, and linkage cannot be checked across it. Record
			// it, re-anchor, and carry on.
			res.Gaps = append(res.Gaps, fmt.Sprintf("%d missing", epoch))
			prev = nil
			res.To = epoch
			continue
		}
		if prev != nil && cur.prev != prev.curr {
			// Both objects exist and their names disagree. This cannot be
			// absence or a stale read.
			return nil, &source.ForkError{
				Origin: s.cfg.Origin,
				Reason: fmt.Sprintf(
					"published history breaks at epoch %d: it follows root %x, but epoch %d published root %x",
					epoch, cur.prev[:], epoch-1, prev.curr[:]),
			}
		}
		prev = cur
		res.To = epoch
		res.Epochs++
	}
	if log != nil {
		log.Info("history extended", "origin", s.cfg.Origin,
			"from", from, "to", res.To, "new_epochs", res.Epochs-1, "gaps", len(res.Gaps))
	}
	return res, nil
}
