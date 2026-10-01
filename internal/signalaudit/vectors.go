package signalaudit

import (
	"fmt"

	"github.com/gdbsecurity/kt-witness/internal/pbwire"
)

// Vectors is the update-replay part of Signal's auditor test vectors
// (proto/vectors.proto in the reference auditor):
//
//	TestVectors {
//	  repeated ShouldFailTestVector should_fail = 1;   // { string description = 1; repeated AuditorUpdate updates = 2; }
//	  ShouldSucceedTestVector should_succeed = 2;      // { repeated UpdateAndHash updates = 1; }
//	  SignatureTestVector signature = 3;               // not used: we do not sign
//	}
//	UpdateAndHash { AuditorUpdate update = 1; bytes log_root = 2; }
//
// Updates are kept as wire bytes so that replaying them exercises DecodeUpdate
// too.
type Vectors struct {
	ShouldFail    []FailVector
	ShouldSucceed []SucceedStep
}

// FailVector is a sequence of updates of which the last must be rejected.
type FailVector struct {
	Description string
	Updates     [][]byte
}

// SucceedStep is one update and the log root expected after applying it, in a
// single sequence starting from the empty log.
type SucceedStep struct {
	Update  []byte
	LogRoot [HashSize]byte
}

// DecodeVectors parses a kt_test_vectors.pb file.
func DecodeVectors(b []byte) (*Vectors, error) {
	top, err := pbwire.Fields(b)
	if err != nil {
		return nil, fmt.Errorf("signalaudit: vectors: %w", err)
	}
	v := &Vectors{}
	for _, f := range top {
		switch {
		case f.Num == 1 && f.Wire == 2:
			fields, err := pbwire.Fields(f.Bytes)
			if err != nil {
				return nil, fmt.Errorf("signalaudit: vectors: should_fail: %w", err)
			}
			var fv FailVector
			for _, g := range fields {
				switch {
				case g.Num == 1 && g.Wire == 2:
					fv.Description = string(g.Bytes)
				case g.Num == 2 && g.Wire == 2:
					fv.Updates = append(fv.Updates, g.Bytes)
				}
			}
			v.ShouldFail = append(v.ShouldFail, fv)
		case f.Num == 2 && f.Wire == 2:
			steps, err := pbwire.Fields(f.Bytes)
			if err != nil {
				return nil, fmt.Errorf("signalaudit: vectors: should_succeed: %w", err)
			}
			for _, g := range steps {
				if g.Num != 1 || g.Wire != 2 {
					continue
				}
				pair, err := pbwire.Fields(g.Bytes)
				if err != nil {
					return nil, fmt.Errorf("signalaudit: vectors: should_succeed[%d]: %w", len(v.ShouldSucceed), err)
				}
				var st SucceedStep
				var root []byte
				for _, h := range pair {
					switch {
					case h.Num == 1 && h.Wire == 2:
						st.Update = h.Bytes
					case h.Num == 2 && h.Wire == 2:
						root = h.Bytes
					}
				}
				if len(root) != HashSize {
					return nil, fmt.Errorf("signalaudit: vectors: should_succeed[%d]: log_root is %d bytes",
						len(v.ShouldSucceed), len(root))
				}
				st.LogRoot = [HashSize]byte(root)
				v.ShouldSucceed = append(v.ShouldSucceed, st)
			}
		}
	}
	return v, nil
}
