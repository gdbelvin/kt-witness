package store

import (
	"path/filepath"
	"testing"
)

// Two signed attestations disagreeing at one size is the conclusive evidence a
// single witness cannot produce alone. A log cannot have two roots at one size,
// so it served different histories to different parties.
func TestDisagreementAtOneSizeIsDetected(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	const origin = "thelemail.com/keys"
	// First witness attests size 99 with root A.
	conflicts, err := db.RecordPeer(&PeerAttestation{
		Origin: origin, Witness: "witness.stagemole.eu", Size: 99, Root: "AAA", Timestamp: 1,
	})
	if err != nil || len(conflicts) != 0 {
		t.Fatalf("first attestation should not conflict: %v %v", conflicts, err)
	}

	// Same size, same root, different witness: agreement, not a conflict.
	conflicts, err = db.RecordPeer(&PeerAttestation{
		Origin: origin, Witness: "witness.navigli.example", Size: 99, Root: "AAA", Timestamp: 2,
	})
	if err != nil || len(conflicts) != 0 {
		t.Fatalf("agreeing witnesses must not conflict: %v %v", conflicts, err)
	}

	// Same size, DIFFERENT root. Conclusive.
	conflicts, err = db.RecordPeer(&PeerAttestation{
		Origin: origin, Witness: "witness.third.example", Size: 99, Root: "BBB", Timestamp: 3,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(conflicts) != 2 {
		t.Fatalf("a different root at the same size must conflict with both prior "+
			"attestations, got %d", len(conflicts))
	}

	// A different size is not a conflict: logs grow.
	conflicts, err = db.RecordPeer(&PeerAttestation{
		Origin: origin, Witness: "witness.stagemole.eu", Size: 100, Root: "CCC", Timestamp: 4,
	})
	if err != nil || len(conflicts) != 0 {
		t.Fatalf("a later size is growth, not disagreement: %v %v", conflicts, err)
	}
}

// Attestations must not leak between logs: a witness disagreeing about one log
// says nothing about another.
func TestPeerAttestationsAreScopedToTheirOrigin(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	if _, err := db.RecordPeer(&PeerAttestation{
		Origin: "a/log", Witness: "w", Size: 5, Root: "AAA",
	}); err != nil {
		t.Fatal(err)
	}
	conflicts, err := db.RecordPeer(&PeerAttestation{
		Origin: "b/log", Witness: "w", Size: 5, Root: "ZZZ",
	})
	if err != nil || len(conflicts) != 0 {
		t.Fatalf("a different origin must not conflict: %v %v", conflicts, err)
	}
	if got, _ := db.PeerAttestations("a/log"); len(got) != 1 {
		t.Errorf("origin a/log should have exactly its own attestation, got %d", len(got))
	}
}
