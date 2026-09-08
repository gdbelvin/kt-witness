package witness

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/gdbsecurity/kt-witness/internal/source"
	"github.com/gdbsecurity/kt-witness/internal/store"
)

// TestReportedCosignersAreRecordedWithoutANoteOrPeerKeys.
//
// Sigsum publishes cosignatures in its own tree-head encoding, keyed by key
// hash, and the adapter synthesises a note carrying only the log's own
// signature. Twelve witnesses cosigning seasalp were therefore invisible to
// every downstream consumer, and this witness reported an ecosystem of one.
//
// So the recording must not depend on the note format, and must not depend on
// holding any peer key: a cosigner that cannot be identified or verified is
// still evidence that somebody else is watching.
func TestReportedCosignersAreRecordedWithoutANoteOrPeerKeys(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "w.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	w := &Witness{Store: db} // no Peers configured, deliberately
	w.observePeers("sigsum.org/v1/tree/abc", &source.Head{
		Origin:    "sigsum.org/v1/tree/abc",
		Cosigners: []string{"keyhash:90ad80e6", "keyhash:9246694a", "keyhash:deadbeef"},
		FetchedAt: time.Now(),
	})

	seen, err := db.SeenWitnesses()
	if err != nil {
		t.Fatal(err)
	}
	if len(seen) != 3 {
		t.Fatalf("recorded %d cosigners, want 3", len(seen))
	}
	for _, s := range seen {
		if len(s.Origins) != 1 || s.Origins[0] != "sigsum.org/v1/tree/abc" {
			t.Errorf("%s: origins %v", s.Name, s.Origins)
		}
	}
}
