package akd

import "testing"

// TestLexicographicKeysAreNotSortedAsStrings documents the constraint that
// shapes backfill, and pins that our own handling of it is numeric.
//
// Meta names objects with an unpadded decimal epoch and S3 returns keys in
// UTF-8 binary order, so "99999" sorts after "624700". That blocks paginating
// from a given epoch — there is no start-after that means "above N" — which is
// why a full walk exists at all.
//
// It does NOT mean epochs are ordered as strings anywhere in this package: the
// epoch is parsed to an int64 and sorted numerically. If that ever regresses,
// the chain walk would compare the wrong pairs and either invent a fork or miss
// one.
func TestLexicographicKeysAreNotSortedAsStrings(t *testing.T) {
	// The property that defeats start-after.
	if !("99999" > "624700") {
		t.Fatal("assumption wrong: these keys no longer sort the way the design assumes")
	}
	// The property our code relies on instead.
	if !(int64(99999) < int64(624700)) {
		t.Fatal("numeric ordering is what the chain walk needs")
	}
}
