// Package push implements the write side of c2sp.org/tlog-witness:
//
//	POST /add-checkpoint
//
// A pushed checkpoint goes through the same witness core as a polled one, so
// every gate — permanent fork state, rollback handling, consistency, freshness
// — applies identically whichever way a head arrived.
package push

import "golang.org/x/mod/sumdb/note"

// Log is one log this witness accepts pushes for.
type Log struct {
	// Origin is the checkpoint origin line.
	Origin string
	// VKey is the log's verifier key in vkey form, as configured or listed.
	VKey string
	// Verifier checks the log's signature on a pushed checkpoint.
	Verifier note.Verifier
	// QPD is the number of add-checkpoint requests per day the log may make.
	// Zero means unlimited (statically configured logs).
	QPD int64
	// Contact is the log operator's contact, for display.
	Contact string
	// From says where this log came from: "config", or the list URL that
	// introduced it.
	From string
}

// Registry resolves an origin to a log that may push to us.
//
// Implementations must be safe for concurrent use; the list fetcher adds logs
// while requests are being served.
type Registry interface {
	Lookup(origin string) (*Log, bool)
}
