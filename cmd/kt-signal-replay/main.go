// Command kt-signal-replay replays Signal key-transparency auditor updates
// offline and prints the resulting tree size and log root.
//
// It is the offline half of auditing Signal: the verifier is ready, the
// connection is not. Signal's Audit RPC is served only to holders of a
// Signal-issued client certificate, which we have asked for and do not yet
// have. Until then this checks the replay core against files — Signal's test
// vectors, or a captured stream — so the day the certificate arrives the only
// new code is the client.
//
// Usage:
//
//	kt-signal-replay [-state state.json] updates.bin
//	kt-signal-replay -vectors kt_test_vectors.pb
//
// updates.bin is a sequence of length-delimited AuditorUpdate messages (a
// varint length, then the message — protobuf's standard delimited framing),
// "-" for stdin. With -state, the state is loaded first if the file exists and
// the file must continue from that state's size; after the run the state as of
// the last accepted update is written back, whether or not a later update was
// rejected — everything in it was verified.
//
// With -vectors, the file is the reference auditor's kt_test_vectors.pb and
// its should_succeed sequence is replayed from empty, checking the expected
// log root after every update.
//
// Exit status is 1 if any update is rejected or a root disagrees.
package main

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/gdbsecurity/kt-witness/internal/signalaudit"
)

// maxUpdate bounds one framed message. A legitimate update is at most a full
// 256-entry copath (about 8.7 KB) plus a hundred bytes of fixed fields; the
// bound only stops a corrupt length prefix from allocating gigabytes.
const maxUpdate = 64 << 10

func main() {
	statePath := flag.String("state", "", "load state from and save it to this JSON file")
	vectors := flag.Bool("vectors", false, "input is kt_test_vectors.pb; replay should_succeed and check every root")
	flag.Parse()
	if flag.NArg() != 1 || (*vectors && *statePath != "") {
		fmt.Fprintln(os.Stderr, "usage: kt-signal-replay [-state state.json] updates.bin | kt-signal-replay -vectors kt_test_vectors.pb")
		os.Exit(2)
	}

	var s signalaudit.State
	if *statePath != "" {
		if err := load(*statePath, &s); err != nil {
			fatal(err)
		}
	}

	var err error
	if *vectors {
		err = replayVectors(flag.Arg(0), &s)
	} else {
		err = replayStream(flag.Arg(0), &s)
	}

	if *statePath != "" {
		if serr := save(*statePath, &s); serr != nil {
			fatal(serr)
		}
	}
	report(&s)
	if err != nil {
		fatal(err)
	}
}

func replayStream(path string, s *signalaudit.State) error {
	var in io.Reader = os.Stdin
	if path != "-" {
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
		in = f
	}
	r := bufio.NewReader(in)
	start := s.Size()
	for {
		n, err := binary.ReadUvarint(r)
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("update %d: reading length: %w", s.Size(), err)
		}
		if n > maxUpdate {
			return fmt.Errorf("update %d: framed length %d exceeds %d", s.Size(), n, maxUpdate)
		}
		b := make([]byte, n)
		if _, err := io.ReadFull(r, b); err != nil {
			return fmt.Errorf("update %d: truncated (%d updates read): %w", s.Size(), s.Size()-start, err)
		}
		if err := apply(s, b); err != nil {
			return err
		}
	}
}

func replayVectors(path string, s *signalaudit.State) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	v, err := signalaudit.DecodeVectors(b)
	if err != nil {
		return err
	}
	for i, st := range v.ShouldSucceed {
		if err := apply(s, st.Update); err != nil {
			return err
		}
		if got, _ := s.LogRoot(); got != st.LogRoot {
			return fmt.Errorf("vector %d: log root %x, vectors expect %x", i, got, st.LogRoot)
		}
	}
	fmt.Printf("vectors: %d should_succeed updates matched\n", len(v.ShouldSucceed))
	return nil
}

func apply(s *signalaudit.State, b []byte) error {
	pos := s.Size()
	u, err := signalaudit.DecodeUpdate(b)
	if err == nil {
		err = s.Apply(u)
	}
	var pe *signalaudit.ProofError
	switch {
	case errors.As(err, &pe):
		return fmt.Errorf("CONTRADICTION: %w", err)
	case err != nil:
		return fmt.Errorf("update %d: %w", pos, err)
	}
	return nil
}

func report(s *signalaudit.State) {
	fmt.Printf("size %d\n", s.Size())
	if root, err := s.LogRoot(); err == nil {
		fmt.Printf("log_root %s\n", hex.EncodeToString(root[:]))
	}
	if p, ok := s.PrefixRoot(); ok {
		fmt.Printf("prefix_root %s\n", hex.EncodeToString(p[:]))
	}
}

func load(path string, s *signalaudit.State) error {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return json.Unmarshal(b, s)
}

// save writes via a temporary file and rename, so a crash mid-write leaves the
// previous state rather than a truncated one.
func save(path string, s *signalaudit.State) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".kt-signal-replay-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(append(b, '\n')); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "kt-signal-replay:", err)
	os.Exit(1)
}
