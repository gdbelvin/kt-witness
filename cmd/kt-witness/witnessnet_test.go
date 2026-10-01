package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/gdbsecurity/kt-witness/internal/cosig"
	"github.com/gdbsecurity/kt-witness/internal/loglist"
	"github.com/gdbsecurity/kt-witness/internal/server"
	"github.com/gdbsecurity/kt-witness/internal/store"
	"golang.org/x/mod/sumdb/note"
)

const mullvadKey = "witness.stagemole.eu+67f7aea0+BEqSG3yu9YrmcM3BHvQYTxwFj3uSWakQepafafpUqklv"

func keyWithAlg(name string, alg byte) string {
	raw := make([]byte, 33)
	raw[0] = alg
	for i := 1; i < len(raw); i++ {
		raw[i] = byte(i)
	}
	// The key hash is SHA-256(name || "\n" || key)[:4], as sumdb/note and
	// C2SP define it for every algorithm.
	h := sha256.Sum256(append([]byte(name+"\n"), raw...))
	return fmt.Sprintf("%s+%08x+%s", name, binary.BigEndian.Uint32(h[:4]), base64.StdEncoding.EncodeToString(raw))
}

// Network witness keys join the peer set, deduplicated against what the
// operator configured, and only cosignature/v1 keys get in: one key of another
// type would otherwise fail cosig.NewVerifier, and with it the whole startup.
func TestNetworkPeerKeys(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	other := keyWithAlg("witness.other.example", 0x04)
	noteKey := keyWithAlg("witness.ed25519.example", 0x01)
	clash := keyWithAlg("witness.stagemole.eu", 0x04) // same name, different key

	keys, ws := networkPeerKeys([]string{mullvadKey}, []server.NetworkWitness{
		{Operator: "Mullvad", VKey: mullvadKey},
		{Operator: "Mullvad again", VKey: clash},
		{Operator: "Other", VKey: " " + other + " "},
		{Operator: "Other twice", VKey: other},
		{Operator: "Wrong type", VKey: noteKey},
		{Operator: "Garbage", VKey: "not a key"},
		{Operator: "Bad hash", VKey: "witness.bad.example+0badc0de+BEqSG3yu9YrmcM3BHvQYTxwFj3uSWakQepafafpUqklv"},
		{Operator: "None"},
	}, log)

	if len(keys) != 2 || keys[0] != mullvadKey || keys[1] != other {
		t.Fatalf("keys = %v, want the configured key and the one new 0x04 key", keys)
	}
	want := []string{mullvadKey, mullvadKey, other, other, "", "", "", ""}
	for i, w := range ws {
		if w.VKey != want[i] {
			t.Errorf("%s: vkey %q, want %q", w.Operator, w.VKey, want[i])
		}
	}
	// And the result is accepted by the verifier it feeds.
	v, err := cosig.NewVerifier(keys)
	if err != nil {
		t.Fatal(err)
	}
	if len(v.Names()) != 2 {
		t.Errorf("verifier names %v", v.Names())
	}
}

func TestNetworkViewNilWhenUnconfigured(t *testing.T) {
	if networkView(nil, nil, nil) != nil {
		t.Fatal("no lists and no witnesses must leave /graph's network layer off")
	}
	f := networkView(nil, nil, []server.NetworkWitness{{Operator: "x", Env: "testing"}})
	if f == nil || len(f().Witnesses) != 1 || len(f().Logs) != 0 {
		t.Fatal("a witness table alone should still be drawn")
	}
}

// Discovered logs are reported with their list's short name; a configured log
// no list names is not a network log.
func TestNetworkViewReportsDiscoveredLogs(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "n.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	const list = "https://raw.githubusercontent.com/transparency-dev/witness-network/main/lists/staging/log-list-10qps-4klogs.1"
	if _, err := db.AddPushLog(&store.PushLog{
		Origin: "pushed.example/log", VKey: testNoteVKey(t, "pushed.example/log"),
		QPD: 24, Contact: "ops", List: list, AddedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	reg := loglist.NewRegistry(nil)
	if err := reg.Load(db); err != nil {
		t.Fatal(err)
	}
	v := networkView(reg, []string{list}, nil)()
	if len(v.Lists) != 1 || v.Lists[0] != "staging/log-list-10qps-4klogs.1" {
		t.Errorf("lists %v", v.Lists)
	}
	if len(v.Logs) != 1 {
		t.Fatalf("logs %+v", v.Logs)
	}
	got := v.Logs[0]
	if got.Origin != "pushed.example/log" || got.Static || got.List != "staging/log-list-10qps-4klogs.1" || got.QPD != 24 {
		t.Errorf("log %+v", got)
	}
}

func testNoteVKey(t *testing.T, name string) string {
	t.Helper()
	_, vkey, err := note.GenerateKey(rand.Reader, name)
	if err != nil {
		t.Fatal(err)
	}
	return vkey
}
