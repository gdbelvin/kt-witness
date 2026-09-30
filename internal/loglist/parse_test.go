package loglist

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/mod/sumdb/note"
)

// The real published lists, as of the fetch into testdata. Every entry in them
// is Ed25519, so every one must also yield a verifier.
func TestParseRealLists(t *testing.T) {
	for _, tc := range []struct {
		file string
		want int
	}{
		{"testing-log-list.1", 9},
		{"staging-log-list-10qps-4klogs.1", 12},
		{"staging-log-list-100qps-40klogs.1", 13},
	} {
		t.Run(tc.file, func(t *testing.T) {
			fh, err := os.Open(filepath.Join("testdata", tc.file))
			if err != nil {
				t.Fatal(err)
			}
			defer fh.Close()
			entries, err := Parse(fh)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != tc.want {
				t.Fatalf("got %d entries, want %d", len(entries), tc.want)
			}
			for _, e := range entries {
				if e.QPD < 1 || e.Contact == "" || e.Origin == "" {
					t.Errorf("incomplete entry %+v", e)
				}
				if !strings.HasPrefix(e.VKey, e.Origin+"+") {
					t.Errorf("origin %q is not the vkey key name of %q", e.Origin, e.VKey)
				}
				if e.KeyType() != 0x01 {
					t.Errorf("%s: key type 0x%02x, want Ed25519", e.Origin, e.KeyType())
				}
				if _, err := note.NewVerifier(e.VKey); err != nil {
					t.Errorf("%s: %v", e.Origin, err)
				}
			}
		})
	}
}

// A real key whose base64 ends in '+': splitting on '+' would mangle it.
func TestParseKeyWithPlusInMaterial(t *testing.T) {
	const vkey = "log.frem.sh+4e9c5de6+AcfzmSNWSmxIklo06ELrJzqR8VNCsdV3Sz9pFqL+5lH+"
	entries, err := Parse(strings.NewReader("logs/v0\nvkey " + vkey + "\nqpd 96\ncontact info@fremverk.com\n"))
	if err != nil {
		t.Fatal(err)
	}
	if entries[0].Origin != "log.frem.sh" || entries[0].VKey != vkey {
		t.Fatalf("got %+v", entries[0])
	}
}

func TestParseOriginAndWhitespace(t *testing.T) {
	a := testVKey(t, "a.example/log")
	b := testVKey(t, "b.example/log")
	list := "  # comment\n\n\t logs/v0 \n" +
		"vkey " + a + "\n" +
		"  qpd 24\n" +
		"contact  two  spaces | kept \n" +
		"# between entries\n" +
		"vkey " + b + "\n" +
		"origin something-not-equal-to-vkey-keyname\n" +
		"qpd 2147483647\n" +
		"contact sysadmin (at) b.example\n"
	entries, err := Parse(strings.NewReader(list))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("got %d entries", len(entries))
	}
	if entries[0].Origin != "a.example/log" || entries[0].QPD != 24 || entries[0].Contact != " two  spaces | kept" {
		t.Errorf("entry 0: %+v", entries[0])
	}
	if entries[1].Origin != "something-not-equal-to-vkey-keyname" || entries[1].QPD != 1<<31-1 {
		t.Errorf("entry 1: %+v", entries[1])
	}
}

func TestParseEmptyList(t *testing.T) {
	entries, err := Parse(strings.NewReader("# nothing yet\nlogs/v0\n"))
	if err != nil || len(entries) != 0 {
		t.Fatalf("got %v, %v", entries, err)
	}
}

func TestParseRejectsMalformed(t *testing.T) {
	k := testVKey(t, "a.example/log")
	k2 := testVKey(t, "b.example/log")
	entry := "vkey " + k + "\nqpd 24\ncontact c\n"
	for name, list := range map[string]string{
		"empty":                "",
		"missing header":       entry,
		"wrong header":         "logs/v1\n" + entry,
		"duplicate header":     "logs/v0\nlogs/v0\n" + entry,
		"header after entry":   "logs/v0\n" + entry + "logs/v0\n",
		"qpd before vkey":      "logs/v0\nqpd 24\nvkey " + k + "\ncontact c\n",
		"origin after qpd":     "logs/v0\nvkey " + k + "\nqpd 24\norigin o\ncontact c\n",
		"contact before qpd":   "logs/v0\nvkey " + k + "\ncontact c\nqpd 24\n",
		"missing qpd":          "logs/v0\nvkey " + k + "\ncontact c\n",
		"missing contact":      "logs/v0\nvkey " + k + "\nqpd 24\nvkey " + k2 + "\nqpd 24\ncontact c\n",
		"missing contact eof":  "logs/v0\nvkey " + k + "\nqpd 24\n",
		"vkey only eof":        "logs/v0\nvkey " + k + "\n",
		"unknown field":        "logs/v0\nvkey " + k + "\nqpd 24\ncontact c\nurl https://x\n",
		"unknown field inside": "logs/v0\nvkey " + k + "\nsize 3\nqpd 24\ncontact c\n",
		"two origins":          "logs/v0\nvkey " + k + "\norigin a\norigin b\nqpd 24\ncontact c\n",
		"origin leading space": "logs/v0\nvkey " + k + "\norigin  o\nqpd 24\ncontact c\n",
		"empty contact":        "logs/v0\nvkey " + k + "\nqpd 24\ncontact\n",
		"qpd zero":             "logs/v0\nvkey " + k + "\nqpd 0\ncontact c\n",
		"qpd leading zero":     "logs/v0\nvkey " + k + "\nqpd 024\ncontact c\n",
		"qpd 2^31":             "logs/v0\nvkey " + k + "\nqpd 2147483648\ncontact c\n",
		"qpd huge":             "logs/v0\nvkey " + k + "\nqpd 99999999999999999999999\ncontact c\n",
		"qpd plus":             "logs/v0\nvkey " + k + "\nqpd +24\ncontact c\n",
		"qpd negative":         "logs/v0\nvkey " + k + "\nqpd -1\ncontact c\n",
		"qpd hex":              "logs/v0\nvkey " + k + "\nqpd 0x10\ncontact c\n",
		"qpd space":            "logs/v0\nvkey " + k + "\nqpd 2 4\ncontact c\n",
		"vkey no id":           "logs/v0\nvkey a.example\nqpd 24\ncontact c\n",
		"vkey bad id":          "logs/v0\nvkey a.example+zzzzzzzz+AQID\nqpd 24\ncontact c\n",
		"vkey bad base64":      "logs/v0\nvkey a.example+01020304+!!!!\nqpd 24\ncontact c\n",
		"vkey empty name":      "logs/v0\nvkey +01020304+AQID\nqpd 24\ncontact c\n",
		"duplicate origin":     "logs/v0\n" + entry + entry,
		"good then bad":        "logs/v0\n" + entry + "vkey " + k2 + "\nqpd 0\ncontact c\n",
	} {
		t.Run(name, func(t *testing.T) {
			if entries, err := Parse(strings.NewReader(list)); err == nil {
				t.Fatalf("accepted: %+v", entries)
			}
		})
	}
}

// testVKey returns a fresh Ed25519 vkey named name.
func testVKey(t *testing.T, name string) string {
	t.Helper()
	_, vkey, err := note.GenerateKey(rand.Reader, name)
	if err != nil {
		t.Fatal(err)
	}
	return vkey
}

// mldsaVKey returns a syntactically valid ML-DSA-44 vkey (type 0x06, 1312-byte
// key) with a correct key ID, so a rejection is for the algorithm and not a
// malformed key.
func mldsaVKey(t *testing.T, name string) string {
	t.Helper()
	key := make([]byte, 1+1312)
	key[0] = 0x06
	if _, err := rand.Read(key[1:]); err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(append([]byte(name+"\n"), key...))
	return name + "+" + hex.EncodeToString(h[:4]) + "+" + base64.StdEncoding.EncodeToString(key)
}

func TestParseMLDSAKey(t *testing.T) {
	vkey := mldsaVKey(t, "pq.example/log")
	entries, err := Parse(strings.NewReader("logs/v0\nvkey " + vkey + "\nqpd 24\ncontact c\n"))
	if err != nil {
		t.Fatal(err)
	}
	if entries[0].KeyType() != 0x06 || entries[0].Origin != "pq.example/log" {
		t.Fatalf("got %+v", entries[0])
	}
}
