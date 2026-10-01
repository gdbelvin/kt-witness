package pbwire

import "testing"

func TestFieldsStrict(t *testing.T) {
	ok := []byte{
		0x08, 0x96, 0x01, // field 1 varint 150
		0x12, 0x02, 'h', 'i', // field 2 bytes
		0x1d, 1, 2, 3, 4, // field 3 fixed32
		0x21, 1, 2, 3, 4, 5, 6, 7, 8, // field 4 fixed64
	}
	fs, err := Fields(ok)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 4 || fs[0].Varint != 150 || string(fs[1].Bytes) != "hi" ||
		fs[2].Wire != 5 || len(fs[2].Bytes) != 4 || fs[3].Wire != 1 || len(fs[3].Bytes) != 8 {
		t.Fatalf("decoded %+v", fs)
	}
	max := []byte{0x08, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01}
	if fs, err := Fields(max); err != nil || fs[0].Varint != ^uint64(0) {
		t.Fatalf("max varint: %v %+v", err, fs)
	}

	bad := map[string][]byte{
		"truncated varint":  {0x08, 0x96},
		"truncated tag":     {0x80},
		"varint > 64 bits":  {0x08, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02},
		"length past end":   {0x12, 0x05, 'h'},
		"huge length":       {0x12, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f},
		"field zero":        {0x00, 0x00},
		"start group":       {0x0b},
		"end group":         {0x0c},
		"truncated fixed32": {0x1d, 1, 2},
		"truncated fixed64": {0x21, 1, 2, 3},
	}
	for name, b := range bad {
		if _, err := Fields(b); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
