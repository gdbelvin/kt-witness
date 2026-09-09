package workrpc

import "testing"

// TestOnlyLocalAddressesAreAccepted.
//
// Getting this wrong is silent: an exposed port behaves exactly like a correct
// one until somebody finds it, and what they find accepts results that move a
// published coverage figure. So the check refuses rather than warns, and the
// cases below are the ones somebody would plausibly type.
func TestOnlyLocalAddressesAreAccepted(t *testing.T) {
	ok := []string{
		"127.0.0.1:8090",
		"192.168.0.10:8090",
		"10.2.0.4:8090",
		"172.16.9.9:8090",
		"100.100.100.100:8090", // tailnet
		"[::1]:8090",
	}
	for _, a := range ok {
		if err := CheckListenAddr(a); err != nil {
			t.Errorf("%s should be allowed: %v", a, err)
		}
	}

	bad := map[string]string{
		":8090":            "a bare port binds everything",
		"0.0.0.0:8090":     "unspecified binds everything",
		"[::]:8090":        "unspecified v6 binds everything",
		"104.21.6.56:8090": "a public address",
		"8.8.8.8:8090":     "a public address",
		"witness.gdbsecurity.com:8090": "a hostname can resolve anywhere, and can change later",
		"192.168.0.10":    "no port",
	}
	for a, why := range bad {
		if err := CheckListenAddr(a); err == nil {
			t.Errorf("%s should be refused (%s)", a, why)
		}
	}
}
