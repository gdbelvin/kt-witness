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
		for _, contained := range []bool{false, true} {
			note, err := checkListenAddr(a, contained)
			if err != nil {
				t.Errorf("%s should be allowed (contained=%v): %v", a, contained, err)
			}
			if note != "" {
				t.Errorf("%s named a LAN address; it needs no caveat, got %q", a, note)
			}
		}
	}

	bad := map[string]string{
		"104.21.6.56:8090":             "a public address",
		"8.8.8.8:8090":                 "a public address",
		"witness.gdbsecurity.com:8090": "a hostname can resolve anywhere, and can change later",
		"192.168.0.10":                "no port",
	}
	for a, why := range bad {
		for _, contained := range []bool{false, true} {
			if _, err := checkListenAddr(a, contained); err == nil {
				t.Errorf("%s should be refused (%s), contained=%v", a, why, contained)
			}
		}
	}
}

// On a host, binding everything is refused: the machine has a LAN address and
// nothing stands between that port and the network.
func TestAnUnspecifiedBindIsRefusedOnAHost(t *testing.T) {
	for _, a := range []string{":8090", "0.0.0.0:8090", "[::]:8090"} {
		if _, err := checkListenAddr(a, false); err == nil {
			t.Errorf("%s should be refused on a host", a)
		}
	}
}

// Inside a container it is allowed, and says so.
//
// The namespace is the confinement: the host's LAN address does not exist in
// there, so naming it would not restrict the listener, it would stop the
// witness from starting at all. What can reach the port is decided by the
// publish rule — which must carry a host_ip, and which this process cannot
// read. Hence the note: the caller is required to log what it cannot check.
func TestAnUnspecifiedBindIsAllowedInAContainerAndSaysSo(t *testing.T) {
	for _, a := range []string{":8090", "0.0.0.0:8090", "[::]:8090"} {
		note, err := checkListenAddr(a, true)
		if err != nil {
			t.Errorf("%s should be allowed in a container: %v", a, err)
		}
		if note == "" {
			t.Errorf("%s was allowed silently; confinement it cannot verify must be stated", a)
		}
	}
}

// A worker's target is checked before its token is sent.
//
// The failure this prevents is not a connection error — it is a credential
// disclosure that happens on the way to one. The old default was the witness's
// public HTTPS URL, which cannot serve gRPC at all, so the connection would
// have failed; the token would already have left the machine.
func TestAWorkerRefusesToDialOffThisNetwork(t *testing.T) {
	for _, a := range []string{"192.168.0.10:18090", "127.0.0.1:8090", "100.100.100.100:8090"} {
		if err := CheckDialAddr(a); err != nil {
			t.Errorf("%s is on this network and should be allowed: %v", a, err)
		}
	}
	bad := map[string]string{
		"https://witness.gdbsecurity.com": "a URL, and a public one — the old default",
		"104.21.6.56:18090":               "a public address",
		"8.8.8.8:443":                     "a public address",
		"192.168.0.10":                   "no port",
	}
	for a, why := range bad {
		if err := CheckDialAddr(a); err == nil {
			t.Errorf("%s should be refused (%s)", a, why)
		}
	}
}
