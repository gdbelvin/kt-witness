package netmeter

import (
	"net"
	"testing"

	"golang.org/x/sys/unix"
)

func TestTheMarkReachesTheSocket(t *testing.T) {
	t.Cleanup(func() { SetDSCP(0) })
	SetDSCP(DSCPCS1)

	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Skip("no loopback listener:", err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err == nil {
			c.Close()
		}
	}()

	c, err := Dialer().Dial("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	raw, err := c.(*net.TCPConn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var got int
	if err := raw.Control(func(fd uintptr) {
		got, _ = unix.GetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_TOS)
	}); err != nil {
		t.Fatal(err)
	}
	if want := DSCPCS1 << 2; got != want {
		t.Errorf("IP_TOS = %d, want %d (CS1 in the top six bits)", got, want)
	}
}
