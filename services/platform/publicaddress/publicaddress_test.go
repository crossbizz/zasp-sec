package publicaddress

import (
	"net"
	"testing"
)

func TestIsPublic(t *testing.T) {
	for address, want := range map[string]bool{
		"8.8.8.8": true, "1.1.1.1": true, "2606:4700:4700::1111": true,
		"127.0.0.1": false, "10.1.2.3": false, "172.16.0.9": false, "192.168.1.1": false, "169.254.169.254": false, "100.64.0.1": false,
		"0.0.0.0": false, "::1": false, "fe80::1": false, "fc00::1": false, "224.0.0.1": false, "::ffff:10.0.0.1": false, "::ffff:169.254.169.254": false,
		"64:ff9b::a00:1": false, "2002:a00:1::": false, "198.18.0.1": false, "240.0.0.1": false,
	} {
		if got := IsPublic(net.ParseIP(address)); got != want {
			t.Errorf("IsPublic(%s) = %v, want %v", address, got, want)
		}
	}
	if IsPublic(nil) || IsPublic(net.IP{1, 2, 3}) {
		t.Error("a malformed address is public")
	}
}
