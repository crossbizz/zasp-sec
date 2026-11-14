// Package publicaddress decides whether an IP address belongs to the public
// internet. It is the check every outbound request to a host a customer names
// goes through (the Nango per-tenant proxy, the hosted gateway's upstreams),
// so that such a request can never reach the cluster, the cloud metadata
// service or a private network.
package publicaddress

import "net"

// nonPublicNetworks are the address ranges that Go's own tests do not call
// private, loopback, link-local or multicast and that still never belong to
// a provider on the public internet: shared address space (carrier NAT,
// where cloud and cluster services often live), protocol assignments,
// benchmarking, documentation, reserved space, and the IPv6 ranges that
// embed or translate an IPv4 address.
var nonPublicNetworks = func() []*net.IPNet {
	var networks []*net.IPNet
	for _, cidr := range []string{
		"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4",
		"64:ff9b::/96", "64:ff9b:1::/48", "100::/64", "2001:db8::/32", "2002::/16", "2001::/32",
	} {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			panic(err)
		}
		networks = append(networks, network)
	}
	return networks
}()

// IsPublic reports whether value is an address of the public internet. An
// IPv4 address in its 16-byte form is judged as the IPv4 address it is.
func IsPublic(value net.IP) bool {
	if four := value.To4(); four != nil && len(value) == net.IPv6len {
		value = four
	}
	if value == nil || len(value) != net.IPv4len && len(value) != net.IPv6len || value.IsUnspecified() || value.IsLoopback() || value.IsPrivate() || value.IsLinkLocalUnicast() || value.IsLinkLocalMulticast() || value.IsMulticast() || value.IsInterfaceLocalMulticast() {
		return false
	}
	for _, network := range nonPublicNetworks {
		if network.Contains(value) {
			return false
		}
	}
	return true
}
