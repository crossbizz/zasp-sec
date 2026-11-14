//go:build linux

package main

import (
	"context"
	"errors"

	"golang.org/x/sys/unix"
)

var errEgressCapture = errors.New("sensor egress capture unavailable")

// dnsCapture reads DNS responses from every interface in its network
// namespace. In the host namespace that includes the host side of each pod's
// veth, so it sees the answers pods receive. It needs CAP_NET_RAW.
type dnsCapture struct{ descriptor int }

// The socket is cooked (SOCK_DGRAM): packets start at the network header on
// every link type. The classic BPF program below keeps unfragmented UDP with
// source port 53 over IPv4 or IPv6 and drops everything else in the kernel.
var dnsResponseFilter = []unix.SockFilter{
	{Code: 0x30, K: 0},                    // 0: A = first byte
	{Code: 0x74, K: 4},                    // 1: A >>= 4 (IP version)
	{Code: 0x15, Jt: 0, Jf: 7, K: 4},      // 2: IPv4? else 10
	{Code: 0x30, K: 9},                    // 3: A = protocol
	{Code: 0x15, Jt: 0, Jf: 11, K: 17},    // 4: UDP? else drop
	{Code: 0x28, K: 6},                    // 5: A = flags and fragment offset
	{Code: 0x45, Jt: 9, Jf: 0, K: 0x1fff}, // 6: a later fragment? drop
	{Code: 0xb1, K: 0},                    // 7: X = IPv4 header length
	{Code: 0x48, K: 0},                    // 8: A = UDP source port
	{Code: 0x15, Jt: 5, Jf: 6, K: 53},     // 9: 53? accept else drop
	{Code: 0x15, Jt: 0, Jf: 5, K: 6},      // 10: IPv6? else drop
	{Code: 0x30, K: 6},                    // 11: A = next header
	{Code: 0x15, Jt: 0, Jf: 3, K: 17},     // 12: UDP? else drop
	{Code: 0x28, K: 40},                   // 13: A = UDP source port
	{Code: 0x15, Jt: 0, Jf: 1, K: 53},     // 14: 53? accept else drop
	{Code: 0x06, K: 0xffff},               // 15: accept
	{Code: 0x06, K: 0},                    // 16: drop
}

func openDNSCapture() (*dnsCapture, error) {
	protocol := uint16(unix.ETH_P_ALL)
	descriptor, err := unix.Socket(unix.AF_PACKET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, int(protocol<<8|protocol>>8))
	if err != nil {
		return nil, errEgressCapture
	}
	program := unix.SockFprog{Len: uint16(len(dnsResponseFilter)), Filter: &dnsResponseFilter[0]}
	// The receive timeout lets the reader notice cancellation.
	if unix.SetsockoptSockFprog(descriptor, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, &program) != nil ||
		unix.SetsockoptTimeval(descriptor, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 1}) != nil {
		_ = unix.Close(descriptor)
		return nil, errEgressCapture
	}
	return &dnsCapture{descriptor: descriptor}, nil
}

// run delivers every parsed DNS response until the context ends or the
// socket fails. Packets that arrived before the filter attached, and any
// malformed packet, are discarded by the parser.
func (capture *dnsCapture) run(ctx context.Context, deliver func(dnsResolution)) error {
	buffer := make([]byte, 65536)
	for ctx.Err() == nil {
		length, _, err := unix.Recvfrom(capture.descriptor, buffer, 0)
		if err != nil {
			if err == unix.EAGAIN || err == unix.EINTR {
				continue
			}
			return errEgressCapture
		}
		if resolution, ok := parseDNSResponsePacket(buffer[:length]); ok {
			deliver(resolution)
		}
	}
	return nil
}

func (capture *dnsCapture) Close() error {
	if capture == nil {
		return nil
	}
	return unix.Close(capture.descriptor)
}
