//go:build linux

package main

import (
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// runClassicBPF interprets the opcodes dnsResponseFilter uses, with the
// kernel's rule that a load past the end of the packet drops it.
func runClassicBPF(t *testing.T, program []unix.SockFilter, packet []byte) uint32 {
	t.Helper()
	var accumulator, index uint32
	load := func(offset uint32, size uint32) (uint32, bool) {
		if uint64(offset)+uint64(size) > uint64(len(packet)) {
			return 0, false
		}
		if size == 1 {
			return uint32(packet[offset]), true
		}
		return uint32(binary.BigEndian.Uint16(packet[offset:])), true
	}
	for counter := 0; counter < len(program); counter++ {
		instruction := program[counter]
		var ok bool
		switch instruction.Code {
		case 0x30: // ld [k], byte
			accumulator, ok = load(instruction.K, 1)
		case 0x28: // ld [k], half
			accumulator, ok = load(instruction.K, 2)
		case 0x48: // ld [x+k], half
			accumulator, ok = load(index+instruction.K, 2)
		case 0xb1: // ldx 4*([k]&0xf)
			var value uint32
			value, ok = load(instruction.K, 1)
			index = (value & 0x0f) * 4
		case 0x74: // rsh #k
			accumulator, ok = accumulator>>instruction.K, true
		case 0x15: // jeq #k
			ok = true
			if accumulator == instruction.K {
				counter += int(instruction.Jt)
			} else {
				counter += int(instruction.Jf)
			}
		case 0x45: // jset #k
			ok = true
			if accumulator&instruction.K != 0 {
				counter += int(instruction.Jt)
			} else {
				counter += int(instruction.Jf)
			}
		case 0x06: // ret #k
			return instruction.K
		default:
			t.Fatalf("instruction %d: unsupported opcode %#x", counter, instruction.Code)
		}
		if !ok {
			return 0
		}
	}
	t.Fatal("the program ran past its end")
	return 0
}

// The in-kernel filter must pass every packet the parser can accept (or
// answers are silently lost) and should drop the obvious rest.
func TestDNSResponseFilterMatchesParser(t *testing.T) {
	answer := dnsMessage(dnsResponseFlags, 1, 1, openAIQuestion(), aRecord("104.18.6.192"))
	ipv6Extension := ipv6UDP("fd00::a", "fd00::1:2", 53, answer)
	ipv6Extension[6] = 0
	for _, test := range []struct {
		name   string
		packet []byte
		pass   bool
	}{
		{"IPv4 from port 53", ipv4UDP("10.96.0.10", "10.1.2.3", 53, answer), true},
		{"IPv4 with options from port 53", ipv4Packet(8, 0, 17, 53, answer), true},
		{"IPv4 don't-fragment", ipv4Packet(5, 0x4000, 17, 53, answer), true},
		{"IPv4 first fragment", ipv4Packet(5, 0x2000, 17, 53, answer), true}, // the parser drops it
		{"IPv6 from port 53", ipv6UDP("fd00::a", "fd00::1:2", 53, answer), true},
		{"IPv4 from port 5353", ipv4UDP("10.96.0.10", "10.1.2.3", 5353, answer), false},
		{"IPv4 to port 53", ipv4Packet(5, 0, 17, 40000, answer), false},
		{"IPv4 TCP from port 53", ipv4Packet(5, 0, 6, 53, answer), false},
		{"IPv4 later fragment", ipv4Packet(5, 0x0010, 17, 53, answer), false},
		{"IPv6 from port 853", ipv6UDP("fd00::a", "fd00::1:2", 853, answer), false},
		{"IPv6 extension header", ipv6Extension, false},
		{"unknown version", append([]byte{0x55}, make([]byte, 60)...), false},
		{"empty", nil, false},
		{"IPv4 cut before the protocol", ipv4UDP("10.96.0.10", "10.1.2.3", 53, answer)[:8], false},
		{"IPv6 cut before the UDP header", ipv6UDP("fd00::a", "fd00::1:2", 53, answer)[:41], false},
	} {
		verdict := runClassicBPF(t, dnsResponseFilter, test.packet)
		if (verdict != 0) != test.pass {
			t.Errorf("%s: verdict %d, want pass=%v", test.name, verdict, test.pass)
		}
		if _, parsed := parseDNSResponsePacket(test.packet); parsed && verdict == 0 {
			t.Errorf("%s: the filter drops a packet the parser accepts", test.name)
		}
	}
}

// A datagram socket pair stands in for the packet socket: run's read,
// parse, deliver and cancellation logic needs no privilege to exercise.
func TestDNSCaptureRunDeliversParsedPacketsUntilCancelled(t *testing.T) {
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(pair[1])
	if err := unix.SetsockoptTimeval(pair[0], unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Usec: 20_000}); err != nil {
		unix.Close(pair[0])
		t.Fatal(err)
	}
	capture := &dnsCapture{descriptor: pair[0]}
	for _, packet := range [][]byte{
		{0xff, 0x00},
		ipv4UDP("10.96.0.10", "10.1.2.3", 5353, dnsResponse("api.openai.com", "104.18.6.192")),
		ipv4UDP("10.96.0.10", "10.1.2.3", 53, dnsResponse("api.openai.com", "104.18.6.192")),
		ipv6UDP("fd00::a", "fd00::1:2", 53, dnsResponse("api.anthropic.com", "160.79.104.10")),
	} {
		if _, err := unix.Write(pair[1], packet); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	delivered := make(chan dnsResolution, 8)
	done := make(chan error, 1)
	go func() { done <- capture.run(ctx, func(resolution dnsResolution) { delivered <- resolution }) }()
	for _, want := range []struct{ client, name string }{{"10.1.2.3", "api.openai.com"}, {"fd00::1:2", "api.anthropic.com"}} {
		select {
		case got := <-delivered:
			if got.client != netip.MustParseAddr(want.client) || got.name != want.name {
				t.Fatalf("delivered %+v, want %+v", got, want)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("nothing delivered")
		}
	}
	// With nothing to read the receive timeout fires repeatedly; run keeps
	// going until it is cancelled, then returns cleanly.
	time.Sleep(60 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run = %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("run ignored cancellation")
	}
	if len(delivered) != 0 {
		t.Fatalf("delivered a malformed packet: %+v", <-delivered)
	}
	if err := capture.Close(); err != nil {
		t.Fatalf("Close = %v", err)
	}
}

func TestDNSCaptureRunFailsOnABrokenSocket(t *testing.T) {
	capture := &dnsCapture{descriptor: -1}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := capture.run(ctx, func(dnsResolution) { t.Error("delivered from a broken socket") }); !errors.Is(err, errEgressCapture) {
		t.Fatalf("run = %v", err)
	}
	// A cancelled context stops run before it touches the socket at all.
	cancel()
	if err := capture.run(ctx, func(dnsResolution) {}); err != nil {
		t.Fatalf("cancelled run = %v", err)
	}
}

func TestDNSCaptureCloseNil(t *testing.T) {
	var capture *dnsCapture
	if err := capture.Close(); err != nil {
		t.Fatalf("Close = %v", err)
	}
}

// openDNSCapture either opens a filtered packet socket (with CAP_NET_RAW) or
// fails with the capture error; it never returns a half-open capture.
func TestOpenDNSCapture(t *testing.T) {
	capture, err := openDNSCapture()
	if err != nil {
		if !errors.Is(err, errEgressCapture) || capture != nil {
			t.Fatalf("capture = %v, err = %v", capture, err)
		}
		t.Skip("packet capture needs CAP_NET_RAW; verified the unprivileged refusal")
	}
	defer capture.Close()
	// The receive timeout is what lets run notice cancellation.
	if timeout, err := unix.GetsockoptTimeval(capture.descriptor, unix.SOL_SOCKET, unix.SO_RCVTIMEO); err != nil || timeout.Sec != 1 {
		t.Fatalf("receive timeout = %+v, %v", timeout, err)
	}
	socketType, err := unix.GetsockoptInt(capture.descriptor, unix.SOL_SOCKET, unix.SO_TYPE)
	if err != nil || socketType != unix.SOCK_DGRAM {
		t.Fatalf("socket type = %d, %v", socketType, err)
	}
}
