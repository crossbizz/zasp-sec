package main

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"strings"
	"testing"
)

// Wire-format builders for hand-made DNS messages. dnsResponse in
// egress_test.go builds the common well-formed shape; these build the odd
// ones.

func dnsWireName(name string) []byte {
	var wire []byte
	for _, label := range strings.Split(name, ".") {
		wire = append(wire, byte(len(label)))
		wire = append(wire, label...)
	}
	return append(wire, 0)
}

func dnsHeader(flags, questions, answers uint16) []byte {
	header := make([]byte, 12)
	binary.BigEndian.PutUint16(header[0:2], 0xbeef)
	binary.BigEndian.PutUint16(header[2:4], flags)
	binary.BigEndian.PutUint16(header[4:6], questions)
	binary.BigEndian.PutUint16(header[6:8], answers)
	return header
}

func dnsQuestion(name []byte, questionType, class uint16) []byte {
	question := append([]byte{}, name...)
	question = binary.BigEndian.AppendUint16(question, questionType)
	return binary.BigEndian.AppendUint16(question, class)
}

func dnsRecord(owner []byte, recordType, class uint16, data []byte) []byte {
	record := append([]byte{}, owner...)
	record = binary.BigEndian.AppendUint16(record, recordType)
	record = binary.BigEndian.AppendUint16(record, class)
	record = binary.BigEndian.AppendUint32(record, 60)
	record = binary.BigEndian.AppendUint16(record, uint16(len(data)))
	return append(record, data...)
}

// questionPointer is a compression pointer to the question name at offset 12.
var questionPointer = []byte{0xc0, 12}

const (
	dnsTypeA, dnsTypeCNAME, dnsTypeTXT, dnsTypeAAAA, dnsTypeHTTPS = 1, 5, 16, 28, 65
	dnsClassIN, dnsClassCH                                        = 1, 3
	dnsResponseFlags                                              = 0x8180 // QR, RD, RA, NOERROR
)

func addressBytes(address string) []byte {
	return netip.MustParseAddr(address).AsSlice()
}

func aRecord(address string) []byte {
	return dnsRecord(questionPointer, dnsTypeA, dnsClassIN, addressBytes(address))
}

// dnsMessage is a response with the given flags and counts, one question for
// name, and the given raw answer records.
func dnsMessage(flags, questions, answers uint16, question []byte, records ...[]byte) []byte {
	return bytes.Join(append([][]byte{dnsHeader(flags, questions, answers), question}, records...), nil)
}

func openAIQuestion() []byte { return dnsQuestion(dnsWireName("api.openai.com"), dnsTypeA, dnsClassIN) }

// ipv4Packet builds an IPv4/UDP packet with a configurable header length,
// flags/fragment field and protocol; the client (IP destination) is 10.1.2.3.
func ipv4Packet(headerWords int, fragment uint16, protocol byte, sourcePort uint16, payload []byte) []byte {
	headerLength := headerWords * 4
	packet := make([]byte, headerLength+8+len(payload))
	packet[0], packet[9] = 0x40|byte(headerWords), protocol
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	binary.BigEndian.PutUint16(packet[6:8], fragment)
	copy(packet[12:16], addressBytes("10.96.0.10"))
	copy(packet[16:20], addressBytes("10.1.2.3"))
	binary.BigEndian.PutUint16(packet[headerLength:], sourcePort)
	binary.BigEndian.PutUint16(packet[headerLength+2:], 40000)
	binary.BigEndian.PutUint16(packet[headerLength+4:], uint16(8+len(payload)))
	copy(packet[headerLength+8:], payload)
	return packet
}

// chainedPointerMessage is an A response whose question name is reached
// through exactly jumps compression pointers; the answer owner points at the
// start of the same chain and so takes the same number of jumps.
func chainedPointerMessage(jumps int) []byte {
	message := dnsHeader(dnsResponseFlags, 1, 1)
	questionAt := len(message)
	message = append(message, 0xc0, 0, 0, dnsTypeA, 0, dnsClassIN)
	ownerAt := len(message)
	message = append(message, aRecord("104.18.6.192")...)
	tail := len(message)
	binary.BigEndian.PutUint16(message[questionAt:], 0xc000|uint16(tail))
	binary.BigEndian.PutUint16(message[ownerAt:], 0xc000|uint16(tail))
	for index := 1; index < jumps; index++ {
		message = binary.BigEndian.AppendUint16(message, 0xc000|uint16(tail+2*index))
	}
	return append(message, dnsWireName("api.openai.com")...)
}

func TestParseDNSResponsePacketAcceptsValidVariants(t *testing.T) {
	longName := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61)
	manyAnswers := [][]byte{}
	for index := range 70 {
		manyAnswers = append(manyAnswers, aRecord(netip.AddrFrom4([4]byte{104, 18, 6, byte(index)}).String()))
	}
	withPadding := ipv4UDP("10.96.0.10", "10.1.2.3", 53, dnsMessage(dnsResponseFlags, 1, 1, openAIQuestion(), aRecord("104.18.6.192")))
	withPadding = append(withPadding, 0xde, 0xad, 0xbe, 0xef) // link-layer padding past the IP total length
	shortUDP := ipv4UDP("10.96.0.10", "10.1.2.3", 53, append(dnsMessage(dnsResponseFlags, 1, 1, openAIQuestion(), aRecord("104.18.6.192")), 0xff, 0xff, 0xff))
	binary.BigEndian.PutUint16(shortUDP[24:26], binary.BigEndian.Uint16(shortUDP[24:26])-3) // UDP length excludes trailing junk
	for _, test := range []struct {
		name      string
		packet    []byte
		client    string
		host      string
		addresses []string
	}{{
		name:   "AAAA question with mapped and native answers",
		packet: ipv4UDP("10.96.0.10", "10.1.2.3", 53, dnsMessage(dnsResponseFlags, 1, 2, dnsQuestion(dnsWireName("api.anthropic.com"), dnsTypeAAAA, dnsClassIN), dnsRecord(questionPointer, dnsTypeAAAA, dnsClassIN, addressBytes("::ffff:160.79.104.10")), dnsRecord(questionPointer, dnsTypeAAAA, dnsClassIN, addressBytes("2607:6bc0::10")))),
		client: "10.1.2.3", host: "api.anthropic.com", addresses: []string{"160.79.104.10", "2607:6bc0::10"},
	}, {
		name:   "don't-fragment bit is not a fragment",
		packet: ipv4Packet(5, 0x4000, 17, 53, dnsMessage(dnsResponseFlags, 1, 1, openAIQuestion(), aRecord("104.18.6.192"))),
		client: "10.1.2.3", host: "api.openai.com", addresses: []string{"104.18.6.192"},
	}, {
		name:   "IPv4 options shift the UDP header",
		packet: ipv4Packet(7, 0, 17, 53, dnsMessage(dnsResponseFlags, 1, 1, openAIQuestion(), aRecord("104.18.6.192"))),
		client: "10.1.2.3", host: "api.openai.com", addresses: []string{"104.18.6.192"},
	}, {
		name: "bytes past the IP total length are ignored", packet: withPadding,
		client: "10.1.2.3", host: "api.openai.com", addresses: []string{"104.18.6.192"},
	}, {
		name: "bytes past the UDP length are ignored", packet: shortUDP,
		client: "10.1.2.3", host: "api.openai.com", addresses: []string{"104.18.6.192"},
	}, {
		name:   "IPv4-mapped IPv6 client is unmapped",
		packet: ipv6UDP("fd00::a", "::ffff:10.1.2.3", 53, dnsMessage(dnsResponseFlags, 1, 1, openAIQuestion(), aRecord("104.18.6.192"))),
		client: "10.1.2.3", host: "api.openai.com", addresses: []string{"104.18.6.192"},
	}, {
		name:   "authoritative answer flags are a success",
		packet: ipv4UDP("10.96.0.10", "10.1.2.3", 53, dnsMessage(0x8580, 1, 1, openAIQuestion(), aRecord("104.18.6.192"))),
		client: "10.1.2.3", host: "api.openai.com", addresses: []string{"104.18.6.192"},
	}, {
		name: "records that are not IN A/AAAA of the right size are skipped",
		packet: ipv4UDP("10.96.0.10", "10.1.2.3", 53, dnsMessage(dnsResponseFlags, 1, 6, openAIQuestion(),
			dnsRecord(questionPointer, dnsTypeCNAME, dnsClassIN, dnsWireName("edge.example")),
			dnsRecord(questionPointer, dnsTypeTXT, dnsClassIN, []byte("\x041.2.3.4")),
			dnsRecord(questionPointer, dnsTypeA, dnsClassCH, addressBytes("1.1.1.1")),
			dnsRecord(questionPointer, dnsTypeA, dnsClassIN, []byte{2, 2, 2, 2, 2}),
			dnsRecord(questionPointer, dnsTypeAAAA, dnsClassIN, addressBytes("3.3.3.3")),
			aRecord("104.18.6.192"))),
		client: "10.1.2.3", host: "api.openai.com", addresses: []string{"104.18.6.192"},
	}, {
		name:   "253-character name",
		packet: ipv4UDP("10.96.0.10", "10.1.2.3", 53, dnsMessage(dnsResponseFlags, 1, 1, dnsQuestion(dnsWireName(longName), dnsTypeA, dnsClassIN), aRecord("1.2.3.4"))),
		client: "10.1.2.3", host: longName, addresses: []string{"1.2.3.4"},
	}, {
		name:   "underscore labels are accepted",
		packet: ipv4UDP("10.96.0.10", "10.1.2.3", 53, dnsMessage(dnsResponseFlags, 1, 1, dnsQuestion(dnsWireName("_mcp.MCP.example.com"), dnsTypeA, dnsClassIN), aRecord("1.2.3.4"))),
		client: "10.1.2.3", host: "_mcp.mcp.example.com", addresses: []string{"1.2.3.4"},
	}, {
		name:   "eight compression jumps are allowed",
		packet: ipv4UDP("10.96.0.10", "10.1.2.3", 53, chainedPointerMessage(8)),
		client: "10.1.2.3", host: "api.openai.com", addresses: []string{"104.18.6.192"},
	}} {
		t.Run(test.name, func(t *testing.T) {
			resolution, ok := parseDNSResponsePacket(test.packet)
			if !ok {
				t.Fatal("refused")
			}
			if resolution.client != netip.MustParseAddr(test.client) || resolution.name != test.host || len(resolution.addresses) != len(test.addresses) {
				t.Fatalf("resolution = %+v", resolution)
			}
			for index, address := range test.addresses {
				if resolution.addresses[index] != netip.MustParseAddr(address) {
					t.Fatalf("address %d = %v, want %s", index, resolution.addresses[index], address)
				}
			}
		})
	}
	t.Run("answers are capped", func(t *testing.T) {
		resolution, ok := parseDNSResponsePacket(ipv4UDP("10.96.0.10", "10.1.2.3", 53, dnsMessage(dnsResponseFlags, 1, 70, openAIQuestion(), manyAnswers...)))
		if !ok || len(resolution.addresses) != maximumDNSAnswers || resolution.addresses[maximumDNSAnswers-1] != netip.MustParseAddr("104.18.6.63") {
			t.Fatalf("got %d addresses, ok %v", len(resolution.addresses), ok)
		}
	})
}

func TestParseDNSResponsePacketRefusesMalformedAndUnwanted(t *testing.T) {
	good := func() []byte { return dnsMessage(dnsResponseFlags, 1, 1, openAIQuestion(), aRecord("104.18.6.192")) }
	v4 := func(message []byte) []byte { return ipv4UDP("10.96.0.10", "10.1.2.3", 53, message) }
	mutate := func(packet []byte, change func([]byte)) []byte { change(packet); return packet }
	truncatedRecord := aRecord("104.18.6.192")[:2+9]
	overrun := dnsRecord(questionPointer, dnsTypeA, dnsClassIN, addressBytes("104.18.6.192"))
	binary.BigEndian.PutUint16(overrun[10:12], 200)
	// A label containing a dot must not decode into a catalog name.
	dottedLabel := append([]byte{byte(len("api.openai"))}, "api.openai"...)
	dottedLabel = append(append(dottedLabel, 3), "com"...)
	dottedLabel = append(dottedLabel, 0)
	tooLong := strings.TrimSuffix(strings.Repeat(strings.Repeat("a", 63)+".", 5), ".")
	for name, packet := range map[string][]byte{
		"single byte":                        {0x45},
		"unknown IP version":                 mutate(v4(good()), func(packet []byte) { packet[0] = 0x55 }),
		"IPv4 header length below 20":        mutate(v4(good()), func(packet []byte) { packet[0] = 0x44 }),
		"IPv4 shorter than header and UDP":   v4(good())[:27],
		"IPv4 not UDP":                       ipv4Packet(5, 0, 6, 53, good()),
		"IPv4 first fragment":                ipv4Packet(5, 0x2000, 17, 53, good()),
		"IPv4 later fragment":                ipv4Packet(5, 0x0001, 17, 53, good()),
		"IPv4 total length below UDP header": mutate(v4(good()), func(packet []byte) { binary.BigEndian.PutUint16(packet[2:4], 27) }),
		"IPv4 total length past capture":     mutate(v4(good()), func(packet []byte) { binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)+1)) }),
		"IPv6 shorter than header and UDP":   ipv6UDP("fd00::a", "fd00::1:2", 53, good())[:47],
		"IPv6 extension header":              mutate(ipv6UDP("fd00::a", "fd00::1:2", 53, good()), func(packet []byte) { packet[6] = 0 }),
		"IPv6 payload below UDP header":      mutate(ipv6UDP("fd00::a", "fd00::1:2", 53, good()), func(packet []byte) { binary.BigEndian.PutUint16(packet[4:6], 7) }),
		"IPv6 payload past capture":          mutate(ipv6UDP("fd00::a", "fd00::1:2", 53, good()), func(packet []byte) { binary.BigEndian.PutUint16(packet[4:6], uint16(len(packet))) }),
		"IPv6 not from port 53":              ipv6UDP("fd00::a", "fd00::1:2", 853, good()),
		"UDP length below DNS header":        mutate(v4(good()), func(packet []byte) { binary.BigEndian.PutUint16(packet[24:26], 19) }),
		"UDP length past datagram":           mutate(v4(good()), func(packet []byte) { binary.BigEndian.PutUint16(packet[24:26], uint16(len(packet))) }),
		"opcode IQUERY":                      v4(dnsMessage(dnsResponseFlags|0x0800, 1, 1, openAIQuestion(), aRecord("104.18.6.192"))),
		"opcode NOTIFY":                      v4(dnsMessage(dnsResponseFlags|0x2000, 1, 1, openAIQuestion(), aRecord("104.18.6.192"))),
		"SERVFAIL":                           v4(dnsMessage(dnsResponseFlags|2, 1, 1, openAIQuestion(), aRecord("104.18.6.192"))),
		"REFUSED":                            v4(dnsMessage(dnsResponseFlags|5, 1, 1, openAIQuestion(), aRecord("104.18.6.192"))),
		"no question":                        v4(dnsMessage(dnsResponseFlags, 0, 1, openAIQuestion(), aRecord("104.18.6.192"))),
		"two questions":                      v4(dnsMessage(dnsResponseFlags, 2, 1, openAIQuestion(), openAIQuestion(), aRecord("104.18.6.192"))),
		"answer count zero":                  v4(dnsMessage(dnsResponseFlags, 1, 0, openAIQuestion(), aRecord("104.18.6.192"))),
		"TXT question":                       v4(dnsMessage(dnsResponseFlags, 1, 1, dnsQuestion(dnsWireName("api.openai.com"), dnsTypeTXT, dnsClassIN), aRecord("104.18.6.192"))),
		"HTTPS question":                     v4(dnsMessage(dnsResponseFlags, 1, 1, dnsQuestion(dnsWireName("api.openai.com"), dnsTypeHTTPS, dnsClassIN), aRecord("104.18.6.192"))),
		"CHAOS class question":               v4(dnsMessage(dnsResponseFlags, 1, 1, dnsQuestion(dnsWireName("api.openai.com"), dnsTypeA, dnsClassCH), aRecord("104.18.6.192"))),
		"question cut after the name":        v4(dnsMessage(dnsResponseFlags, 1, 1, append(dnsWireName("api.openai.com"), 0, 1))),
		"root question name":                 v4(dnsMessage(dnsResponseFlags, 1, 1, dnsQuestion([]byte{0}, dnsTypeA, dnsClassIN), aRecord("104.18.6.192"))),
		"answer header truncated":            v4(dnsMessage(dnsResponseFlags, 1, 1, openAIQuestion(), truncatedRecord)),
		"answer data past message":           v4(dnsMessage(dnsResponseFlags, 1, 1, openAIQuestion(), overrun)),
		"answer count above records":         v4(dnsMessage(dnsResponseFlags, 1, 3, openAIQuestion(), aRecord("104.18.6.192"))),
		"only CNAME answers":                 v4(dnsMessage(dnsResponseFlags, 1, 1, openAIQuestion(), dnsRecord(questionPointer, dnsTypeCNAME, dnsClassIN, dnsWireName("edge.example")))),
		"answer owner with a bad character":  v4(dnsMessage(dnsResponseFlags, 1, 2, openAIQuestion(), aRecord("104.18.6.192"), dnsRecord(dnsWireName("a*b.example"), dnsTypeA, dnsClassIN, addressBytes("1.2.3.4")))),
		"answer owner pointer loop":          v4(dnsMessage(dnsResponseFlags, 1, 1, openAIQuestion(), dnsRecord([]byte{0xc0, 32}, dnsTypeA, dnsClassIN, addressBytes("1.2.3.4")))),
		"label length 64":                    v4(dnsMessage(dnsResponseFlags, 1, 1, dnsQuestion(append([]byte{64}, append(bytes.Repeat([]byte("a"), 64), 0)...), dnsTypeA, dnsClassIN), aRecord("1.2.3.4"))),
		"reserved label type":                v4(dnsMessage(dnsResponseFlags, 1, 1, dnsQuestion([]byte{0x80, 1, 0}, dnsTypeA, dnsClassIN), aRecord("1.2.3.4"))),
		"pointer cut in half":                v4(append(dnsHeader(dnsResponseFlags, 1, 1), 0xc0)),
		"pointer past the message":           v4(dnsMessage(dnsResponseFlags, 1, 1, dnsQuestion([]byte{0xff, 0xff}, dnsTypeA, dnsClassIN), aRecord("1.2.3.4"))),
		"nine compression jumps":             v4(chainedPointerMessage(9)),
		"label cut by end of message":        v4(append(dnsHeader(dnsResponseFlags, 1, 1), 10, 'a', 'p', 'i')),
		"dot inside a label":                 v4(dnsMessage(dnsResponseFlags, 1, 1, dnsQuestion(dottedLabel, dnsTypeA, dnsClassIN), aRecord("104.18.6.192"))),
		"space inside a label":               v4(dnsMessage(dnsResponseFlags, 1, 1, dnsQuestion(dnsWireName("api.open ai.com"), dnsTypeA, dnsClassIN), aRecord("104.18.6.192"))),
		"name longer than 254":               v4(dnsMessage(dnsResponseFlags, 1, 1, dnsQuestion(dnsWireName(tooLong), dnsTypeA, dnsClassIN), aRecord("1.2.3.4"))),
	} {
		if resolution, ok := parseDNSResponsePacket(packet); ok {
			t.Errorf("%s: accepted %+v", name, resolution)
		}
	}
	// The baseline the mutations start from is itself accepted, so each
	// refusal above is caused by its mutation.
	if _, ok := parseDNSResponsePacket(v4(good())); !ok {
		t.Fatal("baseline refused")
	}
	if _, ok := parseDNSResponsePacket(ipv6UDP("fd00::a", "fd00::1:2", 53, good())); !ok {
		t.Fatal("IPv6 baseline refused")
	}
}

// FuzzParseDNSResponsePacket checks the parser's contract on arbitrary
// input: it never panics, and whatever it accepts is a usable resolution.
func FuzzParseDNSResponsePacket(f *testing.F) {
	f.Add(ipv4UDP("10.96.0.10", "10.1.2.3", 53, dnsResponse("api.openai.com", "104.18.6.192", "2606:4700::6812:6c0")))
	f.Add(ipv6UDP("fd00::a", "fd00::1:2", 53, dnsResponse("api.anthropic.com", "160.79.104.10")))
	f.Add(ipv4UDP("10.96.0.10", "10.1.2.3", 53, chainedPointerMessage(8)))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, packet []byte) {
		resolution, ok := parseDNSResponsePacket(packet)
		if !ok {
			return
		}
		if !resolution.client.IsValid() || resolution.name == "" || len(resolution.name) > 254 || len(resolution.addresses) == 0 || len(resolution.addresses) > maximumDNSAnswers {
			t.Fatalf("accepted an unusable resolution %+v", resolution)
		}
		if resolution.name != strings.ToLower(resolution.name) || strings.HasSuffix(resolution.name, ".") {
			t.Fatalf("name not canonical: %q", resolution.name)
		}
		for _, address := range resolution.addresses {
			if !address.IsValid() || address.Is4In6() {
				t.Fatalf("address %v not canonical", address)
			}
		}
	})
}

// parseDNSAnswer guards its own input even though the packet parser only
// hands it messages of at least a header's length.
func TestParseDNSAnswerRefusesShortMessage(t *testing.T) {
	for length := range 12 {
		if name, addresses, ok := parseDNSAnswer(make([]byte, length)); ok || name != "" || addresses != nil {
			t.Fatalf("length %d: %q, %v, %v", length, name, addresses, ok)
		}
	}
}
