package main

import (
	"encoding/binary"
	"net/netip"
	"strings"
)

// dnsResolution is what one DNS response tells the egress role: the client
// that asked, the name it asked for, and the addresses it was given.
type dnsResolution struct {
	client    netip.Addr
	name      string
	addresses []netip.Addr
}

const maximumDNSAnswers = 64

// parseDNSResponsePacket reads an IP packet that starts at the network
// header. It accepts only an unfragmented UDP datagram from port 53 that is a
// successful answer to one A or AAAA question. Anything else, including
// every malformed input, yields false; the parser never panics on truncated
// data.
func parseDNSResponsePacket(packet []byte) (dnsResolution, bool) {
	if len(packet) < 1 {
		return dnsResolution{}, false
	}
	var client netip.Addr
	var transport []byte
	switch packet[0] >> 4 {
	case 4:
		headerLength := int(packet[0]&0x0f) * 4
		if headerLength < 20 || len(packet) < headerLength+8 || packet[9] != 17 || binary.BigEndian.Uint16(packet[6:8])&0x3fff != 0 {
			return dnsResolution{}, false
		}
		total := int(binary.BigEndian.Uint16(packet[2:4]))
		if total < headerLength+8 || total > len(packet) {
			return dnsResolution{}, false
		}
		client = netip.AddrFrom4([4]byte(packet[16:20]))
		transport = packet[headerLength:total]
	case 6:
		if len(packet) < 48 || packet[6] != 17 {
			return dnsResolution{}, false
		}
		payload := int(binary.BigEndian.Uint16(packet[4:6]))
		if payload < 8 || 40+payload > len(packet) {
			return dnsResolution{}, false
		}
		client = netip.AddrFrom16([16]byte(packet[24:40])).Unmap()
		transport = packet[40 : 40+payload]
	default:
		return dnsResolution{}, false
	}
	if binary.BigEndian.Uint16(transport[0:2]) != 53 {
		return dnsResolution{}, false
	}
	length := int(binary.BigEndian.Uint16(transport[4:6]))
	if length < 8+12 || length > len(transport) {
		return dnsResolution{}, false
	}
	name, addresses, ok := parseDNSAnswer(transport[8:length])
	if !ok {
		return dnsResolution{}, false
	}
	return dnsResolution{client: client, name: name, addresses: addresses}, true
}

// parseDNSAnswer reads a DNS message. Addresses are attributed to the
// question name, so a CNAME chain still maps the final addresses to the name
// the client asked for.
func parseDNSAnswer(message []byte) (string, []netip.Addr, bool) {
	if len(message) < 12 {
		return "", nil, false
	}
	flags := binary.BigEndian.Uint16(message[2:4])
	questions, answers := binary.BigEndian.Uint16(message[4:6]), int(binary.BigEndian.Uint16(message[6:8]))
	// QR set, opcode QUERY, RCODE NOERROR, exactly one question.
	if flags&0x8000 == 0 || flags&0x7800 != 0 || flags&0x000f != 0 || questions != 1 || answers < 1 {
		return "", nil, false
	}
	if answers > maximumDNSAnswers {
		answers = maximumDNSAnswers
	}
	name, offset, ok := readDNSName(message, 12)
	if !ok || offset+4 > len(message) {
		return "", nil, false
	}
	questionType, class := binary.BigEndian.Uint16(message[offset:offset+2]), binary.BigEndian.Uint16(message[offset+2:offset+4])
	if questionType != 1 && questionType != 28 || class != 1 {
		return "", nil, false
	}
	offset += 4
	var addresses []netip.Addr
	for range answers {
		_, next, ok := readDNSName(message, offset)
		if !ok || next+10 > len(message) {
			return "", nil, false
		}
		recordType, recordClass := binary.BigEndian.Uint16(message[next:next+2]), binary.BigEndian.Uint16(message[next+2:next+4])
		dataLength := int(binary.BigEndian.Uint16(message[next+8 : next+10]))
		data := next + 10
		if data+dataLength > len(message) {
			return "", nil, false
		}
		if recordClass == 1 && recordType == 1 && dataLength == 4 {
			addresses = append(addresses, netip.AddrFrom4([4]byte(message[data:data+4])))
		} else if recordClass == 1 && recordType == 28 && dataLength == 16 {
			addresses = append(addresses, netip.AddrFrom16([16]byte(message[data:data+16])).Unmap())
		}
		offset = data + dataLength
	}
	return name, addresses, len(addresses) > 0
}

// readDNSName decodes a possibly compressed name starting at offset and
// returns it lowercased without the trailing dot, plus the offset just past
// the name in the original position.
func readDNSName(message []byte, offset int) (string, int, bool) {
	var name strings.Builder
	next, jumps := -1, 0
	for {
		if offset >= len(message) {
			return "", 0, false
		}
		length := int(message[offset])
		switch {
		case length == 0:
			if next < 0 {
				next = offset + 1
			}
			return name.String(), next, name.Len() > 0
		case length&0xc0 == 0xc0:
			if offset+1 >= len(message) || jumps >= 8 {
				return "", 0, false
			}
			if next < 0 {
				next = offset + 2
			}
			jumps++
			offset = int(binary.BigEndian.Uint16(message[offset:offset+2]) & 0x3fff)
		case length > 63:
			return "", 0, false
		default:
			if offset+1+length > len(message) || name.Len()+length+1 > 254 {
				return "", 0, false
			}
			if name.Len() > 0 {
				name.WriteByte('.')
			}
			for _, character := range message[offset+1 : offset+1+length] {
				if character >= 'A' && character <= 'Z' {
					character += 'a' - 'A'
				}
				if character != '-' && character != '_' && (character < 'a' || character > 'z') && (character < '0' || character > '9') {
					return "", 0, false
				}
				name.WriteByte(character)
			}
			offset += 1 + length
		}
	}
}
