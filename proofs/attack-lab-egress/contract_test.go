package main

import (
	"os"
	"strings"
	"testing"
)

func TestProductionContract(t *testing.T) {
	source, err := os.ReadFile("../../deploy/staging/attack-lab-egress-contract.json")
	if err != nil {
		t.Fatal(err)
	}
	rules, err := readContract(source)
	if err != nil || len(rules) != 6 {
		t.Fatalf("contract rejected: %v", err)
	}
	for name, rewrite := range map[string]func(string) string{
		"broad protocol":   func(s string) string { return strings.Replace(s, `"tcp"`, `"-1"`, 1) },
		"wrong proxy port": func(s string) string { return strings.Replace(s, `8443`, `443`, 1) },
		"missing DNS":      func(s string) string { return strings.Replace(s, `"dns_udp"`, `"unknown"`, 1) },
		"extra rule": func(s string) string {
			return strings.Replace(s, `"rules": {`, `"rules": {"internet":{"protocol":"tcp","port":443},`, 1)
		},
		"extra field":     func(s string) string { return strings.Replace(s, `"port": 8443`, `"port":8443,"cidr":"0.0.0.0/0"`, 1) },
		"schema drift":    func(s string) string { return strings.Replace(s, `egress-v1`, `egress-v2`, 1) },
		"trailing object": func(s string) string { return s + `{}` },
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := readContract([]byte(rewrite(string(source)))); err == nil {
				t.Fatal("unsafe contract accepted")
			}
		})
	}
}
