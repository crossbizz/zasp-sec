//go:build !linux

package main

import (
	"context"
	"errors"
)

var errEgressCapture = errors.New("sensor egress capture unavailable")

type dnsCapture struct{}

func openDNSCapture() (*dnsCapture, error)                         { return nil, errEgressCapture }
func (*dnsCapture) run(context.Context, func(dnsResolution)) error { return errEgressCapture }
func (*dnsCapture) Close() error                                   { return nil }
