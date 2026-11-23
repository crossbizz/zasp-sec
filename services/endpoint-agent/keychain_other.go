//go:build !darwin || !cgo

package main

import "crypto/ed25519"

func keychainSecret(string, string) ([]byte, error) { return nil, errUnavailable }

func initializeDeviceKey(string) (ed25519.PublicKey, error) { return nil, errUnavailable }
