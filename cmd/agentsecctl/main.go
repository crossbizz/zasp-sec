package main

import (
	"errors"
	"io"
	"os"
)

var (
	buildVersion           = "dev"
	errInvalidArguments    = errors.New("invalid arguments")
	errInvalidBuildVersion = errors.New("invalid build version")
	errOutputUnavailable   = errors.New("output unavailable")
)

func main() {
	if err := run(os.Stdout, os.Args[1:], buildVersion); err != nil {
		os.Exit(1)
	}
}

func run(output io.Writer, arguments []string, version string) error {
	if len(arguments) != 1 || arguments[0] != "version" {
		return errInvalidArguments
	}
	if !validBuildVersion(version) {
		return errInvalidBuildVersion
	}
	if output == nil {
		return errOutputUnavailable
	}
	line := "agentsecctl version " + version + "\n"
	written, err := io.WriteString(output, line)
	if err != nil {
		return err
	}
	if written != len(line) {
		return io.ErrShortWrite
	}
	return nil
}

func validBuildVersion(version string) bool {
	if len(version) == 0 || len(version) > 64 {
		return false
	}
	for index := 0; index < len(version); index++ {
		character := version[index]
		alphanumeric := character >= 'a' && character <= 'z' ||
			character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9'
		if alphanumeric {
			continue
		}
		if index == 0 || character != '.' && character != '_' && character != '+' && character != '-' {
			return false
		}
	}
	return true
}
