package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"
)

const healthListenAddress = ":8081"

var (
	buildVersion           = "dev"
	errInvalidBuildVersion = errors.New("invalid build version")
	errOutputUnavailable   = errors.New("output unavailable")
	errRuntimeUnavailable  = errors.New("runtime unavailable")
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	operation, err := parseGatewayProcessOperation(os.Args[1:])
	if err != nil {
		os.Exit(1)
	}
	config, err := loadProductionGatewayConfig(os.Getenv)
	if err != nil {
		os.Exit(1)
	}
	dependencies, err := buildProductionGatewayDependencies(ctx, config)
	if err != nil {
		os.Exit(1)
	}
	if operation.Mode == "acknowledge-quarantine" {
		if err := runGatewayQuarantineAcknowledgment(ctx, os.Stdout, dependencies, operation.Acknowledgment); err != nil {
			os.Exit(1)
		}
		return
	}
	if err := serveProductionGateway(ctx, os.Stdout, buildVersion, config, dependencies, net.Listen); err != nil {
		os.Exit(1)
	}
}

type gatewayProcessOperation struct {
	Mode           string
	Acknowledgment gatewayQuarantineAcknowledgment
}

func parseGatewayProcessOperation(arguments []string) (gatewayProcessOperation, error) {
	if len(arguments) == 0 {
		return gatewayProcessOperation{Mode: "serve"}, nil
	}
	if len(arguments) != 5 || arguments[0] != "acknowledge-quarantine" || !validGatewayProductID(arguments[1]) || !validGatewayProductID(arguments[4]) {
		return gatewayProcessOperation{}, errRuntimeUnavailable
	}
	digest, err := hex.DecodeString(arguments[2])
	floor, floorErr := strconv.ParseUint(arguments[3], 10, 64)
	if err != nil || len(digest) != 32 || hex.EncodeToString(digest) != arguments[2] || floorErr != nil || strconv.FormatUint(floor, 10) != arguments[3] {
		return gatewayProcessOperation{}, errRuntimeUnavailable
	}
	var requestDigest [32]byte
	copy(requestDigest[:], digest)
	acknowledgment := gatewayQuarantineAcknowledgment{EventID: arguments[1], RequestDigest: requestDigest, ConfirmedFloor: floor, IncidentID: arguments[4]}
	if !validGatewayQuarantineAcknowledgment(acknowledgment) {
		return gatewayProcessOperation{}, errRuntimeUnavailable
	}
	return gatewayProcessOperation{Mode: "acknowledge-quarantine", Acknowledgment: acknowledgment}, nil
}

func runGatewayQuarantineAcknowledgment(ctx context.Context, output io.Writer, dependencies productionGatewayDependencies, acknowledgment gatewayQuarantineAcknowledgment) (resultErr error) {
	if invalidRuntimeValue(ctx) || invalidRuntimeValue(output) || ctx.Err() != nil || dependencies.AcknowledgeQuarantine == nil || dependencies.Close == nil || !validGatewayQuarantineAcknowledgment(acknowledgment) {
		return errRuntimeUnavailable
	}
	defer func() {
		if recover() != nil {
			resultErr = errRuntimeUnavailable
		}
		if err := dependencies.Close(); err != nil && resultErr == nil {
			resultErr = errRuntimeUnavailable
		}
	}()
	if err := dependencies.AcknowledgeQuarantine(ctx, acknowledgment); err != nil {
		return errRuntimeUnavailable
	}
	raw, err := json.Marshal(struct {
		EventID        string `json:"event_id"`
		ConfirmedFloor uint64 `json:"confirmed_floor"`
		IncidentID     string `json:"incident_id"`
		Acknowledged   bool   `json:"acknowledged"`
	}{EventID: acknowledgment.EventID, ConfirmedFloor: acknowledgment.ConfirmedFloor, IncidentID: acknowledgment.IncidentID, Acknowledged: true})
	if err != nil {
		return errRuntimeUnavailable
	}
	raw = append(raw, '\n')
	if written, err := output.Write(raw); err != nil || written != len(raw) {
		return errRuntimeUnavailable
	}
	return nil
}

func serveProcess(ctx context.Context, output io.Writer, version string, listen func(string, string) (net.Listener, error)) (result error) {
	var candidate net.Listener
	defer func() {
		if recover() == nil {
			return
		}
		if !invalidRuntimeValue(candidate) {
			_ = callHealthClose(candidate)
		}
		result = errRuntimeUnavailable
	}()

	if !validBuildVersion(version) {
		return errInvalidBuildVersion
	}
	if invalidRuntimeValue(ctx) || invalidRuntimeValue(output) || listen == nil {
		return errRuntimeUnavailable
	}
	server, err := newHealthServer(healthServerConfig{service: "runtime-gateway", version: version})
	if err != nil {
		return errRuntimeUnavailable
	}
	if ctx.Err() != nil {
		return nil
	}
	listener, err := listen("tcp", healthListenAddress)
	if err != nil {
		if !invalidRuntimeValue(listener) {
			if closeErr := callHealthClose(listener); closeErr != nil {
				return errRuntimeUnavailable
			}
		}
		return err
	}
	if invalidRuntimeValue(listener) {
		return errRuntimeUnavailable
	}
	candidate = listener
	if err := run(output, version); err != nil {
		closeErr := callHealthClose(listener)
		candidate = nil
		if closeErr != nil {
			return errRuntimeUnavailable
		}
		return err
	}
	result = server.Serve(ctx, listener)
	candidate = nil
	return result
}

func run(output io.Writer, version string) error {
	if !validBuildVersion(version) {
		return errInvalidBuildVersion
	}
	if output == nil {
		return errOutputUnavailable
	}
	_, err := io.WriteString(output, "runtime-gateway build "+version+"\n")
	return err
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
