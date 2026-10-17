package apiserver

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"github.com/zasp-ai/zasp-sec/services/platform/nodecoveragewire"
)

const postgresSensorNodeCoverageSQL = `SELECT zasp_sensor_coverage_v1.sensor_coverage($1,$2,$3,$4)`
const sensorNodeCoverageReadSchema = nodecoveragewire.ObservationReadSchema

type SensorNodeCoverage struct {
	SensorCoverage
	NodeObservation nodecoveragewire.ObservationRead `json:"node_observation"`
}
type sensorNodeCoverageAuthority interface {
	GetSensorNodeCoverage(context.Context, domain.Scope, string) (SensorNodeCoverage, error)
}

func (r *PostgresRepository) RequireSensorNodeCoverageProfile(pin string) error {
	if r == nil || !r.currentAuthorization || !migrations.IsSensorNodeCoverageProfileChecksum(pin) {
		return ErrRepositoryConfiguration
	}
	r.sensorNodeCoverageProfileChecksum = pin
	return nil
}
func (r *SensorPublicRepository) RequireSensorNodeCoverageProfile(pin string) error {
	if r == nil || nilInterface(r.database) || !migrations.IsSensorNodeCoverageProfileChecksum(pin) {
		return ErrRepositoryConfiguration
	}
	r.nodeCoverageProfileChecksum = pin
	return nil
}
func (r *SensorPublicRepository) GetSensorNodeCoverage(ctx context.Context, scope domain.Scope, id string) (SensorNodeCoverage, error) {
	if !validSensorRepository(r, ctx) || scope.Validate() != nil || !validProductID(id) {
		return SensorNodeCoverage{}, ErrRepositoryOperation
	}
	g, ok := requestAuthorizationFromContext(ctx)
	if !ok || !migrations.IsSensorNodeCoverageProfileChecksum(r.nodeCoverageProfileChecksum) || !sensorNodeCoverageStatementAllowed(g, postgresSensorNodeCoverageSQL, []any{scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), id}) {
		return SensorNodeCoverage{}, ErrRepositoryUnavailable
	}
	raw, err := r.database.QueryJSON(ctx, postgresSensorNodeCoverageSQL, scope.OrganizationID().String(), scope.WorkspaceID().String(), scope.EnvironmentID().String(), id)
	if err != nil {
		return SensorNodeCoverage{}, discoveryProviderError(err)
	}
	v, ok := decodeSensorNodeCoverage(raw, id)
	if !ok {
		return SensorNodeCoverage{}, ErrRepositoryUnavailable
	}
	return v, nil
}
func sensorNodeCoverageStatementAllowed(g RequestAuthorization, q string, args []any) bool {
	if q != postgresSensorNodeCoverageSQL || len(args) != 4 || g.OperationID != "getSensorCoverage" || g.Collection || !validProductID(g.PathParameters["id"]) || (g.Identity.CredentialKind != CredentialBrowserSession && g.Identity.CredentialKind != CredentialBearerToken) || !authorizationNativeTargetAllowed(g, "sensor", g.PathParameters["id"]) {
		return false
	}
	for i, want := range []string{g.Identity.Scope.OrganizationID().String(), g.Identity.Scope.WorkspaceID().String(), g.Identity.Scope.EnvironmentID().String(), g.PathParameters["id"]} {
		s, ok := args[i].(string)
		if !ok || s != want {
			return false
		}
	}
	return true
}
func (d *PostgresJSONDatabase) SensorNodeCoverageProfileReady(ctx context.Context, pin string) (bool, error) {
	if d == nil || ctx == nil || ctx.Err() != nil || !migrations.IsSensorNodeCoverageProfileChecksum(pin) {
		return false, ErrRepositoryConfiguration
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.closed || !d.currentAuthorization || nilInterface(d.driver) {
		return false, ErrRepositoryUnavailable
	}
	var ready bool
	if err := d.driver.QueryRow(ctx, `SELECT zasp_sensor_coverage_v1.caller_ready('human-read',$1)`, pin).Scan(&ready); err != nil {
		return false, classifyPostgresError(err)
	}
	return ready, nil
}
func sensorNodeCoverageHeader(r *http.Request) (bool, bool) {
	found := false
	for name, values := range r.Header {
		if strings.EqualFold(name, "X-Zasp-Schema-Version") {
			if found || len(values) != 1 || values[0] != nodecoveragewire.ReadSchema {
				return false, false
			}
			found = true
		}
	}
	return found, true
}

// Parse each nested authority object before ordinary typed decoding. The raw
// request digest cannot be recomputed from reserialized JSONB observation data.
func decodeSensorNodeCoverage(raw json.RawMessage, id string) (SensorNodeCoverage, bool) {
	var zero SensorNodeCoverage
	if len(raw) > nodecoveragewire.MaxEnvelopeBytes+65536 {
		return zero, false
	}
	top, ok := nodeCoverageObject(raw, "sensor_id", "supported", "status", "last_heartbeat", "kernel", "btf", "capabilities", "event_rate", "drops", "node_observation")
	if !ok {
		return zero, false
	}
	for k, v := range top {
		if k != "last_heartbeat" && bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
			return zero, false
		}
	}
	obs, ok := nodeCoverageObject(top["node_observation"], "schema", "state", "receipt")
	if !ok {
		return zero, false
	}
	var v SensorNodeCoverage
	if decodeStrictDiscovery(raw, &v) != nil || !validSensorCoverage(v.SensorCoverage, id) || v.NodeObservation.Schema != sensorNodeCoverageReadSchema || !stringIn(v.NodeObservation.State, "unavailable", "source_current", "source_expired", "source_superseded", "enrollment_revoked") {
		return zero, false
	}
	if v.NodeObservation.State == "unavailable" {
		return v, bytes.Equal(bytes.TrimSpace(obs["receipt"]), []byte("null"))
	}
	fields, ok := nodeCoverageObject(obs["receipt"], "sequence", "request_digest", "received_at", "source_observed_at", "expires_at", "observation")
	if !ok || v.NodeObservation.Receipt == nil {
		return zero, false
	}
	envelope, err := nodecoveragewire.ParseEnvelope(fields["observation"])
	if err != nil {
		return zero, false
	}
	receipt := v.NodeObservation.Receipt
	if receipt.Sequence != envelope.Sequence || !receipt.SourceObservedAt.Equal(envelope.SourceObservedAt) || !receipt.ExpiresAt.Equal(envelope.SourceObservedAt.Add(time.Duration(envelope.TTLSeconds)*time.Second)) {
		return zero, false
	}
	_, err = nodecoveragewire.MarshalReceipt(nodecoveragewire.Receipt{SensorID: id, Sequence: receipt.Sequence, RequestDigest: receipt.RequestDigest, Disposition: "accepted", ResolvedAt: receipt.ReceivedAt, SourceObservedAt: receipt.SourceObservedAt, ExpiresAt: receipt.ExpiresAt})
	if err != nil {
		return zero, false
	}
	receipt.Observation = envelope
	return v, true
}
func nodeCoverageObject(raw json.RawMessage, names ...string) (map[string]json.RawMessage, bool) {
	d := json.NewDecoder(bytes.NewReader(raw))
	t, e := d.Token()
	if e != nil || t != json.Delim('{') {
		return nil, false
	}
	allowed := map[string]bool{}
	for _, name := range names {
		allowed[name] = true
	}
	fields := map[string]json.RawMessage{}
	for d.More() {
		t, e = d.Token()
		k, ok := t.(string)
		if e != nil || !ok || !allowed[k] || fields[k] != nil {
			return nil, false
		}
		var v json.RawMessage
		if d.Decode(&v) != nil {
			return nil, false
		}
		fields[k] = v
	}
	t, e = d.Token()
	if e != nil || t != json.Delim('}') || len(fields) != len(names) {
		return nil, false
	}
	if d.Decode(&struct{}{}) != io.EOF {
		return nil, false
	}
	return fields, true
}
