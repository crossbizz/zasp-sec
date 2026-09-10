package apiserver

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"unicode/utf8"
)

// Sensor authority is a bounded flat object. Reject duplicate keys before the
// ordinary typed decoder can silently accept the final occurrence.
func decodeSensorObject(payload []byte) (map[string]json.RawMessage, bool) {
	if len(payload) == 0 || len(payload) > 16*1024 || !utf8.Valid(payload) {
		return nil, false
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	first, err := decoder.Token()
	if err != nil || first != json.Delim('{') {
		return nil, false
	}
	object := map[string]json.RawMessage{}
	for decoder.More() {
		token, err := decoder.Token()
		key, ok := token.(string)
		if err != nil || !ok || object[key] != nil {
			return nil, false
		}
		var raw json.RawMessage
		if decoder.Decode(&raw) != nil {
			return nil, false
		}
		object[key] = raw
	}
	last, err := decoder.Token()
	return object, err == nil && last == json.Delim('}') && decoder.Decode(&struct{}{}) == io.EOF
}

type sensorCreateBody struct{ Name, Kind, Mode, RuntimeSensorID string }

func decodeSensorCreateBody(request *http.Request) (sensorCreateBody, error) {
	if request.Body == nil || request.Header.Get("Content-Type") != "application/json" {
		return sensorCreateBody{}, ErrRepositoryOperation
	}
	body, err := io.ReadAll(io.LimitReader(request.Body, 16*1024+1))
	if err != nil {
		return sensorCreateBody{}, ErrRepositoryOperation
	}
	object, ok := decodeSensorObject(body)
	if !ok || len(object) < 3 || len(object) > 4 {
		return sensorCreateBody{}, ErrRepositoryOperation
	}
	var input sensorCreateBody
	fields := map[string]*string{"name": &input.Name, "kind": &input.Kind, "mode": &input.Mode, "runtime_sensor_id": &input.RuntimeSensorID}
	for key, raw := range object {
		if fields[key] == nil || json.Unmarshal(raw, fields[key]) != nil || *fields[key] == "" {
			return sensorCreateBody{}, ErrRepositoryOperation
		}
	}
	if !validSensorName(input.Name) || !stringIn(input.Kind, "otlp", "tetragon") || !validSensorMode(input.Mode) || input.RuntimeSensorID != "" && (input.Kind != "otlp" || !validProductID(input.RuntimeSensorID)) {
		return sensorCreateBody{}, ErrRepositoryOperation
	}
	return input, nil
}
