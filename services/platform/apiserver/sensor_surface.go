package apiserver

import "net/http"

// NewSensorWorkflowSurface composes v15 sensor management into the workflow
// route family while leaving earlier schema versions on the existing surface.
func NewSensorWorkflowSurface(workflow, sensors http.Handler) (http.Handler, error) {
	if nilInterface(workflow) || nilInterface(sensors) {
		return nil, ErrRepositoryConfiguration
	}
	return &sensorWorkflowSurface{workflow: workflow, sensors: sensors}, nil
}

type sensorWorkflowSurface struct {
	workflow http.Handler
	sensors  http.Handler
}

func (surface *sensorWorkflowSurface) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	routed, ok := RoutedOperationFromRequest(request)
	if !ok {
		writeProductionError(writer, request, ErrRepositoryAuthentication)
		return
	}
	switch routed.OperationID {
	case "listSensors", "createSensorEnrollment", "getSensor", "updateSensor", "deleteSensor", "rotateSensorToken", "getSensorCoverage":
		surface.sensors.ServeHTTP(writer, request)
	default:
		surface.workflow.ServeHTTP(writer, request)
	}
}
