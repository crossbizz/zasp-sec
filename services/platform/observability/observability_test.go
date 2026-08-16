package observability

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
)

func TestResourceAttributesBuildExactOrderedCopy(t *testing.T) {
	scope := observabilityTestScope(t)
	resource, err := NewResourceAttributes(scope, ServiceAPI, "1.2.3", DeploymentTest)
	if err != nil {
		t.Fatalf("NewResourceAttributes returned error: %v", err)
	}

	want := []StringAttribute{
		{Key: "service.namespace", Value: "agentsec"},
		{Key: "service.name", Value: "agentsec-api"},
		{Key: "service.version", Value: "1.2.3"},
		{Key: "deployment.environment.name", Value: "test"},
		{Key: "organization.id", Value: scope.OrganizationID().String()},
		{Key: "workspace.id", Value: scope.WorkspaceID().String()},
		{Key: "environment.id", Value: scope.EnvironmentID().String()},
	}
	if got := resource.OTLP(); !reflect.DeepEqual(got, want) {
		t.Fatalf("OTLP = %#v, want %#v", got, want)
	}
	if err := ValidateResourceAttributes(resource.OTLP()); err != nil {
		t.Fatalf("ValidateResourceAttributes returned error: %v", err)
	}

	mutated := resource.OTLP()
	mutated[0] = StringAttribute{Key: "prompt.text", Value: "seeded-customer-content"}
	if got := resource.OTLP(); !reflect.DeepEqual(got, want) {
		t.Fatalf("retained OTLP changed to %#v, want %#v", got, want)
	}
}

func TestCorrelationContextRoundTrip(t *testing.T) {
	correlationID := observabilityTestCorrelationID(t, 4)
	correlation, err := NewCorrelation(
		correlationID,
		"0123456789abcdef0123456789abcdef",
		"0123456789abcdef",
	)
	if err != nil {
		t.Fatalf("NewCorrelation returned error: %v", err)
	}
	if err := correlation.Validate(); err != nil {
		t.Fatalf("Validate returned error: %v", err)
	}
	if correlation.CorrelationID() != correlationID ||
		correlation.TraceID() != "0123456789abcdef0123456789abcdef" ||
		correlation.SpanID() != "0123456789abcdef" {
		t.Fatalf("correlation accessors drifted: %#v", correlation)
	}

	ctx, err := WithCorrelation(context.Background(), correlation)
	if err != nil {
		t.Fatalf("WithCorrelation returned error: %v", err)
	}
	got, ok := CorrelationFromContext(ctx)
	if !ok || got != correlation {
		t.Fatalf("CorrelationFromContext = %#v, %t; want %#v, true", got, ok, correlation)
	}
}

func TestResourceAttributesAcceptOnlyBoundedCatalogValues(t *testing.T) {
	scope := observabilityTestScope(t)
	services := []Service{ServiceAPI, ServiceWorker}
	deployments := []Deployment{
		DeploymentDevelopment,
		DeploymentTest,
		DeploymentStaging,
		DeploymentProduction,
	}
	versions := []string{
		"1",
		"v1.2.3",
		"2026.08.16-rc1",
		"A1+B2_C3-D4",
		strings.Repeat("a", 63),
	}

	for _, service := range services {
		for _, deployment := range deployments {
			for _, version := range versions {
				name := fmt.Sprintf("%s/%s/%s", service, deployment, version[:min(len(version), 12)])
				t.Run(name, func(t *testing.T) {
					resource, err := NewResourceAttributes(scope, service, version, deployment)
					if err != nil {
						t.Fatalf("NewResourceAttributes returned error: %v", err)
					}
					if err := ValidateResourceAttributes(resource.OTLP()); err != nil {
						t.Fatalf("ValidateResourceAttributes returned error: %v", err)
					}
				})
			}
		}
	}
}

func TestResourceAttributesRejectInvalidConstruction(t *testing.T) {
	validScope := observabilityTestScope(t)
	tests := map[string]struct {
		scope      domain.Scope
		service    Service
		version    string
		deployment Deployment
	}{
		"zero scope":               {service: ServiceAPI, version: "1", deployment: DeploymentTest},
		"zero service":             {scope: validScope, version: "1", deployment: DeploymentTest},
		"unknown service":          {scope: validScope, service: Service("agentsec-api-other"), version: "1", deployment: DeploymentTest},
		"zero deployment":          {scope: validScope, service: ServiceAPI, version: "1"},
		"unknown deployment":       {scope: validScope, service: ServiceAPI, version: "1", deployment: Deployment("customer-production")},
		"empty version":            {scope: validScope, service: ServiceAPI, deployment: DeploymentTest},
		"leading separator":        {scope: validScope, service: ServiceAPI, version: ".1", deployment: DeploymentTest},
		"trailing separator":       {scope: validScope, service: ServiceAPI, version: "1-", deployment: DeploymentTest},
		"adjacent separators":      {scope: validScope, service: ServiceAPI, version: "1.+2", deployment: DeploymentTest},
		"space":                    {scope: validScope, service: ServiceAPI, version: "1 2", deployment: DeploymentTest},
		"slash":                    {scope: validScope, service: ServiceAPI, version: "1/2", deployment: DeploymentTest},
		"control":                  {scope: validScope, service: ServiceAPI, version: "1\n2", deployment: DeploymentTest},
		"unicode":                  {scope: validScope, service: ServiceAPI, version: "vérsion", deployment: DeploymentTest},
		"over maximum byte length": {scope: validScope, service: ServiceAPI, version: strings.Repeat("a", 64), deployment: DeploymentTest},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			resource, err := NewResourceAttributes(test.scope, test.service, test.version, test.deployment)
			if err != ErrResource || resource != (ResourceAttributes{}) {
				t.Fatalf("NewResourceAttributes = %#v, %v; want zero, ErrResource", resource, err)
			}
		})
	}
	if got := (ResourceAttributes{}).OTLP(); got != nil {
		t.Fatalf("zero resource OTLP = %#v, want nil", got)
	}
}

func TestValidateResourceAttributesRejectsRawCustomerContentAndShapeDrift(t *testing.T) {
	validResource, err := NewResourceAttributes(observabilityTestScope(t), ServiceWorker, "1.2.3", DeploymentStaging)
	if err != nil {
		t.Fatal(err)
	}
	valid := validResource.OTLP()
	prohibited := []string{
		"prompt.text",
		"response.text",
		"tool.arguments",
		"secret.value",
		"raw_evidence",
		"stack_trace",
		"url",
		"customer.content",
		"correlation.id",
	}
	tests := map[string][]StringAttribute{
		"nil":                  nil,
		"missing":              append([]StringAttribute(nil), valid[:6]...),
		"extra":                append(append([]StringAttribute(nil), valid...), StringAttribute{Key: "extra", Value: "value"}),
		"reordered":            mutateAttributes(valid, func(value []StringAttribute) { value[0], value[1] = value[1], value[0] }),
		"duplicate key":        mutateAttributes(valid, func(value []StringAttribute) { value[1] = value[0] }),
		"namespace drift":      mutateAttributes(valid, func(value []StringAttribute) { value[0].Value = "customer-space" }),
		"service drift":        mutateAttributes(valid, func(value []StringAttribute) { value[1].Value = "customer-service" }),
		"version drift":        mutateAttributes(valid, func(value []StringAttribute) { value[2].Value = "1..2" }),
		"deployment drift":     mutateAttributes(valid, func(value []StringAttribute) { value[3].Value = "customer-env" }),
		"organization invalid": mutateAttributes(valid, func(value []StringAttribute) { value[4].Value = "org_customer" }),
		"scope duplicate":      mutateAttributes(valid, func(value []StringAttribute) { value[5].Value = value[4].Value }),
		"scope order drift":    mutateAttributes(valid, func(value []StringAttribute) { value[4], value[5] = value[5], value[4] }),
	}
	for _, key := range prohibited {
		tests["prohibited "+key] = mutateAttributes(valid, func(value []StringAttribute) {
			value[6] = StringAttribute{Key: key, Value: "seeded-customer-content"}
		})
	}

	for name, attributes := range tests {
		t.Run(name, func(t *testing.T) {
			before := append([]StringAttribute(nil), attributes...)
			err := ValidateResourceAttributes(attributes)
			if err != ErrResource {
				t.Fatalf("ValidateResourceAttributes error = %v, want ErrResource", err)
			}
			if !reflect.DeepEqual(attributes, before) {
				t.Fatalf("attributes mutated from %#v to %#v", before, attributes)
			}
		})
	}
}

func TestCorrelationRejectsMalformedIdentityAndDirectState(t *testing.T) {
	validID := observabilityTestCorrelationID(t, 4)
	validTrace := "0123456789abcdef0123456789abcdef"
	validSpan := "0123456789abcdef"
	tests := map[string]Correlation{
		"zero":                  {},
		"zero correlation ID":   {traceID: validTrace, spanID: validSpan},
		"empty trace":           {correlationID: validID, spanID: validSpan},
		"short trace":           {correlationID: validID, traceID: validTrace[:31], spanID: validSpan},
		"long trace":            {correlationID: validID, traceID: validTrace + "0", spanID: validSpan},
		"uppercase trace":       {correlationID: validID, traceID: strings.ToUpper(validTrace), spanID: validSpan},
		"non hexadecimal trace": {correlationID: validID, traceID: strings.Repeat("g", 32), spanID: validSpan},
		"zero trace":            {correlationID: validID, traceID: strings.Repeat("0", 32), spanID: validSpan},
		"empty span":            {correlationID: validID, traceID: validTrace},
		"short span":            {correlationID: validID, traceID: validTrace, spanID: validSpan[:15]},
		"long span":             {correlationID: validID, traceID: validTrace, spanID: validSpan + "0"},
		"uppercase span":        {correlationID: validID, traceID: validTrace, spanID: strings.ToUpper(validSpan)},
		"non hexadecimal span":  {correlationID: validID, traceID: validTrace, spanID: strings.Repeat("g", 16)},
		"zero span":             {correlationID: validID, traceID: validTrace, spanID: strings.Repeat("0", 16)},
	}

	for name, candidate := range tests {
		t.Run(name, func(t *testing.T) {
			created, err := NewCorrelation(candidate.correlationID, candidate.traceID, candidate.spanID)
			if err != ErrCorrelation || created != (Correlation{}) {
				t.Fatalf("NewCorrelation = %#v, %v; want zero, ErrCorrelation", created, err)
			}
			if err := candidate.Validate(); err != ErrCorrelation {
				t.Fatalf("Validate error = %v, want ErrCorrelation", err)
			}
			if candidate.CorrelationID() != (domain.CorrelationID{}) || candidate.TraceID() != "" || candidate.SpanID() != "" {
				t.Fatalf("invalid accessors exposed state: %#v", candidate)
			}
		})
	}
}

func TestCorrelationContextRejectsNilInvalidAndReplacement(t *testing.T) {
	valid := mustTestCorrelation(t, 4, "0123456789abcdef0123456789abcdef", "0123456789abcdef")
	other := mustTestCorrelation(t, 5, "fedcba9876543210fedcba9876543210", "fedcba9876543210")

	if ctx, err := WithCorrelation(nil, valid); err != ErrCorrelation || ctx != nil {
		t.Fatalf("nil WithCorrelation = %#v, %v; want nil, ErrCorrelation", ctx, err)
	}
	if ctx, err := WithCorrelation(context.Background(), Correlation{}); err != ErrCorrelation || ctx != nil {
		t.Fatalf("invalid WithCorrelation = %#v, %v; want nil, ErrCorrelation", ctx, err)
	}
	if got, ok := CorrelationFromContext(nil); ok || got != (Correlation{}) {
		t.Fatalf("nil CorrelationFromContext = %#v, %t", got, ok)
	}
	if got, ok := CorrelationFromContext(context.Background()); ok || got != (Correlation{}) {
		t.Fatalf("missing CorrelationFromContext = %#v, %t", got, ok)
	}

	ctx, err := WithCorrelation(context.Background(), valid)
	if err != nil {
		t.Fatal(err)
	}
	same, err := WithCorrelation(ctx, valid)
	if err != nil || same != ctx {
		t.Fatalf("exact reattach = %#v, %v; want same context", same, err)
	}
	preserved, err := WithCorrelation(ctx, other)
	if err != ErrCorrelation || preserved != ctx {
		t.Fatalf("replacement = %#v, %v; want original, ErrCorrelation", preserved, err)
	}
	got, ok := CorrelationFromContext(ctx)
	if !ok || got != valid {
		t.Fatalf("retained correlation = %#v, %t; want %#v", got, ok, valid)
	}

	invalidContext := context.WithValue(context.Background(), correlationContextKey{}, Correlation{correlationID: valid.correlationID, traceID: "invalid", spanID: valid.spanID})
	if got, ok := CorrelationFromContext(invalidContext); ok || got != (Correlation{}) {
		t.Fatalf("invalid stored correlation = %#v, %t", got, ok)
	}
	if preserved, err := WithCorrelation(invalidContext, valid); err != ErrCorrelation || preserved != invalidContext {
		t.Fatalf("invalid stored replacement = %#v, %v; want original, ErrCorrelation", preserved, err)
	}
}

func TestCorrelationContextIsConcurrentAndIsolated(t *testing.T) {
	const count = 64
	correlationID := observabilityTestCorrelationID(t, 4)
	errorsByWorker := make(chan error, count)
	var wait sync.WaitGroup
	for index := 0; index < count; index++ {
		index := index
		wait.Add(1)
		go func() {
			defer wait.Done()
			hex := fmt.Sprintf("%x", index%16)
			traceID := strings.Repeat(hex, 31) + "1"
			spanID := strings.Repeat(hex, 15) + "1"
			correlation, err := NewCorrelation(correlationID, traceID, spanID)
			if err != nil {
				errorsByWorker <- err
				return
			}
			ctx, err := WithCorrelation(context.Background(), correlation)
			if err != nil {
				errorsByWorker <- err
				return
			}
			got, ok := CorrelationFromContext(ctx)
			if !ok || got != correlation {
				errorsByWorker <- fmt.Errorf("worker %d got %#v, %t", index, got, ok)
				return
			}
			errorsByWorker <- nil
		}()
	}
	wait.Wait()
	close(errorsByWorker)
	for err := range errorsByWorker {
		if err != nil {
			t.Fatal(err)
		}
	}
}

func mutateAttributes(source []StringAttribute, mutate func([]StringAttribute)) []StringAttribute {
	result := append([]StringAttribute(nil), source...)
	mutate(result)
	return result
}

func mustTestCorrelation(t *testing.T, suffix int, traceID, spanID string) Correlation {
	t.Helper()
	correlation, err := NewCorrelation(observabilityTestCorrelationID(t, suffix), traceID, spanID)
	if err != nil {
		t.Fatalf("NewCorrelation returned error: %v", err)
	}
	return correlation
}

func observabilityTestScope(t *testing.T) domain.Scope {
	t.Helper()
	scope, err := domain.NewScope(
		observabilityTestID(t, 1),
		observabilityTestID(t, 2),
		observabilityTestID(t, 3),
	)
	if err != nil {
		t.Fatalf("NewScope returned error: %v", err)
	}
	return scope
}

func observabilityTestCorrelationID(t *testing.T, suffix int) domain.CorrelationID {
	t.Helper()
	correlationID, err := domain.NewCorrelationID(observabilityTestID(t, suffix))
	if err != nil {
		t.Fatalf("NewCorrelationID returned error: %v", err)
	}
	return correlationID
}

func observabilityTestID(t *testing.T, suffix int) domain.ProductID {
	t.Helper()
	id, err := domain.ParseProductID("pid_10000000-0000-4000-8000-00000000000" + string(rune('0'+suffix)))
	if err != nil {
		t.Fatalf("ParseProductID returned error: %v", err)
	}
	return id
}
