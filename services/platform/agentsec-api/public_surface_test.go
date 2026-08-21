package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMountPublicSurfaceRoutesOnlyTheExactStytchWebhookPath(t *testing.T) {
	productCalls, webhookCalls := 0, 0
	product := http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		productCalls++
		writer.WriteHeader(http.StatusNoContent)
	})
	webhook := http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		webhookCalls++
		writer.WriteHeader(http.StatusAccepted)
	})
	handler, err := mountPublicSurface(product, webhook)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		path                  string
		status                int
		wantProduct, wantHook int
	}{
		{path: "/api/v1/webhooks/stytch", status: http.StatusAccepted, wantHook: 1},
		{path: "/api/v1/webhooks/stytch/", status: http.StatusNoContent, wantProduct: 1, wantHook: 1},
		{path: "/api/v1/admin/group-mappings", status: http.StatusNoContent, wantProduct: 2, wantHook: 1},
	} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, test.path, nil))
		if response.Code != test.status || productCalls != test.wantProduct || webhookCalls != test.wantHook {
			t.Fatalf("path=%q response=%d product=%d webhook=%d", test.path, response.Code, productCalls, webhookCalls)
		}
	}
	if handler, err := mountPublicSurface(nil, webhook); err == nil || handler != nil {
		t.Fatalf("nil product handler=%v err=%v", handler, err)
	}
	if handler, err := mountPublicSurface(product, nil); err == nil || handler != nil {
		t.Fatalf("nil webhook handler=%v err=%v", handler, err)
	}
}
