package artifactstore

import (
	"context"
	"errors"
	"testing"
)

func TestGetClassifiesReturnedObjectIntegrity(t *testing.T) {
	request := validPutRequest(t)
	store, err := New(&recordingDriver{get: func(context.Context, DriverLocator) (DriverObject, error) { return DriverObject{}, nil }}, validConfig())
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.Get(context.Background(), request.Locator)
	if !errors.Is(err, ErrGet) || !errors.Is(err, ErrIntegrity) {
		t.Fatalf("invalid successful object category: %v", err)
	}
}
