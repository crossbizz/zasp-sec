package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"

	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore"
)

const (
	artifactResourcePrefix = "zasp-m1-12-"
	maximumArtifactBytes   = 64 * 1024 * 1024
)

type s3ArtifactDriver struct {
	client      s3API
	bucket      string
	key         *KMSKey
	marker      string
	maximum     int64
	onCandidate func(PutObjectRequest)
}

func newS3ArtifactDriver(client s3API, bucket string, key *KMSKey, marker string, maximum int64, onCandidate func(PutObjectRequest)) (*s3ArtifactDriver, error) {
	if client == nil || key == nil || !validKeyIdentity(*key) || !markerPattern.MatchString(marker) ||
		bucket != artifactBucketName(marker) || maximum <= 0 || maximum > maximumArtifactBytes || onCandidate == nil {
		return nil, errConfiguration
	}
	return &s3ArtifactDriver{client: client, bucket: bucket, key: key, marker: marker, maximum: maximum, onCandidate: onCandidate}, nil
}

func (driver *s3ArtifactDriver) Put(ctx context.Context, object artifactstore.DriverObject) (artifactstore.DriverObject, error) {
	if driver == nil || ctx == nil || !driver.validObject(object) {
		return artifactstore.DriverObject{}, errContent
	}
	request := driver.request(object)
	driver.onCandidate(clonePutObjectRequest(request))
	_, putErr := driver.client.PutObject(ctx, request)
	if putErr != nil && !errors.Is(putErr, errMutationAmbiguous) {
		return artifactstore.DriverObject{}, errProvider
	}
	returned, fetchErr := driver.fetch(ctx, object.DriverLocator)
	if fetchErr != nil {
		return artifactstore.DriverObject{}, errProvider
	}
	return returned, nil
}

func (driver *s3ArtifactDriver) Get(ctx context.Context, locator artifactstore.DriverLocator) (artifactstore.DriverObject, error) {
	if driver == nil || ctx == nil || !driver.validLocator(locator) {
		return artifactstore.DriverObject{}, errContent
	}
	return driver.fetch(ctx, locator)
}

func (driver *s3ArtifactDriver) Delete(ctx context.Context, locator artifactstore.DriverLocator) error {
	if driver == nil || ctx == nil || !driver.validLocator(locator) {
		return errContent
	}
	if _, err := driver.fetch(ctx, locator); err != nil {
		return errProvider
	}
	deleteErr := driver.client.DeleteObject(ctx, driver.bucket, locator.Key)
	if deleteErr != nil && !errors.Is(deleteErr, errMutationAmbiguous) {
		return errProvider
	}
	objects, err := driver.client.ListObjects(ctx, driver.bucket, locator.Key)
	if err != nil || len(objects) != 0 {
		return errProvider
	}
	return nil
}

func (driver *s3ArtifactDriver) fetch(ctx context.Context, locator artifactstore.DriverLocator) (artifactstore.DriverObject, error) {
	value, err := driver.client.GetObject(ctx, driver.bucket, locator.Key)
	if err != nil {
		return artifactstore.DriverObject{}, errProvider
	}
	tags, err := driver.client.GetObjectTags(ctx, driver.bucket, locator.Key)
	if err != nil {
		return artifactstore.DriverObject{}, errProvider
	}
	if value.Key != locator.Key || strings.TrimSpace(strings.Trim(value.ETag, `"`)) == "" ||
		value.Algorithm != sseAlgorithmKMS || !sameKeyIdentity(value.KMSKeyID, driver.key) ||
		value.Size != int64(len(value.Body)) || value.Size <= 0 || value.Size > driver.maximum ||
		!equalStringMaps(tags, artifactProofTags(driver.marker)) {
		return artifactstore.DriverObject{}, errContent
	}
	digest := sha256.Sum256(value.Body)
	mediaType := value.Metadata["media_type"]
	if !equalStringMaps(value.Metadata, artifactMetadata(
		artifactstore.Locator{Scope: locator.Scope, Reference: locator.Reference}, mediaType, digest,
	)) {
		return artifactstore.DriverObject{}, errContent
	}
	objects, err := driver.client.ListObjects(ctx, driver.bucket, locator.Key)
	if err != nil || len(objects) != 1 || objects[0].Key != locator.Key || objects[0].Size != value.Size ||
		strings.TrimSpace(strings.Trim(objects[0].ETag, `"`)) != strings.TrimSpace(strings.Trim(value.ETag, `"`)) {
		return artifactstore.DriverObject{}, errContent
	}
	return artifactstore.DriverObject{
		DriverLocator: locator, MediaType: mediaType, Body: bytes.Clone(value.Body),
		Size: value.Size, SHA256: digest,
	}, nil
}

func (driver *s3ArtifactDriver) request(object artifactstore.DriverObject) PutObjectRequest {
	locator := artifactstore.Locator{Scope: object.Scope, Reference: object.Reference}
	return PutObjectRequest{
		Bucket: driver.bucket, Key: object.Key, KMSKeyID: driver.key.ARN, Body: bytes.Clone(object.Body),
		Metadata: artifactMetadata(locator, object.MediaType, object.SHA256), Tags: artifactProofTags(driver.marker),
	}
}

func (driver *s3ArtifactDriver) validObject(object artifactstore.DriverObject) bool {
	return driver.validLocator(object.DriverLocator) && object.Size == int64(len(object.Body)) && object.Size > 0 &&
		object.Size <= driver.maximum && object.SHA256 == sha256.Sum256(object.Body) && validArtifactMediaType(object.MediaType)
}

func (driver *s3ArtifactDriver) validLocator(locator artifactstore.DriverLocator) bool {
	productLocator := artifactstore.Locator{Scope: locator.Scope, Reference: locator.Reference}
	return productLocator.Scope.Validate() == nil && productLocator.Reference.Validate() == nil &&
		locator.Key == artifactCanonicalKey(productLocator)
}

func artifactMetadata(locator artifactstore.Locator, mediaType string, digest [sha256.Size]byte) map[string]string {
	return map[string]string{
		"organization_id": locator.OrganizationID().String(),
		"workspace_id":    locator.WorkspaceID().String(),
		"environment_id":  locator.EnvironmentID().String(),
		"artifact_id":     locator.Reference.String(),
		"media_type":      mediaType,
		"sha256":          artifactChecksum(digest),
	}
}

func artifactChecksum(digest [sha256.Size]byte) string { return hex.EncodeToString(digest[:]) }

func artifactCanonicalKey(locator artifactstore.Locator) string {
	return "organizations/" + locator.OrganizationID().String() +
		"/workspaces/" + locator.WorkspaceID().String() +
		"/environments/" + locator.EnvironmentID().String() +
		"/artifacts/" + locator.Reference.String()
}

func validArtifactMediaType(value string) bool {
	switch value {
	case "application/json", "application/octet-stream", "application/gzip", "text/plain":
		return true
	default:
		return false
	}
}

func artifactProofTags(marker string) map[string]string {
	return map[string]string{"zasp-proof": "m1-12", "zasp-marker": marker, "zasp-role": "artifact-object"}
}

func artifactLifecycleTags(marker, role string) map[string]string {
	return map[string]string{"zasp-proof": "m1-12", "zasp-marker": marker, "zasp-role": role}
}

func artifactBucketName(marker string) string { return artifactResourcePrefix + marker + "-artifacts" }

func clonePutObjectRequest(request PutObjectRequest) PutObjectRequest {
	request.Body = bytes.Clone(request.Body)
	request.Metadata = cloneStringMap(request.Metadata)
	request.Tags = cloneStringMap(request.Tags)
	return request
}
