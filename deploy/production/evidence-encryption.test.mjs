import assert from "node:assert/strict";
import test from "node:test";
import { validEvidenceReleaseKeys } from "./evidence-encryption.mjs";

const fields = ["evidenceBucketOwner", "awsRegion", "evidenceKMSKeyArn"];
const aws = {
  evidenceBucketOwner: "123456789012",
  awsRegion: "us-west-2",
  evidenceKMSKeyArn: "arn:aws:kms:us-west-2:123456789012:key/11111111-1111-4111-8111-111111111111",
};

test("release keeps existing KMS records and permits SSE-S3 with a scoped legacy key", () => {
  for (const profile of [
    aws,
    { ...aws, evidenceEncryption: "aws-kms" },
    { ...aws, evidenceEncryption: "provider-managed" },
    { ...aws, evidenceEncryption: "provider-managed", evidenceKMSKeyArn: "" },
  ]) assert.ok(validEvidenceReleaseKeys(profile, fields));
});

test("release rejects unknown encryption, cross-account or cross-region historical pins and malformed profiles", () => {
  for (const profile of [
    null, [], "provider-managed",
    { ...aws, evidenceKMSKeyArn: "" },
    { ...aws, evidenceEncryption: null },
    { ...aws, evidenceEncryption: "disabled" },
    { ...aws, evidenceEncryption: "provider-managed", extra: true },
    { ...aws, evidenceEncryption: "provider-managed", evidenceBucketOwner: "987654321098" },
    { ...aws, evidenceEncryption: "provider-managed", awsRegion: "eu-west-1" },
    { ...aws, evidenceEncryption: "provider-managed", evidenceKMSKeyArn: "alias/unpinned" },
    { evidenceEncryption: "provider-managed", awsRegion: aws.awsRegion, evidenceKMSKeyArn: "" },
  ]) assert.equal(validEvidenceReleaseKeys(profile, fields), false);
});
