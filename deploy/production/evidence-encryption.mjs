export function validEvidenceReleaseKeys(section, required) {
  if (!section || typeof section !== "object" || Array.isArray(section)) return false;
  const keys = Object.keys(section).filter(key => key !== "evidenceEncryption").sort();
  return validEvidenceKey(section) && keys.join("\0") === [...required].sort().join("\0") &&
    (!Object.hasOwn(section, "evidenceEncryption") || ["aws-kms", "provider-managed"].includes(section.evidenceEncryption));
}

function validEvidenceKey(section) {
  if (section.evidenceEncryption === "provider-managed" && section.evidenceKMSKeyArn === "") return true;
  const key = /^arn:aws:kms:([a-z]{2}(?:-gov)?-[a-z]+-[0-9]):([0-9]{12}):key\/[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.exec(section.evidenceKMSKeyArn);
  return key !== null && key[1] === section.awsRegion && key[2] === section.evidenceBucketOwner;
}
