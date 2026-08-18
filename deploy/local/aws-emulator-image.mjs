import { LOCALSTACK_IMAGE } from "./aws-emulator-manifest.mjs";

export const LOCALSTACK_IMAGE_PLAN = deepFreeze({
  indexDigest: "sha256:12253acd9676770e9bd31cbfcf17c5ca6fd7fb5c0c62f3c46dd701f20304260c",
  name: "localstack",
  platforms: {
    "linux/amd64": {
      configDigest: "sha256:9a201a5321f1519005b3a745e393c6c08d3d73d0163c4a78615eb4e0ac46c1f5",
      manifestDigest: "sha256:67739ef77133396bc952cee9140fe40ce8301a3d8036078a7709ea000e791a25",
    },
    "linux/arm64": {
      configDigest: "sha256:ad4f76a02108f52479a33bbe0de40690d63ef51713971731f21f1de1e4eedb85",
      manifestDigest: "sha256:af47acfe2ed73a4984f73709b9f655ca255add4aa847dcbf3010301478890bb6",
    },
  },
  reference: LOCALSTACK_IMAGE,
  repository: "localstack/localstack",
});

export function buildLocalStackImagePlan(platform) {
  if (arguments.length !== 1 || (platform !== "linux/amd64" && platform !== "linux/arm64")) {
    throw new TypeError("LocalStack image plan is invalid");
  }
  const selected = LOCALSTACK_IMAGE_PLAN.platforms[platform];
  const architecture = platform.slice("linux/".length);
  const tag = LOCALSTACK_IMAGE_PLAN.reference.split("@")[0];
  return deepFreeze({
    architecture,
    configDigest: selected.configDigest,
    indexDigest: LOCALSTACK_IMAGE_PLAN.indexDigest,
    manifestDigest: selected.manifestDigest,
    name: LOCALSTACK_IMAGE_PLAN.name,
    platform,
    providerReference: `docker.io/${LOCALSTACK_IMAGE_PLAN.repository}:4.7.0@${LOCALSTACK_IMAGE_PLAN.indexDigest}`,
    reference: LOCALSTACK_IMAGE_PLAN.reference,
    repoDigest: `${LOCALSTACK_IMAGE_PLAN.repository}@${LOCALSTACK_IMAGE_PLAN.indexDigest}`,
    repository: LOCALSTACK_IMAGE_PLAN.repository,
    selectedReference: `${LOCALSTACK_IMAGE_PLAN.repository}@${selected.manifestDigest}`,
    tag,
  });
}

function deepFreeze(value) {
  if (value !== null && typeof value === "object" && !Object.isFrozen(value)) {
    for (const item of Object.values(value)) deepFreeze(item);
    Object.freeze(value);
  }
  return value;
}
