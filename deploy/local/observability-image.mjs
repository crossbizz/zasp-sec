import { COLLECTOR_IMAGE } from "./observability-manifest.mjs";

const collectorImagePlan = deepFreeze({
  indexDigest: "sha256:c5918f78992ee73b0d6f0e599423ac5ec52dd5d9726733114d6eca53d5a32ed5",
  name: "collector",
  platforms: {
    "linux/amd64": {
      configDigest: "sha256:837606a793453fd0c2eef9a6d4ee47ecc970d228ede7bc0c15d32ea9324c9e80",
      manifestDigest: "sha256:e290476fa9a75f7a84a28798832bde7068d27825745de67bc38957e22949a64c",
    },
    "linux/arm64": {
      configDigest: "sha256:e4ed3985c0db662ed2f0be81ac3b10110aefd379b0be24c780e2803571997c93",
      manifestDigest: "sha256:51e1afc9d762a359387723170be5cecccad2c09e73a5a2061361c62c60855ccf",
    },
  },
  reference: COLLECTOR_IMAGE,
  repository: "otel/opentelemetry-collector-contrib",
});

export function buildCollectorImagePlan(platform) {
  if (arguments.length !== 1) throw new TypeError("Collector image plan is invalid");
  const selected = collectorImagePlan.platforms[platform];
  if (selected === undefined || (platform !== "linux/amd64" && platform !== "linux/arm64")) {
    throw new TypeError("Collector image plan is invalid");
  }
  const architecture = platform.slice("linux/".length);
  const tag = collectorImagePlan.reference.split("@")[0];
  return deepFreeze({
    architecture,
    configDigest: selected.configDigest,
    indexDigest: collectorImagePlan.indexDigest,
    manifestDigest: selected.manifestDigest,
    name: "collector",
    platform,
    providerReference: `docker.io/${collectorImagePlan.repository}:0.158.0@${collectorImagePlan.indexDigest}`,
    reference: collectorImagePlan.reference,
    repoDigest: `${collectorImagePlan.repository}@${collectorImagePlan.indexDigest}`,
    repository: collectorImagePlan.repository,
    selectedReference: `${collectorImagePlan.repository}@${selected.manifestDigest}`,
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
