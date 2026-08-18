import { pathToFileURL } from "node:url";
import { isDeepStrictEqual } from "node:util";

import { buildLocalStackImagePlan } from "./aws-emulator-image.mjs";
import {
  AWS_EMULATOR_CONSTANTS,
  buildAwsEmulatorCoreResources,
  buildAwsEmulatorResources,
  buildAwsEmulatorS3Resources,
  renderAwsEmulatorCoreManifest,
  renderAwsEmulatorS3Manifest,
} from "./aws-emulator-manifest.mjs";
import { buildGraphResources, renderGraphManifest } from "./graph-manifest.mjs";
import {
  buildObservabilityCoreResources,
  buildObservabilitySpanResources,
  renderObservabilityCoreManifest,
  renderObservabilitySpanManifest,
} from "./observability-manifest.mjs";
import {
  LocalObservabilitySystem,
} from "./observability-run.mjs";
import { DockerKindGraphRuntime } from "./graph-run.mjs";
import { Failure, orchestrate, parseBoundedJson } from "./run.mjs";

const awsMainTimeoutMilliseconds = 1_080_000;
const awsCleanupTimeoutMilliseconds = 360_000;
const awsSettlementTimeoutMilliseconds = 60_000;
const providerByteLimit = 4_194_304;

export const AWS_EMULATOR_SUCCESS_LINE = "Local AWS emulator manifest passed: ready=true internal=true endpoint=true s3=true cleanup=true.";
export const AWS_EMULATOR_FAILURE_CATEGORIES = Object.freeze([
  "build",
  "cleanup",
  "configuration",
  "deadline",
  "normalization",
  "ownership",
  "panic",
  "provider",
  "readiness",
]);

export class AwsEmulatorFailure extends Failure {
  constructor(category = "panic") {
    super("operation");
    this.name = "AwsEmulatorFailure";
    this.category = AWS_EMULATOR_FAILURE_CATEGORIES.includes(category) ? category : "panic";
  }
}

export function buildAwsEmulatorProfile(...input) {
  if (input.length !== 0) throw new TypeError("AWS emulator profile accepts no caller input");
  return deepFreeze({
    manifests: [
      { bytes: renderGraphManifest(buildGraphResources()), name: "graph.yaml", pathKey: "graphManifest" },
      {
        bytes: renderObservabilityCoreManifest(buildObservabilityCoreResources()),
        name: "observability.yaml",
        pathKey: "observabilityCoreManifest",
      },
      {
        bytes: renderObservabilitySpanManifest(buildObservabilitySpanResources()),
        name: "observability-span.yaml",
        pathKey: "observabilitySpanManifest",
      },
      {
        bytes: renderAwsEmulatorCoreManifest(buildAwsEmulatorCoreResources()),
        name: "aws-emulator.yaml",
        pathKey: "awsEmulatorCoreManifest",
      },
      {
        bytes: renderAwsEmulatorS3Manifest(buildAwsEmulatorS3Resources()),
        name: "aws-emulator-s3.yaml",
        pathKey: "awsEmulatorS3Manifest",
      },
    ],
    proof: "m1-30d",
  });
}

export function awsEmulatorApplyPlan(...input) {
  if (input.length !== 0) throw new TypeError("AWS emulator apply plan accepts no caller input");
  return deepFreeze({
    base: ["graphManifest", "observabilityCoreManifest", "awsEmulatorCoreManifest"],
    staged: ["observabilitySpanManifest", "awsEmulatorS3Manifest"],
  });
}

const indexDescriptors = deepFreeze([
  {
    digest: "sha256:67739ef77133396bc952cee9140fe40ce8301a3d8036078a7709ea000e791a25",
    mediaType: "application/vnd.docker.distribution.manifest.v2+json",
    platform: { architecture: "amd64", os: "linux" },
    size: 5342,
  },
  {
    digest: "sha256:af47acfe2ed73a4984f73709b9f655ca255add4aa847dcbf3010301478890bb6",
    mediaType: "application/vnd.docker.distribution.manifest.v2+json",
    platform: { architecture: "arm64", os: "linux" },
    size: 5342,
  },
]);

const manifestFacts = deepFreeze({
  "linux/amd64": buildManifestFact(
    "sha256:9a201a5321f1519005b3a745e393c6c08d3d73d0163c4a78615eb4e0ac46c1f5", 27136,
    "0bdf2c4d1714b5962675435789b4e83edb5aa4d94ec0d7643737940b0e73c4ed:29146692 abd846fa1cdb2ae1ef7731213cd4f0c40b05fdbeeaef9301a4dc9575b2088ece:3514096 b7b61708209ad8f9b9a11c61dc9df90f74c1e39eddc169936146259febc2ec24:16208812 4085babbc5702254267393a22fc7f0d644efddd41dc328f81b1549c13a210b4e:249 886c467dda01b204ca17f990ca3b67f485adb8aa3a1d2122d75dac673d9a4255:76905783 a7f6494d29e7e94189210413dfa9df16d1fe7eb348c9ecfadf44edecca2c7a3f:54434690 863928f55bff1aebbf8ac5b2f00195286f6dbe85cba1a0d1eca15379355d25d0:135 a1662769d7eb1f55507cd5ee6d10941f5424e3afef6d691fabd31734f6d67ffe:153 4f4fb700ef54461cfa02571ae0db9a0dc1e0cdb5577484a6d75e68dc38e8acc1:32 f7d4d7bc677865ed87d02b4d7c50ebb6b0a0027494f99b5f96e2b00bc842f217:3512 df2f830ebaca4610d30b248e28fc0550ace96ceb550e85456d79f6d9c0138dc2:902 24d282c808a40f802aa6cc7a955743e609fe021cb4a9f7a05e6805bfdf7cb406:249 011ac6e946b0519e3afa3942fc5d5f7d669e710cd3b64ce7a97b3f622cac6d00:26734926 3feaef44c375f5d26bd64d71371dbfba3a1272d9006098992c4ed6f2312ed8b8:132284852 7ff5e823c93a0698dd6f4d56e7e1ea43f9e6d0eee5153e17a99902b93a382645:7134 2fd50c495e31e0302f918585ce13f9da8a32314622185fcbb2a30c96188953ea:2758 0e4de24ee2a766765f00913cef04381debf07bcadad0bf34c2f254255ebb5567:3408763 26935249c86ed9783a666a4612ad7f28b38d4c937db8ae8887d1b110d2cb88c3:99363 b31a0be8c4a372748a654350290cbf4f00fd27d5bda69da0584a60fc8ed1c87b:5142843 1773a34a0ead4b6b8392a742b63a308020f9b300ab21ceb51aa5759b7509c1a7:127780 a7c20efc708a6d31170f919e7b8d279aa6910dbdf9b3af19115f8960084141ee:151562303 5560fc75e272356fe3c8179c10cffee4ec4bd9835ca0abe2c90ec391b0f26244:301 2d1b7110e876455d5795bc774bbddfeb69b4f779ed91716d03a5138a68319b72:300 979513209e62b53d441749b618aa6fa5abac1a10d836e5569cb647a82f9f53a0:197",
  ),
  "linux/arm64": buildManifestFact(
    "sha256:ad4f76a02108f52479a33bbe0de40690d63ef51713971731f21f1de1e4eedb85", 27144,
    "c046a38e34226ab0cae005551802ddc0e5c18a02fb42820f76003b3c527362eb:29180468 27b1542b92578c5ae2fdd86937dbb3ff246ba74c2666b93d03369b030c2f6128:3337701 23635a31452efc16982ee0c8dd50d46aa2445221f14cb157dfed8a387cce2ee6:16136798 65bfefa96d6c8b1d434afa24988e3c8cf866f389a0920e43deb11aa26ff139d5:250 71bfe837c38a481964c5dfa5ea2c40aa70dae438b362a903ee3fd451ea3c8e5e:77574345 52f21b0b71be5b707bb588deebee02695b17fd32020d6ad60c72abdc90639ef5:54484795 9ce6374220cb2f546376bc3d6973ee70fdf74629167240a1ec419f4bfc7c4fea:135 af5f2f6fee615513619b2f97371aefd786972cfb6c63ee64f70d4d7e48e791d2:158 4f4fb700ef54461cfa02571ae0db9a0dc1e0cdb5577484a6d75e68dc38e8acc1:32 7799317606dc6f5a8991b53b1d332555cd29a327a12c18d0740069bf37abe2d4:3514 c264381852da2268dfbaa310a781e979f2fb39561f3c2d996fc80f92476af175:902 86d7ae0b49ce9778ca91b8bd1743adff2d835a14c0d078bdea6e2db99df03b42:249 f071571c5fe3c7a1dce8059531a9b06287f077687e0f515b7f3910f863dd676c:26707461 6f70d65ce515f4845232a96545c40d7e436c735fe56d0b7145fb9f3838ae4ae2:131716332 af620d5826f23f3189975ee0c53d1b63a4b7021fb071cbce5f0a6046344cd9b6:7134 0ddaef28eba3ec86511cdc288902be6ea876ca8af0c2de4aead3cf8ec1c270c0:2758 c1343b1e1a2354024464644a0c45869d20ff0d1edd388a05d83e2c2fb1ab61b1:3408776 be8b0eb944715c83d0e054b9446376b006cf5109835d5c10161bb322efc733ee:99359 fa32476481367ea212c3091cd4f8a47e4f544d23cf52bb10e74e5cefef4bb335:5142757 fae1e764c0d2673b998745776345b4a800325e632fe90fc2f5cbee7af420c8a5:127783 ec73a34e5c88a08e65b10cdb25cb929608d6c2cd5e4d312676a2e0d16003f405:149062606 bbcacd23a6b7d065d0fd56e1c3e5acd6c5172ec59c0d78d69c18233ea458f194:300 4685c2a135576c299da17c6e9a22ab0cd4ac2e4279152c483612491744059c2b:299 3272e171b270afc523e08b68161a8708e331aadab0c3daedb3e6f72ffdd93ca2:196",
  ),
});

const imageEnvironment = deepFreeze([
  "PATH=/usr/local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
  "LANG=C.UTF-8",
  "GPG_KEY=" + "A035C8C19219BA821ECEA86B64E628F8D684696D",
  "PYTHON_VERSION=3.11.13",
  "PYTHON_SHA256=8fb5f9fbc7609fa822cb31549884575db7fd9657cbffb89510b5d7975963a83a",
  "USER=localstack",
  "PYTHONUNBUFFERED=1",
  "LOCALSTACK_BUILD_DATE=2025-07-31",
  "LOCALSTACK_BUILD_GIT_HASH=82de91e30",
  "LOCALSTACK_BUILD_VERSION=4.7.0",
]);
const exposedPorts = deepFreeze(Object.fromEntries([
  ...Array.from({ length: 50 }, (_unused, index) => [`${4510 + index}/tcp`, {}]),
  ["4566/tcp", {}],
  ["5678/tcp", {}],
]));
const imageLabels = deepFreeze({
  authors: "LocalStack Contributors",
  description: "LocalStack Docker image",
  maintainer: "LocalStack Team (info@localstack.cloud)",
});
const rootfsFacts = deepFreeze({
  "linux/amd64": splitDigests("7cc7fe68eff66f19872441a51938eecc4ad33746d2baa3abc081c1e6fe25988e 0a00f6ce5fb79b48aa2968e84067a2804f848097e274b172e587a1f8a769187f 943faa7467a0e21a2f91457021f49f601f064076f4a9a9986476bdad86e683d4 d22cc68b10d77da233d72061754d722e59f22e87748b57c0da281b45a5b2a60e e2dc3875264d20d629c726d5d079bce8bbd716f96445da770a0995fa64aa38b2 afa09c301659d6aed87613aefadf27f854d4562db79607d27e2e8e0311f64522 ea6cefaf4864c21e2607c788a26e293bd34b47dc23278417380be821df9f0b0f 8c56619a85c2bd9cf7edb8d8646f09f8ac0059028e27e0bca300eb9e93b76078 5f70bf18a086007016e948b04aed3b82103a36bea41755b6cddfaf10ace3c6ef 0a8cfc82609f5963995033e4ba82028f211a9b16f3038f4de78bca8d49c61a3f 30c271a4e869024539e13b4c7bdb2d871db278c4a0147723d71fb83665034d0d 43bc24875bb0e97b283a0addb65c6bbb64ba02051170ccdcf881f829238fc946 72dac9832986d8201e94c4d75d319b51f3446c2da67c3027b3408f457faba7a6 3c6f3a8e82db2cbb6155a42c5fbc1a0ea3eeaddd54d830ed0f8052a1860e819e 3b205ecdf447785ca2af740b66455d9a2859956b856296e7b98e8d139bdfb7da e51a75e39a4ae50ac030dc581de3971e67cf425ee3c52d8c7edb4564f8c6316f 78aca213048f8bb955f25f843843d7ac1105fd41bfa93f75511d31ab34b5e1b4 44886083083de2e6820d818f1dbb1fa052dd5cc7a020e56394b7691f53943ed5 0ae9f25bd9a1849d30f1e7253ea00fcefc1da3a2f304bea19acf238fa710040c c0e80e9b62ce7f72b27f37bef61085f7d3a5815ca047df675d393f61aba89648 cd28863f7a07fbf214d8fb43cb2fb0adb9606c9a713ec84a2482bdd44c7cd714 e578b693272828dfd6e92da41f17623bfab0d67f940072b16e4b166e9a219b3e ba7f259569135b88242fab7dc01ff9440033da831efc16722e9e51fd4ea97464 fa1f35fa6cad944113da12118915098d30cbf95f3ea9040dae8a939ee7032ab7"),
  "linux/arm64": splitDigests("dd97e58b4e812b247f3cd261fa7eac247b7c5896b8e34d9474762678cae7774d e26286284f6ea22d800d847e7f0ccee9e39591de19270b17eec80289a6270c32 e9890cd72d1ba8ed4f2561f0a5bf8dcefdda006995f19d3c8440d76f35926cbf c98a5e0a8fe7c817f5d1c8a66a8dab61f9d3078f6fb41139c24ce740dd16f62e 2c76fbccc2935724c3e84fc052b1148647bc36a42eb2369f19b2c5f39bf6dc1f 7e369ff650827f0c72650bcc5b389d3de1a5ed8c7d060103c37ae85b1960122c 74a3636105f24bf45639008f5a89c54891af9f9f6f54c009832635a8c6876b37 e542b6dea3e3aa65b52a788c7f37de76897565cfb524e9a6f0d14c8346834c2a 5f70bf18a086007016e948b04aed3b82103a36bea41755b6cddfaf10ace3c6ef b0e2843524ab5d895251195da51e546d01d9c1773de9e8cccbcb89a7138eab85 88ee7e0947a470db0265f3bf6662b67c5fc355e6c6a8bf8b5f4059b3695840f8 439dfba5c7364008079ba52d5219e684caef5568f3a1bf01ece2bbea8d290110 0e2f66df6cc4ef1eba496407f6cf1b11205e29180d8f962d97d1b77f559dc30d 1c88bb3882c0289b43df9c7c494ffa3421371990c76a6c72c3384182a61f187d 296c1ff4085bb574b3fd1ebfa8b241b39e09aa42951f45a439182d4ba59c1b19 c7a5647fe1ea9d79d1b37c831530c6ed74ba10c60b28fbb3737508fc2e31239a 845b205b19f1db0d6aa84e66b39ca749a3bf5b02dea3f29a757665578b2606fe 860087e788694bbd0ecc2867ebc966180ad2386dea8e8a8227c724b9e7dce81b 0d7927c65099db2e28535a92810316146f02ecd0af0ab5b19851ed5594c66f08 09a2092ac95780b82c83349ae1a2137ed07f3d5c3d84718be02611eb6c32288f 23cb31207131721c9e5aacfe417150a9bfc772ebbf949bbd08ed598ac8de50db 22e218564ab1271874027666aeb047b2a7f6865517c21b45c349c035a74b29fa 3380a402b706b97495aff0e64a49a60b3d8394528073e426b224d7e724cdf235 1cb669a6e999056fa3dbaa70318b2193cd2130523097e4a5bedda740288b5e3a"),
});

export function validateLocalStackImageIndex(document, selected) {
  try {
    requireLocalStackPlan(selected);
    requireExactKeys(document, ["manifests", "mediaType", "schemaVersion"]);
    if (document.schemaVersion !== 2 || document.mediaType !== "application/vnd.docker.distribution.manifest.list.v2+json" ||
        !isDeepStrictEqual(document.manifests, indexDescriptors)) throw new TypeError("LocalStack index is invalid");
    const selectedDescriptor = document.manifests.find(({ digest, platform }) =>
      digest === selected.manifestDigest && platform.architecture === selected.architecture && platform.os === "linux");
    if (selectedDescriptor === undefined) throw new TypeError("LocalStack descriptor is invalid");
    return deepFreeze({ indexDigest: selected.indexDigest, manifests: structuredClone(document.manifests), mediaType: document.mediaType, schemaVersion: 2, selected: structuredClone(selectedDescriptor) });
  } catch (error) {
    if (error instanceof AwsEmulatorFailure) throw error;
    throw new AwsEmulatorFailure("normalization");
  }
}

export function validateLocalStackImageManifest(document, selected) {
  try {
    requireLocalStackPlan(selected);
    requireExactKeys(document, ["config", "layers", "mediaType", "schemaVersion"]);
    const expected = manifestFacts[selected.platform];
    if (expected === undefined || !isDeepStrictEqual(document, expected)) throw new TypeError("LocalStack manifest is invalid");
    return deepFreeze(structuredClone(document));
  } catch (error) {
    if (error instanceof AwsEmulatorFailure) throw error;
    throw new AwsEmulatorFailure("normalization");
  }
}

export function validateLocalStackImageInspection(document, selected, resolution, retained = undefined, aliases = undefined) {
  try {
    requireLocalStackPlan(selected);
    const keys = ["architecture", "command", "entrypoint", "environment", "exposedPorts", "id", "intrinsicVolumes", "labels", "operatingSystem", "repoDigests", "repoTags", "rootfs", "user", "workingDirectory"];
    requireExactKeys(document, keys);
    requireExactKeys(resolution, ["index", "manifest"]);
    const expectedAliases = aliases ?? { repoDigests: [selected.repoDigest], repoTags: [] };
    requireExactKeys(expectedAliases, ["repoDigests", "repoTags"]);
    if (!isDeepStrictEqual(expectedAliases.repoDigests, [selected.repoDigest]) ||
        !(isDeepStrictEqual(expectedAliases.repoTags, []) || isDeepStrictEqual(expectedAliases.repoTags, [selected.tag])) ||
        resolution.index?.indexDigest !== selected.indexDigest || resolution.index?.selected?.digest !== selected.manifestDigest ||
        !isDeepStrictEqual(resolution.manifest, manifestFacts[selected.platform]) ||
        document.architecture !== selected.architecture || document.operatingSystem !== "linux" ||
        document.id !== selected.configDigest || !isDeepStrictEqual(document.repoDigests, expectedAliases.repoDigests) ||
        !isDeepStrictEqual(document.repoTags, expectedAliases.repoTags) ||
        !isDeepStrictEqual(document.rootfs, { Layers: rootfsFacts[selected.platform], Type: "layers" }) ||
        !isDeepStrictEqual(document.environment, imageEnvironment) || !isDeepStrictEqual(document.entrypoint, ["docker-entrypoint.sh"]) ||
        document.command !== null || !isDeepStrictEqual(document.exposedPorts, exposedPorts) ||
        !isDeepStrictEqual(document.intrinsicVolumes, { "/var/lib/localstack": {} }) ||
        !isDeepStrictEqual(document.labels, imageLabels) || document.user !== "" ||
        document.workingDirectory !== "/opt/code/localstack/") throw new TypeError("LocalStack inspection is invalid");
    const identity = deepFreeze({
      architecture: document.architecture,
      command: null,
      configDigest: selected.configDigest,
      entrypoint: ["docker-entrypoint.sh"],
      environment: [...document.environment],
      exposedPorts: structuredClone(document.exposedPorts),
      id: selected.configDigest,
      index: structuredClone(resolution.index),
      indexDigest: selected.indexDigest,
      intrinsicVolumes: structuredClone(document.intrinsicVolumes),
      labels: structuredClone(document.labels),
      manifest: structuredClone(resolution.manifest),
      manifestDigest: selected.manifestDigest,
      name: selected.name,
      platform: selected.platform,
      reference: selected.reference,
      repoDigests: [...document.repoDigests],
      repoTags: [...document.repoTags],
      rootfs: structuredClone(document.rootfs),
      user: "",
      workingDirectory: document.workingDirectory,
    });
    if (retained !== undefined && !isDeepStrictEqual(identity, retained)) throw new TypeError("LocalStack identity changed");
    return identity;
  } catch (error) {
    if (error instanceof AwsEmulatorFailure) throw error;
    throw new AwsEmulatorFailure("ownership");
  }
}

export function validateAwsEmulatorKubernetesState(value, expected, retained = undefined, requireJob = false,
  category = "readiness") {
  try {
    requireExactKeys(value, [
      "configMaps", "deployments", "endpointSlices", "ingresses", "jobLog", "jobs", "pods", "replicaSets",
      "services",
    ]);
    requireExactKeys(expected, ["imageTarget", "nodeName"]);
    requireExactKeys(expected.imageTarget, ["configDigest", "imageID"]);
    if (!/^sha256:[0-9a-f]{64}$/.test(expected.imageTarget.configDigest) ||
        !/^docker\.io\/library\/import-\d{4}-\d{2}-\d{2}@sha256:[0-9a-f]{64}$/.test(expected.imageTarget.imageID) ||
        !/^zasp-m1-30d-[0-9a-f]{16}-control-plane$/.test(expected.nodeName) ||
        typeof requireJob !== "boolean" || !AWS_EMULATOR_FAILURE_CATEGORIES.includes(category) ||
        !plainArray(value.configMaps) || value.configMaps.length !== 1 ||
        !plainArray(value.deployments) || value.deployments.length !== 1 ||
        !plainArray(value.replicaSets) || value.replicaSets.length !== 1 ||
        !plainArray(value.services) || value.services.length !== 1 ||
        !plainArray(value.endpointSlices) || value.endpointSlices.length !== 1 ||
        !plainArray(value.ingresses) || value.ingresses.length !== 0 ||
        !plainArray(value.jobs) || value.jobs.length !== (requireJob ? 1 : 0) ||
        !plainArray(value.pods) || value.pods.length !== (requireJob ? 2 : 1) ||
        value.jobLog !== (requireJob ? `${AWS_EMULATOR_CONSTANTS.successMarker}\n` : null)) {
      throw new TypeError("AWS provider collection is invalid");
    }

    const [configResource, deploymentResource, serviceResource, jobResource] = buildAwsEmulatorResources();
    const configMap = value.configMaps[0];
    const deployment = value.deployments[0];
    const replicaSet = value.replicaSets[0];
    const localstackPod = value.pods.find((pod) =>
      pod?.metadata?.labels?.["app.kubernetes.io/name"] === AWS_EMULATOR_CONSTANTS.localstackName);
    const service = value.services[0];
    const endpointSlice = value.endpointSlices[0];
    const configUid = providerUid(configMap?.metadata?.uid);
    const deploymentUid = providerUid(deployment?.metadata?.uid);
    const replicaSetUid = providerUid(replicaSet?.metadata?.uid);
    const podUid = providerUid(localstackPod?.metadata?.uid);
    const serviceUid = providerUid(service?.metadata?.uid);
    const endpointUid = providerUid(endpointSlice?.metadata?.uid);
    const configVersion = providerVersion(configMap?.metadata?.resourceVersion);
    const deploymentVersion = providerVersion(deployment?.metadata?.resourceVersion);
    const replicaSetVersion = providerVersion(replicaSet?.metadata?.resourceVersion);
    const podVersion = providerVersion(localstackPod?.metadata?.resourceVersion);
    const serviceVersion = providerVersion(service?.metadata?.resourceVersion);
    const endpointVersion = providerVersion(endpointSlice?.metadata?.resourceVersion);
    const hash = /^localstack-([a-z0-9]{10})$/.exec(replicaSet?.metadata?.name ?? "")?.[1];
    const podName = hash !== undefined && /^localstack-[a-z0-9]{10}-[a-z0-9]{5}$/.test(
      localstackPod?.metadata?.name ?? "") ? localstackPod.metadata.name : undefined;
    const podIP = validPodAddress(localstackPod?.status?.podIP) ? localstackPod.status.podIP : undefined;
    const clusterIP = validServiceAddress(service?.spec?.clusterIP) ? service.spec.clusterIP : undefined;
    const endpointName = /^localstack-[a-z0-9]{5}$/.test(endpointSlice?.metadata?.name ?? "")
      ? endpointSlice.metadata.name : undefined;
    const container = localstackPod?.status?.containerStatuses?.[0];
    const containerId = providerContainerId(container?.containerID);
    const startedAt = providerTimestamp(container?.state?.running?.startedAt);
    if ([configUid, deploymentUid, replicaSetUid, podUid, serviceUid, endpointUid, configVersion,
      deploymentVersion, replicaSetVersion, podVersion, serviceVersion, endpointVersion, hash, podName,
      podIP, clusterIP, endpointName, containerId, startedAt].some((item) => item === undefined)) {
      throw new TypeError("AWS provider identity is invalid");
    }

    const replicaLabels = { ...deploymentResource.metadata.labels, "pod-template-hash": hash };
    const expectedConfig = {
      apiVersion: "v1", data: structuredClone(configResource.data), kind: "ConfigMap",
      metadata: { labels: structuredClone(configResource.metadata.labels), name: configResource.metadata.name,
        namespace: AWS_EMULATOR_CONSTANTS.namespace, resourceVersion: configVersion, uid: configUid },
    };
    const expectedDeployment = {
      apiVersion: "apps/v1", kind: "Deployment",
      metadata: { generation: 1, labels: structuredClone(deploymentResource.metadata.labels),
        name: AWS_EMULATOR_CONSTANTS.localstackName, namespace: AWS_EMULATOR_CONSTANTS.namespace,
        resourceVersion: deploymentVersion, uid: deploymentUid },
      spec: { ...structuredClone(deploymentResource.spec), template: providerAwsTemplate(deploymentResource.spec.template) },
      status: { availableReplicas: 1, conditions: [{ status: "True", type: "Available" }],
        observedGeneration: 1, readyReplicas: 1, replicas: 1, unavailableReplicas: 0, updatedReplicas: 1 },
    };
    const expectedReplicaSet = {
      apiVersion: "apps/v1", kind: "ReplicaSet",
      metadata: { labels: replicaLabels, name: `localstack-${hash}`, namespace: AWS_EMULATOR_CONSTANTS.namespace,
        ownerReferences: [{ apiVersion: "apps/v1", blockOwnerDeletion: true, controller: true,
          kind: "Deployment", name: AWS_EMULATOR_CONSTANTS.localstackName, uid: deploymentUid }],
        resourceVersion: replicaSetVersion, uid: replicaSetUid },
      spec: { replicas: 1, selector: { matchLabels: { "app.kubernetes.io/name": "localstack",
        "pod-template-hash": hash } }, template: providerAwsTemplate(deploymentResource.spec.template, replicaLabels) },
      status: { availableReplicas: 1, fullyLabeledReplicas: 1, observedGeneration: 1, readyReplicas: 1, replicas: 1 },
    };
    const expectedPod = {
      apiVersion: "v1", kind: "Pod",
      metadata: { labels: replicaLabels, name: podName, namespace: AWS_EMULATOR_CONSTANTS.namespace,
        ownerReferences: [{ apiVersion: "apps/v1", blockOwnerDeletion: true, controller: true,
          kind: "ReplicaSet", name: `localstack-${hash}`, uid: replicaSetUid }],
        resourceVersion: podVersion, uid: podUid },
      spec: providerAwsPodSpec(deploymentResource.spec.template, expected.nodeName),
      status: { conditions: [{ status: "True", type: "Ready" }], containerStatuses: [{
        containerID: containerId, image: expected.imageTarget.configDigest, imageID: expected.imageTarget.imageID,
        lastState: {}, name: "localstack", ready: true, restartCount: 0, started: true,
        state: { running: { startedAt } },
      }], phase: "Running", podIP },
    };
    const expectedService = {
      apiVersion: "v1", kind: "Service",
      metadata: { labels: structuredClone(serviceResource.metadata.labels), name: "localstack",
        namespace: AWS_EMULATOR_CONSTANTS.namespace, resourceVersion: serviceVersion, uid: serviceUid },
      spec: { clusterIP, clusterIPs: [clusterIP], internalTrafficPolicy: "Cluster",
        ...structuredClone(serviceResource.spec) },
      status: { loadBalancer: {} },
    };
    const expectedEndpoint = {
      addressType: "IPv4", apiVersion: "discovery.k8s.io/v1",
      endpoints: [{ addresses: [podIP], conditions: { ready: true, serving: true, terminating: false },
        nodeName: expected.nodeName, targetRef: { kind: "Pod", name: podName,
          namespace: AWS_EMULATOR_CONSTANTS.namespace, uid: podUid } }],
      kind: "EndpointSlice",
      metadata: { labels: { ...structuredClone(serviceResource.metadata.labels),
        "endpointslice.kubernetes.io/managed-by": "endpointslice-controller.k8s.io",
        "kubernetes.io/service-name": "localstack" }, name: endpointName,
        namespace: AWS_EMULATOR_CONSTANTS.namespace,
        ownerReferences: [{ apiVersion: "v1", blockOwnerDeletion: true, controller: true,
          kind: "Service", name: "localstack", uid: serviceUid }], resourceVersion: endpointVersion, uid: endpointUid },
      ports: [{ name: "edge", port: 4566, protocol: "TCP" }],
    };
    if (![isDeepStrictEqual(configMap, expectedConfig), isDeepStrictEqual(deployment, expectedDeployment),
      isDeepStrictEqual(replicaSet, expectedReplicaSet), isDeepStrictEqual(localstackPod, expectedPod),
      isDeepStrictEqual(service, expectedService), isDeepStrictEqual(endpointSlice, expectedEndpoint)].every(Boolean)) {
      throw new TypeError("AWS core provider state is invalid");
    }
    const snapshot = deepFreeze({
      configMaps: structuredClone(value.configMaps), deployments: structuredClone(value.deployments),
      endpointSlices: structuredClone(value.endpointSlices), ingresses: [], pods: [structuredClone(localstackPod)],
      replicaSets: structuredClone(value.replicaSets), services: structuredClone(value.services),
    });
    const localstack = deepFreeze({ configResourceVersion: configVersion, containerId, podName, podUid });
    if (retained !== undefined && (!isPlainObject(retained) ||
        !isDeepStrictEqual(retained.localstack, localstack) || !isDeepStrictEqual(retained.snapshot, snapshot))) {
      throw new TypeError("AWS core state changed");
    }
    const job = requireJob ? validateAwsEmulatorJob(value, expected, jobResource) : null;
    if (requireJob && retained?.job !== null && retained?.job !== undefined && !isDeepStrictEqual(retained.job, job)) {
      throw new TypeError("AWS Job state changed");
    }
    return deepFreeze({ job, localstack, ready: true, snapshot });
  } catch (error) {
    if (error instanceof Failure) throw error;
    throw new AwsEmulatorFailure(category);
  }
}

export class LocalAwsEmulatorSystem extends LocalObservabilitySystem {
  constructor(input, dependencies = undefined) {
    super(input, dependencies, buildAwsEmulatorProfile());
    this.graphImagePlans.set("localstack", buildLocalStackImagePlan(input.nodePlatform));
    this.awsEmulatorCoreMayHaveApplied = false;
    this.awsEmulatorJobMayHaveApplied = false;
    this.awsEmulatorProviderIdentity = undefined;
  }

  async applyManifests(phase) {
    const stagedKey = awsEmulatorApplyPlan().staged[1];
    const s3Path = this.additionalManifestPaths.get(stagedKey);
    if (s3Path === undefined || !this.additionalManifestPaths.delete(stagedKey)) {
      throw new AwsEmulatorFailure("ownership");
    }
    this.awsEmulatorCoreMayHaveApplied = true;
    try {
      await super.applyManifests(phase);
    } finally {
      this.additionalManifestPaths.set(stagedKey, s3Path);
    }
  }

  async verifyAdditionalManifestState(phase, path) {
    if (path !== this.paths?.awsEmulatorCoreManifest && path !== this.paths?.awsEmulatorS3Manifest) {
      return await super.verifyAdditionalManifestState(phase, path);
    }
    await super.verifyAdditionalManifestState(phase, this.paths.observabilityCoreManifest);
    await this.requireOwnedPath(path, phase, "ownership");
  }

  async verifyObservabilityReadiness(productResult, phase) {
    return await super.verifyAdditionalReadiness(productResult, phase);
  }

  awsEmulatorProviderExpectation() {
    const selected = this.graphImagePlans.get("localstack");
    const loaded = this.graphLoadedImageTargets.get("localstack");
    if (selected === undefined || loaded === undefined || typeof loaded.imageID !== "string") {
      throw new AwsEmulatorFailure("ownership");
    }
    return deepFreeze({
      imageTarget: { configDigest: selected.configDigest, imageID: loaded.imageID },
      nodeName: `${this.cluster}-control-plane`,
    });
  }

  async readAwsEmulatorProviderState(phase, category = "readiness") {
    await this.requireTemporaryOwnership(phase, "ownership");
    await this.verifyCluster(phase, "ownership");
    const requests = [
      ["configMaps", "configmap", "app.kubernetes.io/component=aws-emulator"],
      ["deployments", "deployment", "app.kubernetes.io/component=aws-emulator"],
      ["replicaSets", "replicaset", "app.kubernetes.io/component=aws-emulator"],
      ["pods", "pod", "app.kubernetes.io/component=aws-emulator"],
      ["services", "service", "app.kubernetes.io/component=aws-emulator"],
      ["endpointSlices", "endpointslice", "kubernetes.io/service-name=localstack"],
      ["jobs", "job", "app.kubernetes.io/component=aws-emulator"],
      ["ingresses", "ingress", "app.kubernetes.io/component=aws-emulator"],
    ];
    const documents = {};
    for (const [name, resource, selector] of requests) {
      const result = await super.runKubectlRead([
        "get", resource, "--namespace", AWS_EMULATOR_CONSTANTS.namespace,
        `--selector=${selector}`, "--output=json",
      ], phase, category, 30_000, providerByteLimit);
      documents[name] = projectAwsProviderResources(parseAwsProviderList(result.stdout), name);
    }
    const jobPods = documents.pods.filter((pod) =>
      pod?.metadata?.labels?.["app.kubernetes.io/name"] === AWS_EMULATOR_CONSTANTS.s3JobName);
    let jobLog = null;
    if (jobPods.length === 1 && /^localstack-s3-probe-[a-z0-9]{5}$/.test(jobPods[0]?.metadata?.name ?? "")) {
      const result = await super.runKubectlRead([
        "logs", "--namespace", AWS_EMULATOR_CONSTANTS.namespace, jobPods[0].metadata.name,
        "--container", "s3-probe",
      ], phase, category, 30_000, 16_384);
      jobLog = result.stdout;
    }
    return { ...documents, jobLog };
  }

  async pauseAwsEmulatorPoll(phase, category) {
    await new Promise((resolve) => setTimeout(resolve, 500));
    phase.assertActive(category);
  }

  async verifyAwsEmulatorBaseState(phase, category) {
    const retained = this.observabilityProviderIdentity;
    if (retained === undefined) throw new AwsEmulatorFailure(category === "cleanup" ? "cleanup" : "ownership");
    this.observabilityProviderIdentity = await this.pollObservabilityProviderState(
      phase, retained, true, category,
    );
  }

  async pollAwsEmulatorProviderState(phase, retained = undefined, requireJob = false,
    category = "readiness") {
    let failure;
    for (let attempt = 0; attempt < 240; attempt += 1) {
      phase.assertActive(category);
      try {
        const providerState = await this.readAwsEmulatorProviderState(phase, category);
        if (terminalAwsEmulatorProviderState(providerState, requireJob)) {
          throw new AwsEmulatorFailure(category === "readiness" ? "provider" : category);
        }
        const candidate = validateAwsEmulatorKubernetesState(
          providerState,
          this.awsEmulatorProviderExpectation(), retained, requireJob, category,
        );
        await this.verifyAwsEmulatorBaseState(phase, category);
        await this.verifyAdditionalManifestState(phase, this.paths.awsEmulatorCoreManifest);
        if (requireJob) await this.verifyAdditionalManifestState(phase, this.paths.awsEmulatorS3Manifest);
        return validateAwsEmulatorKubernetesState(
          await this.readAwsEmulatorProviderState(phase, category),
          this.awsEmulatorProviderExpectation(), candidate, requireJob, category,
        );
      } catch (error) {
        if (!(error instanceof Failure) || error.category !== category) throw error;
        failure = error;
      }
      if (attempt + 1 < 240) await this.pauseAwsEmulatorPoll(phase, category);
    }
    throw failure ?? new AwsEmulatorFailure(category);
  }

  async applyAwsEmulatorJob(phase) {
    const path = this.paths?.awsEmulatorS3Manifest;
    if (typeof path !== "string") throw new AwsEmulatorFailure("ownership");
    await this.verifyAdditionalManifestState(phase, path);
    const result = await this.withOwnedFiles(
      [this.paths.kubeconfig, path], phase, "ownership", async ([kubeconfig, manifest]) =>
        await this.runMutation("kubectl", [
          "--kubeconfig", "/dev/fd/3", "apply", "--filename", "-",
        ], phase, "provider", {
          environment: this.environment,
          fileDescriptors: [kubeconfig.handle.fd],
          input: manifest.identity.bytes,
          outputLimit: providerByteLimit,
          timeoutMilliseconds: 90_000,
        }),
    );
    await this.requireOwnedPath(this.paths.kubeconfig, phase, "ownership");
    await this.requireOwnedPath(path, phase, "ownership");
    return result;
  }

  async verifyAdditionalReadiness(productResult, phase) {
    const observabilityResult = await this.verifyObservabilityReadiness(productResult, phase);
    const core = await this.pollAwsEmulatorProviderState(phase);
    this.awsEmulatorProviderIdentity = core;
    this.awsEmulatorCoreMayHaveApplied = false;
    this.awsEmulatorJobMayHaveApplied = true;
    const applied = await this.applyAwsEmulatorJob(phase);
    if (!new Set(["ambiguous", "applied"]).has(applied?.outcome)) {
      this.awsEmulatorJobMayHaveApplied = false;
      throw new AwsEmulatorFailure("provider");
    }
    const complete = await this.pollAwsEmulatorProviderState(phase, core, true);
    this.awsEmulatorProviderIdentity = complete;
    this.awsEmulatorJobMayHaveApplied = false;
    this.awsEmulatorProviderIdentity = await this.pollAwsEmulatorProviderState(phase, complete, true);
    return deepFreeze({
      ...observabilityResult,
      awsEmulator: { endpoint: true, internal: true, ready: true, s3: true },
    });
  }

  async verifyAdditionalNodeForCleanup(phase) {
    for (const path of [this.paths?.awsEmulatorCoreManifest, this.paths?.awsEmulatorS3Manifest]) {
      if (typeof path !== "string") throw new AwsEmulatorFailure("cleanup");
      await this.requireOwnedPath(path, phase, "cleanup");
    }
    await super.verifyAdditionalNodeForCleanup(phase);
    if (this.awsEmulatorCoreMayHaveApplied && this.awsEmulatorProviderIdentity === undefined) {
      await this.reconcileAwsEmulatorCoreForCleanup(phase);
    }
    const retained = this.awsEmulatorProviderIdentity;
    if (retained === undefined && !this.awsEmulatorJobMayHaveApplied) return;
    if (retained === undefined) throw new AwsEmulatorFailure("cleanup");
    let failure;
    for (let attempt = 0; attempt < 240; attempt += 1) {
      phase.assertActive("cleanup");
      try {
        const providerState = await this.readAwsEmulatorProviderState(phase, "cleanup");
        let current;
        if (this.awsEmulatorJobMayHaveApplied) {
          try {
            current = validateAwsEmulatorKubernetesState(
              providerState, this.awsEmulatorProviderExpectation(), retained, true, "cleanup",
            );
          } catch {
            try {
              current = validateAwsEmulatorKubernetesState(
                providerState, this.awsEmulatorProviderExpectation(), retained, false, "cleanup",
              );
            } catch {
              current = validateFailedAwsEmulatorKubernetesState(
                providerState, this.awsEmulatorProviderExpectation(), retained, "cleanup",
              );
            }
          }
        } else {
          current = retained.job?.failed === true
            ? validateFailedAwsEmulatorKubernetesState(
              providerState, this.awsEmulatorProviderExpectation(), retained, "cleanup",
            )
            : validateAwsEmulatorKubernetesState(
              providerState, this.awsEmulatorProviderExpectation(), retained, retained.job !== null, "cleanup",
            );
        }
        this.awsEmulatorProviderIdentity = current;
        this.awsEmulatorJobMayHaveApplied = false;
        return;
      } catch (error) {
        if (!(error instanceof Failure) || error.category !== "cleanup") throw error;
        failure = error;
      }
      if (attempt + 1 < 240) await this.pauseAwsEmulatorPoll(phase, "cleanup");
    }
    throw failure ?? new AwsEmulatorFailure("cleanup");
  }

  async reconcileAwsEmulatorCoreForCleanup(phase) {
    let failure;
    for (let attempt = 0; attempt < 3; attempt += 1) {
      phase.assertActive("cleanup");
      try {
        const providerState = await this.readAwsEmulatorProviderState(phase, "cleanup");
        try {
          requireAwsEmulatorProviderAbsent(providerState);
          this.awsEmulatorCoreMayHaveApplied = false;
          this.awsEmulatorProviderIdentity = undefined;
          return;
        } catch {
          this.awsEmulatorProviderIdentity = validateAwsEmulatorKubernetesState(
            providerState, this.awsEmulatorProviderExpectation(), undefined, false, "cleanup",
          );
          this.awsEmulatorCoreMayHaveApplied = false;
          return;
        }
      } catch (error) {
        if (!(error instanceof Failure) || error.category !== "cleanup") throw error;
        failure = error;
      }
    }
    throw failure ?? new AwsEmulatorFailure("cleanup");
  }

  async afterClusterAbsent() {
    await super.afterClusterAbsent();
    this.awsEmulatorCoreMayHaveApplied = false;
    this.awsEmulatorJobMayHaveApplied = false;
    this.awsEmulatorProviderIdentity = undefined;
  }

  hasAdditionalRecoveryState() {
    return super.hasAdditionalRecoveryState() || this.awsEmulatorCoreMayHaveApplied ||
      this.awsEmulatorJobMayHaveApplied || this.awsEmulatorProviderIdentity !== undefined;
  }

  async resolveGraphImage(selected, phase) {
    if (selected.name !== "localstack") return await super.resolveGraphImage(selected, phase);
    const indexResult = await this.runRead("docker", ["manifest", "inspect", selected.reference], phase, "provider", 30_000, providerByteLimit);
    const manifestResult = await this.runRead("docker", ["manifest", "inspect", selected.selectedReference], phase, "provider", 30_000, providerByteLimit);
    try {
      return deepFreeze({
        index: validateLocalStackImageIndex(parseBoundedJson(indexResult.stdout, providerByteLimit), selected),
        manifest: validateLocalStackImageManifest(parseBoundedJson(manifestResult.stdout, providerByteLimit), selected),
      });
    } catch (error) {
      if (error instanceof Failure) throw error;
      throw new AwsEmulatorFailure("normalization");
    }
  }

  async inspectGraphImage(selected, resolution, phase, retained = undefined, reference = selected.reference,
    category = "ownership", aliases = undefined) {
    if (selected.name !== "localstack") {
      return await super.inspectGraphImage(selected, resolution, phase, retained, reference, category, aliases);
    }
    const format = "[{{json .Architecture}},{{json .Os}},{{json .Id}},{{json .RepoDigests}},{{json .RepoTags}}," +
      "{{json .RootFS}},{{json (index .Config \"Env\")}},{{json (index .Config \"Entrypoint\")}}," +
      "{{json (index .Config \"Cmd\")}},{{json (index .Config \"ExposedPorts\")}}," +
      "{{json (index .Config \"Volumes\")}},{{json (index .Config \"Labels\")}}," +
      "{{json (or (index .Config \"User\") \"\")}},{{json (or (index .Config \"WorkingDir\") \"\")}}]";
    const result = await this.runRead("docker", ["image", "inspect", "--format", format, reference], phase, category, 15_000, providerByteLimit);
    let values;
    try { values = parseBoundedJson(result.stdout, providerByteLimit); }
    catch { throw new AwsEmulatorFailure("normalization"); }
    if (!Array.isArray(values) || values.length !== 14) throw new AwsEmulatorFailure("normalization");
    const [architecture, operatingSystem, id, repoDigests, repoTags, rootfs, environment, entrypoint,
      command, exposed, volumes, labels, user, workingDirectory] = values;
    return validateLocalStackImageInspection({
      architecture, command, entrypoint, environment, exposedPorts: exposed, id, intrinsicVolumes: volumes,
      labels, operatingSystem, repoDigests, repoTags, rootfs, user, workingDirectory,
    }, selected, resolution, retained, aliases);
  }
}

export class DockerKindAwsEmulatorRuntime extends DockerKindGraphRuntime {
  constructor(input, system = undefined) {
    super(input, system ?? new LocalAwsEmulatorSystem(input));
    if (!isDeepStrictEqual(this.system?.profile, buildAwsEmulatorProfile())) {
      throw new TypeError("AWS emulator runtime profile is invalid");
    }
  }

  static fromProcess(environment = process.env, systemFactory = (input) => new LocalAwsEmulatorSystem(input)) {
    const selected = DockerKindGraphRuntime.fromProcess(environment, systemFactory);
    return new DockerKindAwsEmulatorRuntime(selected.input, selected.system);
  }
}

export async function runAwsEmulatorMain(runtime = undefined, options = {}) {
  const stdout = options.stdout ?? process.stdout;
  const stderr = options.stderr ?? process.stderr;
  const setExitCode = options.setExitCode ?? ((value) => { process.exitCode = value; });
  try {
    const selected = runtime ?? DockerKindAwsEmulatorRuntime.fromProcess();
    const result = await orchestrate(guardLifecycle(selected), {
      cleanupTimeoutMilliseconds: options.cleanupTimeoutMilliseconds ?? awsCleanupTimeoutMilliseconds,
      mainTimeoutMilliseconds: options.mainTimeoutMilliseconds ?? awsMainTimeoutMilliseconds,
      settlementTimeoutMilliseconds: options.settlementTimeoutMilliseconds ?? awsSettlementTimeoutMilliseconds,
    });
    validateResult(result);
    stdout.write(`${AWS_EMULATOR_SUCCESS_LINE}\n`);
    setExitCode(0);
    return 0;
  } catch (error) {
    const category = AWS_EMULATOR_FAILURE_CATEGORIES.includes(error?.category) ? error.category : "panic";
    stderr.write(`Local AWS emulator manifest failed: ${category} rejected.\n`);
    setExitCode(1);
    return 1;
  }
}

function guardLifecycle(runtime) {
  if (runtime === null || typeof runtime !== "object") throw new TypeError("AWS emulator runtime is invalid");
  const guarded = {};
  for (const name of ["initialize", "preflight", "buildImages", "createNetwork", "createCluster", "loadImages", "applyManifests", "verifyReadiness"]) {
    if (typeof runtime[name] !== "function") throw new TypeError(`AWS emulator runtime ${name} is invalid`);
    guarded[name] = (phase) => runtime[name](phase);
  }
  for (const name of ["joinMutations", "cleanup", "auditAbsence"]) {
    if (typeof runtime[name] !== "function") throw new TypeError(`AWS emulator runtime ${name} is invalid`);
    guarded[name] = async (phase) => {
      try { return await runtime[name](phase); }
      catch (error) {
        if (error instanceof Failure) throw error;
        throw new AwsEmulatorFailure("cleanup");
      }
    };
  }
  return Object.freeze(guarded);
}

function validateResult(value) {
  if (!isPlainObject(value) || value.cleanup !== true || value.internal !== true || value.pods !== 4 ||
      value.ready !== 4 || value.services !== 4 || !isDeepStrictEqual(value.graph, {
        internal: true, persistent: true, ready: true,
      }) || !isDeepStrictEqual(value.observability, {
        internal: true, noEgress: true, ready: true, sink: true, spans: 1,
      }) || !isDeepStrictEqual(value.awsEmulator, {
        endpoint: true, internal: true, ready: true, s3: true,
      })) throw new AwsEmulatorFailure("readiness");
}

function buildManifestFact(configDigest, configSize, layerSource) {
  return {
    config: { digest: configDigest, mediaType: "application/vnd.docker.container.image.v1+json", size: configSize },
    layers: layerSource.split(" ").map((entry) => {
      const [digest, size] = entry.split(":");
      return { digest: `sha256:${digest}`, mediaType: "application/vnd.docker.image.rootfs.diff.tar.gzip", size: Number(size) };
    }),
    mediaType: "application/vnd.docker.distribution.manifest.v2+json",
    schemaVersion: 2,
  };
}

function splitDigests(source) {
  return source.split(" ").map((digest) => `sha256:${digest}`);
}

function parseAwsProviderList(source) {
  try {
    const document = parseBoundedJson(source, providerByteLimit);
    requireExactKeys(document, ["apiVersion", "items", "kind", "metadata"]);
    requireExactKeys(document.metadata, ["resourceVersion"]);
    if (document.apiVersion !== "v1" || document.kind !== "List" ||
        document.metadata.resourceVersion !== "" || !plainArray(document.items) ||
        document.items.length > 128) throw new TypeError("AWS provider list is invalid");
    return structuredClone(document.items);
  } catch (error) {
    if (error instanceof Failure) throw error;
    throw new AwsEmulatorFailure("normalization");
  }
}

function projectAwsProviderResources(items, label) {
  try {
    if (!plainArray(items)) throw new TypeError("AWS provider items are invalid");
    const projector = {
      configMaps: projectAwsConfigMap,
      deployments: projectAwsDeployment,
      endpointSlices: projectAwsEndpointSlice,
      ingresses: (item) => structuredClone(item),
      jobs: projectAwsJob,
      pods: projectAwsPod,
      replicaSets: projectAwsReplicaSet,
      services: projectAwsService,
    }[label];
    if (projector === undefined) throw new TypeError("AWS provider label is invalid");
    return items.map(projector);
  } catch (error) {
    if (error instanceof Failure) throw error;
    throw new AwsEmulatorFailure("normalization");
  }
}

function projectAwsMetadata(item, fields) {
  const metadata = Object.fromEntries(fields.map((key) => [key, structuredClone(item?.metadata?.[key])]));
  if (item?.metadata?.deletionTimestamp !== undefined) metadata.deletionTimestamp = item.metadata.deletionTimestamp;
  if (item?.metadata?.deletionGracePeriodSeconds !== undefined) {
    metadata.deletionGracePeriodSeconds = item.metadata.deletionGracePeriodSeconds;
  }
  return metadata;
}

function projectAwsOwnerReferences(value) {
  return Array.isArray(value) ? value.map((entry) => ({
    apiVersion: entry?.apiVersion, blockOwnerDeletion: entry?.blockOwnerDeletion,
    controller: entry?.controller, kind: entry?.kind, name: entry?.name, uid: entry?.uid,
  })) : [];
}

function projectAwsWorkloadSpec(value) {
  const spec = structuredClone(value);
  const podSpec = spec?.template?.spec;
  if (!isPlainObject(podSpec)) return spec;
  if (isPlainObject(spec.template.metadata) && spec.template.metadata.creationTimestamp === undefined) {
    spec.template.metadata.creationTimestamp = null;
  }
  for (const key of ["hostIPC", "hostNetwork", "hostPID"]) if (podSpec[key] === undefined) podSpec[key] = false;
  return spec;
}

function projectAwsConfigMap(item) {
  return { apiVersion: item?.apiVersion, data: structuredClone(item?.data), kind: item?.kind,
    metadata: projectAwsMetadata(item, ["labels", "name", "namespace", "resourceVersion", "uid"]) };
}

function projectAwsDeployment(item) {
  return { apiVersion: item?.apiVersion, kind: item?.kind,
    metadata: projectAwsMetadata(item, ["generation", "labels", "name", "namespace", "resourceVersion", "uid"]),
    spec: projectAwsWorkloadSpec(item?.spec), status: {
      availableReplicas: item?.status?.availableReplicas ?? 0,
      conditions: Array.isArray(item?.status?.conditions) ? item.status.conditions
        .filter(({ type }) => type === "Available").map(({ status, type }) => ({ status, type })) : undefined,
      observedGeneration: item?.status?.observedGeneration, readyReplicas: item?.status?.readyReplicas ?? 0,
      replicas: item?.status?.replicas ?? 0, unavailableReplicas: item?.status?.unavailableReplicas ?? 0,
      updatedReplicas: item?.status?.updatedReplicas ?? 0,
    } };
}

function projectAwsReplicaSet(item) {
  const metadata = projectAwsMetadata(item, ["labels", "name", "namespace", "ownerReferences", "resourceVersion", "uid"]);
  metadata.ownerReferences = projectAwsOwnerReferences(item?.metadata?.ownerReferences);
  return { apiVersion: item?.apiVersion, kind: item?.kind, metadata,
    spec: projectAwsWorkloadSpec(item?.spec), status: {
      availableReplicas: item?.status?.availableReplicas ?? 0,
      fullyLabeledReplicas: item?.status?.fullyLabeledReplicas ?? 0,
      observedGeneration: item?.status?.observedGeneration, readyReplicas: item?.status?.readyReplicas ?? 0,
      replicas: item?.status?.replicas ?? 0,
    } };
}

function projectAwsContainerStatus(value) {
  let state;
  if (value?.state?.running !== undefined) state = { running: { startedAt: value.state.running.startedAt } };
  else if (value?.state?.terminated !== undefined) state = { terminated: {
    containerID: value.state.terminated.containerID, exitCode: value.state.terminated.exitCode,
    finishedAt: value.state.terminated.finishedAt, reason: value.state.terminated.reason,
    startedAt: value.state.terminated.startedAt,
  } };
  else state = structuredClone(value?.state);
  return { containerID: value?.containerID, image: value?.image, imageID: value?.imageID,
    lastState: structuredClone(value?.lastState), name: value?.name, ready: value?.ready,
    restartCount: value?.restartCount, started: value?.started, state };
}

function projectAwsPod(item) {
  const metadata = projectAwsMetadata(item, ["labels", "name", "namespace", "ownerReferences", "resourceVersion", "uid"]);
  metadata.ownerReferences = projectAwsOwnerReferences(item?.metadata?.ownerReferences);
  return { apiVersion: item?.apiVersion, kind: item?.kind, metadata, spec: structuredClone(item?.spec), status: {
    conditions: Array.isArray(item?.status?.conditions) ? item.status.conditions
      .filter(({ type }) => type === "Ready").map(({ status, type }) => ({ status, type })) : undefined,
    containerStatuses: Array.isArray(item?.status?.containerStatuses)
      ? item.status.containerStatuses.map(projectAwsContainerStatus) : undefined,
    phase: item?.status?.phase, podIP: item?.status?.podIP,
  } };
}

function projectAwsService(item) {
  return { apiVersion: item?.apiVersion, kind: item?.kind,
    metadata: projectAwsMetadata(item, ["labels", "name", "namespace", "resourceVersion", "uid"]),
    spec: structuredClone(item?.spec), status: { loadBalancer: structuredClone(item?.status?.loadBalancer ?? {}) } };
}

function projectAwsEndpointSlice(item) {
  const metadata = projectAwsMetadata(item, ["labels", "name", "namespace", "ownerReferences", "resourceVersion", "uid"]);
  metadata.ownerReferences = projectAwsOwnerReferences(item?.metadata?.ownerReferences);
  return { addressType: item?.addressType, apiVersion: item?.apiVersion,
    endpoints: Array.isArray(item?.endpoints) ? item.endpoints.map((endpoint) => ({
      addresses: structuredClone(endpoint?.addresses), conditions: { ready: endpoint?.conditions?.ready,
        serving: endpoint?.conditions?.serving, terminating: endpoint?.conditions?.terminating ?? false },
      nodeName: endpoint?.nodeName, targetRef: { kind: endpoint?.targetRef?.kind,
        name: endpoint?.targetRef?.name, namespace: endpoint?.targetRef?.namespace, uid: endpoint?.targetRef?.uid },
    })) : [], kind: item?.kind, metadata,
    ports: Array.isArray(item?.ports) ? item.ports.map(({ name, port, protocol }) => ({ name, port, protocol })) : [] };
}

function projectAwsJob(item) {
  return { apiVersion: item?.apiVersion, kind: item?.kind,
    metadata: projectAwsMetadata(item, ["labels", "name", "namespace", "resourceVersion", "uid"]),
    spec: projectAwsWorkloadSpec(item?.spec), status: {
      completionTime: item?.status?.completionTime,
      conditions: Array.isArray(item?.status?.conditions) ? item.status.conditions
        .filter(({ type }) => type === "Complete" || type === "Failed").map((condition) => ({
          lastProbeTime: condition.lastProbeTime, lastTransitionTime: condition.lastTransitionTime,
          status: condition.status, type: condition.type,
        })) : undefined,
      failed: item?.status?.failed ?? 0, ready: item?.status?.ready ?? 0,
      startTime: item?.status?.startTime, succeeded: item?.status?.succeeded ?? 0,
    } };
}

function requireAwsEmulatorProviderAbsent(value) {
  try {
    requireExactKeys(value, [
      "configMaps", "deployments", "endpointSlices", "ingresses", "jobLog", "jobs", "pods", "replicaSets",
      "services",
    ]);
    if (value.jobLog !== null || [value.configMaps, value.deployments, value.endpointSlices, value.ingresses,
      value.jobs, value.pods, value.replicaSets, value.services]
      .some((items) => !plainArray(items) || items.length !== 0)) {
      throw new TypeError("AWS provider resources remain");
    }
    return true;
  } catch {
    throw new AwsEmulatorFailure("cleanup");
  }
}

function terminalAwsEmulatorProviderState(value, requireJob) {
  if (!isPlainObject(value) || !plainArray(value.jobs) || !plainArray(value.pods)) return true;
  const jobPods = value.pods.filter((pod) =>
    pod?.metadata?.labels?.["app.kubernetes.io/name"] === AWS_EMULATOR_CONSTANTS.s3JobName);
  const serverPods = value.pods.filter((pod) =>
    pod?.metadata?.labels?.["app.kubernetes.io/name"] === AWS_EMULATOR_CONSTANTS.localstackName);
  if (serverPods.length > 1 || value.jobs.length > 1 || jobPods.length > 1 ||
      value.pods.some((pod) => pod?.metadata?.deletionTimestamp !== undefined) ||
      value.pods.flatMap((pod) => pod?.status?.containerStatuses ?? []).some((status) =>
        status?.restartCount > 0 || status?.state?.terminated?.exitCode !== undefined &&
          status.state.terminated.exitCode !== 0)) return true;
  if (!requireJob) return value.jobs.length !== 0 || jobPods.length !== 0;
  return value.jobs.some((job) => job?.status?.failed > 0 || job?.status?.conditions?.some((condition) =>
    condition?.type === "Failed" && condition?.status === "True"));
}

function validateFailedAwsEmulatorKubernetesState(value, expected, retained, category) {
  try {
    requireExactKeys(value, [
      "configMaps", "deployments", "endpointSlices", "ingresses", "jobLog", "jobs", "pods", "replicaSets",
      "services",
    ]);
    if (!plainArray(value.jobs) || value.jobs.length !== 1 || !plainArray(value.pods) ||
        value.pods.length !== 2 || value.jobLog !== "") throw new TypeError("failed AWS collection is invalid");
    const serverPods = value.pods.filter((pod) =>
      pod?.metadata?.labels?.["app.kubernetes.io/name"] === AWS_EMULATOR_CONSTANTS.localstackName);
    const failedPods = value.pods.filter((pod) =>
      pod?.metadata?.labels?.["app.kubernetes.io/name"] === AWS_EMULATOR_CONSTANTS.s3JobName);
    if (serverPods.length !== 1 || failedPods.length !== 1) throw new TypeError("failed AWS pods are invalid");
    const core = validateAwsEmulatorKubernetesState({
      configMaps: value.configMaps, deployments: value.deployments, endpointSlices: value.endpointSlices,
      ingresses: value.ingresses, jobLog: null, jobs: [], pods: serverPods,
      replicaSets: value.replicaSets, services: value.services,
    }, expected, retained, false, category);
    const job = validateFailedAwsEmulatorJob(value.jobs[0], failedPods[0], expected);
    if (retained?.job !== null && retained?.job !== undefined && !isDeepStrictEqual(retained.job, job)) {
      throw new TypeError("failed AWS Job changed");
    }
    return deepFreeze({ ...core, job });
  } catch (error) {
    if (error instanceof Failure) throw error;
    throw new AwsEmulatorFailure(category);
  }
}

function validateFailedAwsEmulatorJob(job, pod, expected) {
  const resource = buildAwsEmulatorResources()[3];
  const jobUid = providerUid(job?.metadata?.uid);
  const podUid = providerUid(pod?.metadata?.uid);
  const jobVersion = providerVersion(job?.metadata?.resourceVersion);
  const podVersion = providerVersion(pod?.metadata?.resourceVersion);
  const podName = /^localstack-s3-probe-[a-z0-9]{5}$/.test(pod?.metadata?.name ?? "")
    ? pod.metadata.name : undefined;
  const status = pod?.status?.containerStatuses?.[0];
  const containerId = providerContainerId(status?.containerID);
  const startTime = providerTimestamp(job?.status?.startTime);
  const podStartedAt = providerTimestamp(status?.state?.terminated?.startedAt);
  const finishedAt = providerTimestamp(status?.state?.terminated?.finishedAt);
  const transitionTime = providerTimestamp(job?.status?.conditions?.[0]?.lastTransitionTime);
  const probeTime = providerTimestamp(job?.status?.conditions?.[0]?.lastProbeTime);
  const podIP = validPodAddress(pod?.status?.podIP) ? pod.status.podIP : undefined;
  const exitCode = status?.state?.terminated?.exitCode;
  if ([jobUid, podUid, jobVersion, podVersion, podName, containerId, startTime, podStartedAt, finishedAt,
    transitionTime, probeTime, podIP].some((item) => item === undefined) ||
      !Number.isSafeInteger(exitCode) || exitCode < 1 || exitCode > 255 ||
      !(Date.parse(startTime) <= Date.parse(podStartedAt) && Date.parse(podStartedAt) < Date.parse(finishedAt) &&
        Date.parse(finishedAt) <= Date.parse(transitionTime)) || probeTime !== transitionTime) {
    throw new TypeError("failed AWS Job identity is invalid");
  }
  const labels = { ...resource.spec.template.metadata.labels,
    "batch.kubernetes.io/controller-uid": jobUid,
    "batch.kubernetes.io/job-name": AWS_EMULATOR_CONSTANTS.s3JobName,
    "controller-uid": jobUid, "job-name": AWS_EMULATOR_CONSTANTS.s3JobName };
  const expectedJob = {
    apiVersion: "batch/v1", kind: "Job",
    metadata: { labels: structuredClone(resource.metadata.labels), name: AWS_EMULATOR_CONSTANTS.s3JobName,
      namespace: AWS_EMULATOR_CONSTANTS.namespace, resourceVersion: jobVersion, uid: jobUid },
    spec: { activeDeadlineSeconds: 30, backoffLimit: 0, completionMode: "NonIndexed", completions: 1,
      manualSelector: false, parallelism: 1, podReplacementPolicy: "Failed",
      selector: { matchLabels: { "batch.kubernetes.io/controller-uid": jobUid } }, suspend: false,
      template: providerAwsTemplate(resource.spec.template, labels), ttlSecondsAfterFinished: 60 },
    status: { completionTime: undefined, conditions: [{ lastProbeTime: probeTime,
      lastTransitionTime: transitionTime, status: "True", type: "Failed" }], failed: 1, ready: 0,
      startTime, succeeded: 0 },
  };
  const expectedPod = {
    apiVersion: "v1", kind: "Pod",
    metadata: { labels, name: podName, namespace: AWS_EMULATOR_CONSTANTS.namespace,
      ownerReferences: [{ apiVersion: "batch/v1", blockOwnerDeletion: true, controller: true,
        kind: "Job", name: AWS_EMULATOR_CONSTANTS.s3JobName, uid: jobUid }],
      resourceVersion: podVersion, uid: podUid },
    spec: providerAwsPodSpec(resource.spec.template, expected.nodeName),
    status: { conditions: [{ status: "False", type: "Ready" }], containerStatuses: [{
      containerID: containerId, image: expected.imageTarget.configDigest, imageID: expected.imageTarget.imageID,
      lastState: {}, name: "s3-probe", ready: false, restartCount: 0, started: false,
      state: { terminated: { containerID: containerId, exitCode, finishedAt, reason: "Error", startedAt: podStartedAt } },
    }], phase: "Failed", podIP },
  };
  if (!isDeepStrictEqual(job, expectedJob) || !isDeepStrictEqual(pod, expectedPod)) {
    throw new TypeError("failed AWS Job provider state is invalid");
  }
  return deepFreeze({ failed: true, finishedAt, jobUid, log: "", podName, podUid,
    providerJob: structuredClone(job), providerPod: structuredClone(pod) });
}

function validateAwsEmulatorJob(value, expected, resource) {
  const job = value.jobs[0];
  const pod = value.pods.find((item) =>
    item?.metadata?.labels?.["app.kubernetes.io/name"] === AWS_EMULATOR_CONSTANTS.s3JobName);
  const jobUid = providerUid(job?.metadata?.uid);
  const podUid = providerUid(pod?.metadata?.uid);
  const jobVersion = providerVersion(job?.metadata?.resourceVersion);
  const podVersion = providerVersion(pod?.metadata?.resourceVersion);
  const podName = /^localstack-s3-probe-[a-z0-9]{5}$/.test(pod?.metadata?.name ?? "")
    ? pod.metadata.name : undefined;
  const status = pod?.status?.containerStatuses?.[0];
  const containerId = providerContainerId(status?.containerID);
  const startTime = providerTimestamp(job?.status?.startTime);
  const completionTime = providerTimestamp(job?.status?.completionTime);
  const podStartedAt = providerTimestamp(status?.state?.terminated?.startedAt);
  const finishedAt = providerTimestamp(status?.state?.terminated?.finishedAt);
  const transitionTime = providerTimestamp(job?.status?.conditions?.[0]?.lastTransitionTime);
  const probeTime = providerTimestamp(job?.status?.conditions?.[0]?.lastProbeTime);
  const podIP = validPodAddress(pod?.status?.podIP) ? pod.status.podIP : undefined;
  if ([jobUid, podUid, jobVersion, podVersion, podName, containerId, startTime, completionTime, podStartedAt,
    finishedAt, transitionTime, probeTime, podIP].some((item) => item === undefined) ||
      !(Date.parse(startTime) <= Date.parse(podStartedAt) && Date.parse(podStartedAt) <= Date.parse(finishedAt) &&
        Date.parse(finishedAt) <= Date.parse(completionTime)) || transitionTime !== completionTime ||
      probeTime !== completionTime) throw new TypeError("AWS Job identity is invalid");
  const labels = {
    ...resource.spec.template.metadata.labels,
    "batch.kubernetes.io/controller-uid": jobUid,
    "batch.kubernetes.io/job-name": AWS_EMULATOR_CONSTANTS.s3JobName,
    "controller-uid": jobUid,
    "job-name": AWS_EMULATOR_CONSTANTS.s3JobName,
  };
  const expectedJob = {
    apiVersion: "batch/v1", kind: "Job",
    metadata: { labels: structuredClone(resource.metadata.labels), name: AWS_EMULATOR_CONSTANTS.s3JobName,
      namespace: AWS_EMULATOR_CONSTANTS.namespace, resourceVersion: jobVersion, uid: jobUid },
    spec: { activeDeadlineSeconds: 30, backoffLimit: 0, completionMode: "NonIndexed", completions: 1,
      manualSelector: false, parallelism: 1, podReplacementPolicy: "Failed",
      selector: { matchLabels: { "batch.kubernetes.io/controller-uid": jobUid } }, suspend: false,
      template: providerAwsTemplate(resource.spec.template, labels), ttlSecondsAfterFinished: 60 },
    status: { completionTime, conditions: [{ lastProbeTime: probeTime, lastTransitionTime: transitionTime,
      status: "True", type: "Complete" }], failed: 0, ready: 0, startTime, succeeded: 1 },
  };
  const expectedPod = {
    apiVersion: "v1", kind: "Pod",
    metadata: { labels, name: podName, namespace: AWS_EMULATOR_CONSTANTS.namespace,
      ownerReferences: [{ apiVersion: "batch/v1", blockOwnerDeletion: true, controller: true,
        kind: "Job", name: AWS_EMULATOR_CONSTANTS.s3JobName, uid: jobUid }],
      resourceVersion: podVersion, uid: podUid },
    spec: providerAwsPodSpec(resource.spec.template, expected.nodeName),
    status: { conditions: [{ status: "False", type: "Ready" }], containerStatuses: [{
      containerID: containerId, image: expected.imageTarget.configDigest, imageID: expected.imageTarget.imageID,
      lastState: {}, name: "s3-probe", ready: false, restartCount: 0, started: false,
      state: { terminated: { containerID: containerId, exitCode: 0, finishedAt, reason: "Completed", startedAt: podStartedAt } },
    }], phase: "Succeeded", podIP },
  };
  if (!isDeepStrictEqual(job, expectedJob) || !isDeepStrictEqual(pod, expectedPod)) {
    throw new TypeError("AWS Job provider state is invalid");
  }
  return deepFreeze({ completionTime, containerId, finishedAt, jobUid,
    log: `${AWS_EMULATOR_CONSTANTS.successMarker}\n`, podName, podUid,
    providerJob: structuredClone(job), providerPod: structuredClone(pod) });
}

function providerAwsContainer(value) {
  const projected = { ...structuredClone(value), terminationMessagePath: "/dev/termination-log",
    terminationMessagePolicy: "File" };
  if (Array.isArray(projected.volumeMounts)) projected.volumeMounts = projected.volumeMounts.map((mount) => {
    const item = { ...mount };
    if (item.readOnly === false) delete item.readOnly;
    return item;
  });
  return projected;
}

function providerAwsTemplate(template, labels = template.metadata.labels) {
  return { metadata: { creationTimestamp: null, labels: structuredClone(labels) }, spec: {
    ...structuredClone(template.spec), containers: template.spec.containers.map(providerAwsContainer),
    schedulerName: "default-scheduler",
  } };
}

function providerAwsPodSpec(template, nodeName) {
  return {
    automountServiceAccountToken: template.spec.automountServiceAccountToken,
    containers: template.spec.containers.map(providerAwsContainer),
    dnsPolicy: template.spec.dnsPolicy,
    enableServiceLinks: template.spec.enableServiceLinks,
    nodeName,
    preemptionPolicy: "PreemptLowerPriority",
    priority: 0,
    restartPolicy: template.spec.restartPolicy,
    schedulerName: "default-scheduler",
    securityContext: structuredClone(template.spec.securityContext),
    serviceAccount: "default",
    serviceAccountName: "default",
    terminationGracePeriodSeconds: template.spec.terminationGracePeriodSeconds,
    tolerations: [
      { effect: "NoExecute", key: "node.kubernetes.io/not-ready", operator: "Exists", tolerationSeconds: 300 },
      { effect: "NoExecute", key: "node.kubernetes.io/unreachable", operator: "Exists", tolerationSeconds: 300 },
    ],
    volumes: structuredClone(template.spec.volumes),
  };
}

function providerUid(value) {
  return typeof value === "string" && /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(value)
    ? value : undefined;
}

function providerVersion(value) {
  return typeof value === "string" && /^[1-9]\d{0,19}$/.test(value) ? value : undefined;
}

function providerContainerId(value) {
  return typeof value === "string" && /^containerd:\/\/[0-9a-f]{64}$/.test(value) ? value : undefined;
}

function providerTimestamp(value) {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(value) ||
      !Number.isFinite(Date.parse(value))) return undefined;
  return new Date(value).toISOString().replace(".000Z", "Z") === value ? value : undefined;
}

function validPodAddress(value) {
  if (typeof value !== "string") return false;
  const match = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(value);
  return match !== null && match.slice(1).every((item) => Number(item) <= 255) && value.startsWith("10.");
}

function validServiceAddress(value) {
  return validPodAddress(value) && value.startsWith("10.96.");
}

function plainArray(value) {
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype) return false;
  const keys = Reflect.ownKeys(value);
  const length = Object.getOwnPropertyDescriptor(value, "length");
  if (length === undefined || !("value" in length) || !Number.isSafeInteger(length.value) || length.value < 0 ||
      length.enumerable || keys.length !== length.value + 1 || keys[length.value] !== "length") return false;
  for (let index = 0; index < length.value; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (keys[index] !== String(index) || descriptor === undefined || !("value" in descriptor) ||
        !descriptor.enumerable) return false;
  }
  return true;
}

function requireLocalStackPlan(value) {
  if (!isPlainObject(value) || !isDeepStrictEqual(value, buildLocalStackImagePlan(value.platform))) {
    throw new TypeError("LocalStack plan is invalid");
  }
}

function requireExactKeys(value, keys) {
  if (!isPlainObject(value)) throw new TypeError("value is invalid");
  const actual = Reflect.ownKeys(value);
  if (actual.length !== keys.length || actual.some((key) => typeof key !== "string" || !keys.includes(key))) {
    throw new TypeError("value is invalid");
  }
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !("value" in descriptor) || !descriptor.enumerable) throw new TypeError("value is invalid");
  }
}

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype;
}

function deepFreeze(value) {
  if (value !== null && typeof value === "object" && !Object.isFrozen(value)) {
    for (const item of Object.values(value)) deepFreeze(item);
    Object.freeze(value);
  }
  return value;
}

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await runAwsEmulatorMain();
}
