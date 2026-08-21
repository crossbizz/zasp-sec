import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { test } from "node:test";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { dump } from "js-yaml";

import {
  failureLine,
  parseDependencyLock,
  readBoundedFile,
  runMain,
  successLine,
  validateDependencyState,
} from "./validate-dependencies.mjs";

const manifests = [
  { ecosystem: "npm", path: "apps/web/package.json" },
  { ecosystem: "go", path: "cmd/agentsecctl/go.mod" },
  { ecosystem: "npm", path: "package.json" },
  { ecosystem: "go", path: "services/event-ingest/go.mod" },
  { ecosystem: "go", path: "services/gateway-control/go.mod" },
  { ecosystem: "go", path: "services/health/go.mod" },
  { ecosystem: "go", path: "services/platform/go.mod" },
  { ecosystem: "go", path: "services/runtime-gateway/go.mod" },
  { ecosystem: "go", path: "services/sensor-agent/go.mod" },
  { ecosystem: "npm", path: "workers/redteam-node/package.json" },
  { ecosystem: "python", path: "workers/security-python/cartography/pyproject.toml" },
  { ecosystem: "python", path: "workers/security-python/prowler/pyproject.toml" },
  { ecosystem: "python", path: "workers/security-python/pyproject.toml" },
];

const cartographyLock = readFileSync(
  new URL("../workers/security-python/cartography/requirements.lock", import.meta.url),
  "utf8",
);
const buildLock = readFileSync(
  new URL("../workers/security-python/build-requirements.lock", import.meta.url),
  "utf8",
);
const prowlerLock = readFileSync(
  new URL("../workers/security-python/prowler/requirements.lock", import.meta.url),
  "utf8",
);

const npmDependencies = [
  ["drizzle-orm", "0.45.2", "Apache-2.0", "platform-data"],
  ["lucide-react", "1.31.0", "ISC", "web-platform"],
  ["openapi-fetch", "0.17.0", "MIT", "web-platform"],
  ["react", "19.2.6", "MIT", "web-platform"],
  ["react-dom", "19.2.6", "MIT", "web-platform"],
  ["stytch", "14.2.0", "MIT", "identity-platform"],
  ["vinext", "1.0.0-beta.2", "MIT", "web-platform"],
].map(([name, version, license, owner]) => ({
  ecosystem: "npm",
  manifest: "package.json",
  name,
  version,
  license,
  owner,
  scope: "runtime",
  review: "approved",
}));

const awsDependencies = [
  ["github.com/aws/aws-sdk-go-v2", "v1.43.6"],
  ["github.com/aws/aws-sdk-go-v2/service/kms", "v1.55.6"],
  ["github.com/aws/aws-sdk-go-v2/service/opensearch", "v1.75.6"],
  ["github.com/aws/aws-sdk-go-v2/service/s3", "v1.107.2"],
  ["github.com/aws/aws-sdk-go-v2/service/secretsmanager", "v1.44.6"],
  ["github.com/aws/aws-sdk-go-v2/service/sqs", "v1.46.6"],
  ["github.com/aws/aws-sdk-go-v2/service/sts", "v1.41.6"],
].map(([name, version]) => ({
  ecosystem: "go",
  manifest: "services/platform/go.mod",
  name,
  version,
  license: "Apache-2.0",
  owner: "platform-data",
  scope: "runtime",
  review: "approved",
}));

const policyDependencies = [
  {
    ecosystem: "go",
    manifest: "services/platform/go.mod",
    name: "github.com/open-policy-agent/opa",
    version: "v1.17.0",
    license: "Apache-2.0",
    owner: "platform-data",
    scope: "runtime",
    review: "approved",
  },
];

const platformDependencies = [
  ["github.com/jackc/pgx/v5", "v5.10.0", "MIT"],
  ["github.com/neo4j/neo4j-go-driver/v6", "v6.2.0", "Apache-2.0"],
  ["gopkg.in/yaml.v3", "v3.0.1", "MIT"],
].map(([name, version, license]) => ({
  ecosystem: "go",
  manifest: "services/platform/go.mod",
  name,
  version,
  license,
  owner: "platform-data",
  scope: "runtime",
  review: "approved",
}));

const eventIngestDependencies = [
  ["github.com/aws/aws-sdk-go-v2", "v1.43.6", "Apache-2.0"],
  ["github.com/aws/aws-sdk-go-v2/service/kms", "v1.55.6", "Apache-2.0"],
  ["github.com/aws/aws-sdk-go-v2/service/s3", "v1.107.2", "Apache-2.0"],
  ["github.com/aws/aws-sdk-go-v2/service/sts", "v1.41.6", "Apache-2.0"],
  ["github.com/jackc/pgx/v5", "v5.10.0", "MIT"],
].map(([name, version, license]) => ({
  ecosystem: "go",
  manifest: "services/event-ingest/go.mod",
  name,
  version,
  license,
  owner: "platform-data",
  scope: "runtime",
  review: "approved",
}));

const gatewayDependencies = [{
  ecosystem: "go",
  manifest: "services/gateway-control/go.mod",
  name: "github.com/jackc/pgx/v5",
  version: "v5.10.0",
  license: "MIT",
  owner: "platform-data",
  scope: "runtime",
  review: "approved",
}];

const runtimeGatewayDependencies = [{
  ecosystem: "go",
  manifest: "services/runtime-gateway/go.mod",
  name: "github.com/dgraph-io/badger/v4",
  version: "v4.9.1",
  license: "Apache-2.0",
  owner: "platform-data",
  scope: "runtime",
  review: "approved",
}];

const sensorDependencies = ["api", "apimachinery", "client-go"].map((name) => ({
  ecosystem: "go",
  manifest: "services/sensor-agent/go.mod",
  name: `k8s.io/${name}`,
  version: "v0.35.5",
  license: "Apache-2.0",
  owner: "platform-data",
  scope: "runtime",
  review: "approved",
}));

const securityRuntimeDependencies = [
  {
    ecosystem: "python",
    manifest: "workers/security-python/cartography/pyproject.toml",
    name: "cartography",
    version: "0.139.1",
    license: "Apache-2.0",
    owner: "platform-data",
    scope: "runtime",
    review: "approved",
  },
  {
    ecosystem: "python",
    manifest: "workers/security-python/prowler/pyproject.toml",
    name: "prowler",
    version: "5.39.1",
    license: "Apache-2.0",
    owner: "platform-data",
    scope: "runtime",
    review: "approved",
  },
];

const dependencies = [
  ...npmDependencies,
  ...eventIngestDependencies,
  ...gatewayDependencies,
  ...awsDependencies,
  ...policyDependencies,
  ...platformDependencies,
  ...runtimeGatewayDependencies,
  ...sensorDependencies,
  ...securityRuntimeDependencies,
].sort((left, right) =>
  `${left.manifest}:${left.name}`.localeCompare(`${right.manifest}:${right.name}`),
);

function lockFixture() {
  return {
    schema_version: 1,
    policy: {
      approved_owners: ["identity-platform", "platform-data", "web-platform"],
      allowed_licenses: ["Apache-2.0", "ISC", "MIT"],
      prohibited_licenses: [
        "AGPL-3.0-only",
        "GPL-2.0-only",
        "GPL-3.0-only",
        "LGPL-2.1-only",
        "LGPL-3.0-only",
        "SSPL-1.0",
      ],
    },
    manifests: structuredClone(manifests),
    dependencies: structuredClone(dependencies),
  };
}

function filesFixture() {
  const rootDependencies = Object.fromEntries(npmDependencies.map(({ name, version }) => [name, version]));
  return {
    "package.json": JSON.stringify({ dependencies: rootDependencies }),
    "package-lock.json": JSON.stringify({
      lockfileVersion: 3,
      packages: {
        "": { dependencies: rootDependencies },
        ...Object.fromEntries(
          npmDependencies.map(({ name, version, license }) => [`node_modules/${name}`, { version, license }]),
        ),
      },
    }),
    "apps/web/package.json": JSON.stringify({ name: "@zasp/web" }),
    "workers/redteam-node/package.json": JSON.stringify({ name: "@zasp/redteam-worker" }),
    "workers/security-python/build-requirements.lock": buildLock,
    "workers/security-python/cartography/pyproject.toml": [
      "[project]",
      'name = "zasp-security-cartography-runtime"',
      'dependencies = ["cartography==0.139.1"]',
      "",
    ].join("\n"),
    "workers/security-python/cartography/requirements.lock": cartographyLock,
    "workers/security-python/prowler/pyproject.toml": [
      "[project]",
      'name = "zasp-security-prowler-runtime"',
      'dependencies = ["prowler==5.39.1"]',
      "",
    ].join("\n"),
    "workers/security-python/prowler/requirements.lock": prowlerLock,
    "workers/security-python/pyproject.toml": [
      "[project]",
      'name = "zasp-security-worker"',
      "dependencies = []",
      "",
    ].join("\n"),
    "services/event-ingest/go.mod": [
      "module github.com/zasp-ai/zasp-sec/services/event-ingest",
      "",
      "go 1.25.0",
      "",
      "require (",
      ...eventIngestDependencies.map(({ name, version }) => `\t${name} ${version}`),
      "\tgithub.com/zasp-ai/zasp-sec/services/health v0.0.0",
      "\tgithub.com/zasp-ai/zasp-sec/services/platform v0.0.0",
      ")",
      "",
      "replace github.com/zasp-ai/zasp-sec/services/health => ../health",
      "",
      "replace github.com/zasp-ai/zasp-sec/services/platform => ../platform",
      "",
    ].join("\n"),
    "services/gateway-control/go.mod": [
      "module github.com/zasp-ai/zasp-sec/services/gateway-control",
      "",
      "go 1.25.0",
      "",
      "require (",
      ...gatewayDependencies.map(({ name, version }) => `\t${name} ${version}`),
      "\tgithub.com/zasp-ai/zasp-sec/services/platform v0.0.0",
      "\tgithub.com/zasp-ai/zasp-sec/services/health v0.0.0 // indirect",
      ")",
      "",
      "replace github.com/zasp-ai/zasp-sec/services/health => ../health",
      "",
      "replace github.com/zasp-ai/zasp-sec/services/platform => ../platform",
      "",
    ].join("\n"),
    "services/health/go.mod": "module github.com/zasp-ai/zasp-sec/services/health\n\ngo 1.25.0\n",
    "services/platform/go.mod": [
      "module github.com/zasp-ai/zasp-sec/services/platform",
      "",
      "go 1.25.0",
      "",
      "require (",
      ...awsDependencies.map(({ name, version }) => `\t${name} ${version}`),
      ...policyDependencies.map(({ name, version }) => `\t${name} ${version}`),
      ...platformDependencies.map(({ name, version }) => `\t${name} ${version}`),
      "\tgithub.com/zasp-ai/zasp-sec/services/health v0.0.0",
      ")",
      "",
      "replace github.com/zasp-ai/zasp-sec/services/health => ../health",
      "",
    ].join("\n"),
    "services/runtime-gateway/go.mod": [
      "module github.com/zasp-ai/zasp-sec/services/runtime-gateway",
      "",
      "go 1.25.0",
      "",
      "require github.com/zasp-ai/zasp-sec/services/health v0.0.0",
      "require github.com/zasp-ai/zasp-sec/services/platform v0.0.0",
      `require ${runtimeGatewayDependencies[0].name} ${runtimeGatewayDependencies[0].version}`,
      "require github.com/google/flatbuffers v25.2.10+incompatible // indirect",
      "",
      "replace github.com/zasp-ai/zasp-sec/services/health => ../health",
      "",
      "replace github.com/zasp-ai/zasp-sec/services/platform => ../platform",
      "",
    ].join("\n"),
    "services/sensor-agent/go.mod": [
      "module github.com/zasp-ai/zasp-sec/services/sensor-agent",
      "",
      "go 1.25.0",
      "",
      "require (",
      "\tgithub.com/zasp-ai/zasp-sec/services/health v0.0.0",
      "\tgithub.com/zasp-ai/zasp-sec/services/platform v0.0.0",
      ...sensorDependencies.map(({ name, version }) => `\t${name} ${version}`),
      ")",
      "",
      "replace github.com/zasp-ai/zasp-sec/services/health => ../health",
      "",
      "replace github.com/zasp-ai/zasp-sec/services/platform => ../platform",
      "",
    ].join("\n"),
    "cmd/agentsecctl/go.mod": "module example/agentsecctl\n\ngo 1.25.0\n",
  };
}

function validate(lock = lockFixture(), files = filesFixture()) {
  return validateDependencyState({ lockText: dump(lock, { noRefs: true }), files });
}

test("accepts the exact reviewed product runtime inventory", () => {
  assert.deepEqual(validate(), { manifests: 13, dependencies: 30 });
});

test("binds exact hash-locked isolated Cartography and Prowler runtimes", async (t) => {
  for (const dependency of securityRuntimeDependencies) {
    await t.test(dependency.name, () => {
      const retained = lockFixture().dependencies.find(
        ({ manifest, name }) => manifest === dependency.manifest && name === dependency.name,
      );
      assert.deepEqual(retained, dependency);
    });
  }
  for (const [name, mutate] of [
    ["cartography lock byte drift", (files) => {
      files["workers/security-python/cartography/requirements.lock"] += "# drift\n";
    }],
    ["prowler lock byte drift", (files) => {
      files["workers/security-python/prowler/requirements.lock"] = files[
        "workers/security-python/prowler/requirements.lock"
      ].replace("prowler==5.39.1", "prowler==5.39.0");
    }],
    ["missing runtime lock", (files) => {
      delete files["workers/security-python/cartography/requirements.lock"];
    }],
    ["build tool lock drift", (files) => {
      files["workers/security-python/build-requirements.lock"] += "# drift\n";
    }],
  ]) {
    await t.test(name, () => {
      const files = filesFixture();
      mutate(files);
      assert.throws(() => validate(lockFixture(), files));
    });
  }
});

test("binds the exact seven AWS SDK product dependencies", async (t) => {
  assert.deepEqual(
    lockFixture().dependencies.filter(
      ({ manifest, name }) => manifest === "services/platform/go.mod" && name.startsWith("github.com/aws/aws-sdk-go-v2"),
    ),
    awsDependencies,
  );

  for (const [name, mutate] of [
    ["missing", (lock) => lock.dependencies.splice(lock.dependencies.findIndex(
      (entry) => entry.manifest === "services/platform/go.mod" && entry.name === awsDependencies[0].name,
    ), 1)],
    ["version drift", (lock) => {
      lock.dependencies.find((entry) => entry.manifest === "services/platform/go.mod" && entry.name === awsDependencies[0].name).version = "v1.43.5";
    }],
    ["prohibited license", (lock) => {
      lock.dependencies.find((entry) => entry.manifest === "services/platform/go.mod" && entry.name === awsDependencies[0].name).license = "GPL-3.0-only";
    }],
    ["wrong owner", (lock) => {
      lock.dependencies.find((entry) => entry.manifest === "services/platform/go.mod" && entry.name === awsDependencies[0].name).owner = "web-platform";
    }],
    ["wrong scope", (lock) => {
      lock.dependencies.find((entry) => entry.manifest === "services/platform/go.mod" && entry.name === awsDependencies[0].name).scope = "development";
    }],
  ]) {
    await t.test(name, () => {
      const lock = lockFixture();
      mutate(lock);
      assert.throws(() => validate(lock));
    });
  }

  await t.test("extra direct SDK module", () => {
    const files = filesFixture();
    files["services/platform/go.mod"] = files["services/platform/go.mod"].replace(
      "\n)",
      "\n\tgithub.com/aws/aws-sdk-go-v2/service/sns v1.39.3\n)",
    );
    assert.throws(() => validate(lockFixture(), files));
  });
});

test("binds the exact OPA product runtime dependency", async (t) => {
  const retained = lockFixture().dependencies.filter(({ name }) => name === "github.com/open-policy-agent/opa");
  assert.deepEqual(retained, policyDependencies);
  for (const [name, mutate] of [
    ["version drift", (entry) => { entry.version = "v1.16.0"; }],
    ["license drift", (entry) => { entry.license = "MIT"; }],
    ["owner drift", (entry) => { entry.owner = "web-platform"; }],
  ]) {
    await t.test(name, () => {
      const lock = lockFixture();
      mutate(lock.dependencies.find((entry) => entry.name === "github.com/open-policy-agent/opa"));
      assert.throws(() => validate(lock));
    });
  }
});

test("binds exact metadata for every newly reviewed service dependency", async (t) => {
  for (const { manifest, name } of [
    ...eventIngestDependencies,
    ...gatewayDependencies,
    ...runtimeGatewayDependencies,
    ...sensorDependencies,
  ]) {
    await t.test(`${manifest}:${name}`, () => {
      const lock = lockFixture();
      const entry = lock.dependencies.find((candidate) => candidate.manifest === manifest && candidate.name === name);
      entry.owner = "web-platform";
      assert.throws(() => validate(lock));
    });
  }
});

test("rejects YAML aliases, duplicate keys, and oversized input", async (t) => {
  await t.test("alias", () => {
    assert.throws(() => parseDependencyLock("schema_version: &version 1\ncopy: *version\n"));
  });
  await t.test("duplicate key", () => {
    assert.throws(() => parseDependencyLock("schema_version: 1\nschema_version: 1\n"));
  });
  await t.test("oversized", () => {
    assert.throws(() => parseDependencyLock(`schema_version: 1\npad: ${"x".repeat(65_536)}\n`));
  });
});

test("requires exact schema keys and sorted unique inventory", async (t) => {
  await t.test("unknown top-level key", () => {
    const lock = lockFixture();
    lock.extra = true;
    assert.throws(() => validate(lock));
  });
  await t.test("missing dependency field", () => {
    const lock = lockFixture();
    delete lock.dependencies[0].owner;
    assert.throws(() => validate(lock));
  });
  await t.test("unsorted dependencies", () => {
    const lock = lockFixture();
    lock.dependencies.reverse();
    assert.throws(() => validate(lock));
  });
  await t.test("duplicate dependency", () => {
    const lock = lockFixture();
    lock.dependencies.push(structuredClone(lock.dependencies.at(-1)));
    assert.throws(() => validate(lock));
  });
  await t.test("manifest inventory drift", () => {
    const lock = lockFixture();
    lock.manifests.pop();
    assert.throws(() => validate(lock));
  });
  await t.test("new product manifest", () => {
    const files = filesFixture();
    files["workers/new-runtime/package.json"] = JSON.stringify({ dependencies: { unreviewed: "1.0.0" } });
    assert.throws(() => validate(lockFixture(), files));
  });
});

test("rejects non-exact versions, unknown owners, unreviewed runtime, and copyleft", async (t) => {
  for (const [name, mutate] of [
    ["version", (entry) => { entry.version = "^0.45.2"; }],
    ["owner", (entry) => { entry.owner = "unknown-team"; }],
    ["review", (entry) => { entry.review = "pending"; }],
    ["scope", (entry) => { entry.scope = "development"; }],
    ["copyleft", (entry, lock) => {
      entry.license = "GPL-3.0-only";
      lock.policy.allowed_licenses.push("GPL-3.0-only");
    }],
  ]) {
    await t.test(name, () => {
      const lock = lockFixture();
      mutate(lock.dependencies[0], lock);
      assert.throws(() => validate(lock));
    });
  }
});

test("rejects missing, extra, version-drifted, and license-drifted npm runtime state", async (t) => {
  await t.test("non-JSON package manifest", () => {
    const files = filesFixture();
    files["package.json"] = files["package.json"].replace(/}$/, ",}");
    assert.throws(() => validate(lockFixture(), files));
  });
  await t.test("manifest addition", () => {
    const files = filesFixture();
    const manifest = JSON.parse(files["package.json"]);
    manifest.dependencies.unreviewed = "1.0.0";
    files["package.json"] = JSON.stringify(manifest);
    assert.throws(() => validate(lockFixture(), files));
  });
  await t.test("stale lock entry", () => {
    const files = filesFixture();
    const manifest = JSON.parse(files["package.json"]);
    delete manifest.dependencies.stytch;
    files["package.json"] = JSON.stringify(manifest);
    assert.throws(() => validate(lockFixture(), files));
  });
  await t.test("resolved version drift", () => {
    const files = filesFixture();
    const packageLock = JSON.parse(files["package-lock.json"]);
    packageLock.packages["node_modules/react"].version = "19.2.5";
    files["package-lock.json"] = JSON.stringify(packageLock);
    assert.throws(() => validate(lockFixture(), files));
  });
  await t.test("resolved license drift", () => {
    const files = filesFixture();
    const packageLock = JSON.parse(files["package-lock.json"]);
    packageLock.packages["node_modules/react"].license = "GPL-3.0-only";
    files["package-lock.json"] = JSON.stringify(packageLock);
    assert.throws(() => validate(lockFixture(), files));
  });
});

test("tracks direct Go and Python requirements while ignoring development and indirect state", () => {
  const lock = lockFixture();
  const files = filesFixture();
  files["services/platform/go.mod"] += [
    "",
    "require (",
    "\texample.com/direct v1.2.3",
    "\texample.com/indirect v1.0.0 // indirect",
    ")",
    "",
  ].join("\n");
  files["workers/security-python/pyproject.toml"] = [
    "[project]",
    'name = "zasp-security-worker"',
    'dependencies = ["example-python==2.3.4"]',
    "",
    "[project.optional-dependencies]",
    'test = ["ignored==1.0.0"]',
    "",
  ].join("\n");
  lock.dependencies.push(
    {
      ecosystem: "go",
      manifest: "services/platform/go.mod",
      name: "example.com/direct",
      version: "v1.2.3",
      license: "MIT",
      owner: "platform-data",
      scope: "runtime",
      review: "approved",
    },
    {
      ecosystem: "python",
      manifest: "workers/security-python/pyproject.toml",
      name: "example-python",
      version: "2.3.4",
      license: "MIT",
      owner: "platform-data",
      scope: "runtime",
      review: "approved",
    },
  );
  lock.dependencies.sort((left, right) => `${left.manifest}:${left.name}`.localeCompare(`${right.manifest}:${right.name}`));

  assert.deepEqual(validate(lock, files), { manifests: 13, dependencies: 32 });
});

test("accepts only exact repository-owned module requirements and replacements outside the third-party lock", async (t) => {
  assert.deepEqual(validate(lockFixture(), filesFixture()), { manifests: 13, dependencies: 30 });

  for (const [name, mutate] of [
    ["missing health replacement", (files) => {
      files["services/platform/go.mod"] = files["services/platform/go.mod"].replace(
        "\nreplace github.com/zasp-ai/zasp-sec/services/health => ../health\n",
        "\n",
      );
    }],
    ["missing platform replacement", (files) => {
      files["services/event-ingest/go.mod"] = files["services/event-ingest/go.mod"].replace(
        "\nreplace github.com/zasp-ai/zasp-sec/services/platform => ../platform\n",
        "\n",
      );
    }],
    ["wrong replacement target", (files) => {
      files["services/platform/go.mod"] = files["services/platform/go.mod"].replace("=> ../health", "=> ../../services/health");
    }],
    ["wrong internal version", (files) => {
      files["services/platform/go.mod"] = files["services/platform/go.mod"].replace("v0.0.0", "v0.0.1");
    }],
    ["wrong target module", (files) => {
      files["services/health/go.mod"] = files["services/health/go.mod"].replace("services/health", "services/health-copy");
    }],
    ["wrong platform target module", (files) => {
      files["services/platform/go.mod"] = files["services/platform/go.mod"].replace(
        "module github.com/zasp-ai/zasp-sec/services/platform",
        "module github.com/zasp-ai/zasp-sec/services/platform-copy",
      );
    }],
    ["remote replacement", (files) => {
      files["services/platform/go.mod"] = files["services/platform/go.mod"].replace("../health", "github.com/example/health v1.0.0");
    }],
    ["extra replacement", (files) => {
      files["services/platform/go.mod"] += "replace example.com/other => ../other\n";
    }],
    ["alternate consumer indirect requirement", (files) => {
      files["cmd/agentsecctl/go.mod"] +=
        "require github.com/zasp-ai/zasp-sec/services/health v0.0.0 // indirect\n";
    }],
    ["unexpected runtime-gateway indirect health requirement", (files) => {
      files["services/runtime-gateway/go.mod"] = files["services/runtime-gateway/go.mod"].replace(
        "github.com/zasp-ai/zasp-sec/services/health v0.0.0",
        "github.com/zasp-ai/zasp-sec/services/health v0.0.0 // indirect",
      );
    }],
    ["event-ingest indirect requirement", (files) => {
      files["services/event-ingest/go.mod"] = files["services/event-ingest/go.mod"].replace(
        "github.com/zasp-ai/zasp-sec/services/health v0.0.0",
        "github.com/zasp-ai/zasp-sec/services/health v0.0.0 // indirect",
      );
    }],
    ["platform indirect requirement", (files) => {
      files["services/platform/go.mod"] = files["services/platform/go.mod"].replace(
        "github.com/zasp-ai/zasp-sec/services/health v0.0.0",
        "github.com/zasp-ai/zasp-sec/services/health v0.0.0 // indirect",
      );
    }],
    ["unexpected gateway direct health requirement", (files) => {
      files["services/gateway-control/go.mod"] = files["services/gateway-control/go.mod"].replace(
        "github.com/zasp-ai/zasp-sec/services/health v0.0.0 // indirect",
        "github.com/zasp-ai/zasp-sec/services/health v0.0.0",
      );
    }],
    ["sensor platform requirement becomes indirect", (files) => {
      files["services/sensor-agent/go.mod"] = files["services/sensor-agent/go.mod"].replace(
        "github.com/zasp-ai/zasp-sec/services/platform v0.0.0",
        "github.com/zasp-ai/zasp-sec/services/platform v0.0.0 // indirect",
      );
    }],
  ]) {
    await t.test(name, () => {
      const files = filesFixture();
      mutate(files);
      assert.throws(() => validate(lockFixture(), files));
    });
  }
});

test("does not silently ignore alternate direct dependency assignment syntax", async (t) => {
  await t.test("Go tab separator", () => {
    const files = filesFixture();
    files["services/platform/go.mod"] += "\nrequire\texample.com/unreviewed\tv1.2.3\n";
    assert.throws(() => validate(lockFixture(), files));
  });
  await t.test("Python trailing comment", () => {
    const files = filesFixture();
    files["workers/security-python/pyproject.toml"] = [
      "[project]",
      'name = "zasp-security-worker"',
      'dependencies = ["unreviewed==1.2.3"] # runtime',
      "",
    ].join("\n");
    assert.throws(() => validate(lockFixture(), files));
  });
});

test("bounds repository file reads and rejects symlinked inputs", async () => {
  const directory = await mkdtemp(join(tmpdir(), "zasp-m1-02-"));
  try {
    const regular = join(directory, "regular.txt");
    const oversized = join(directory, "oversized.txt");
    const link = join(directory, "link.txt");
    await writeFile(regular, "safe", { encoding: "utf8", mode: 0o600 });
    await writeFile(oversized, "unsafe", { encoding: "utf8", mode: 0o600 });
    await symlink(regular, link);

    assert.equal(await readBoundedFile(regular, 4), "safe");
    await assert.rejects(readBoundedFile(oversized, 4));
    await assert.rejects(readBoundedFile(link, 4));
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("contains failures behind fixed CLI output and rejects arguments before validation", async () => {
  let stdout = "";
  let stderr = "";
  let exitCode;
  let calls = 0;
  const io = {
    stdout: { write: (value) => { stdout += value; } },
    stderr: { write: (value) => { stderr += value; } },
    setExitCode: (value) => { exitCode = value; },
    validateRepository: async () => {
      calls += 1;
      throw new Error("sensitive dependency payload");
    },
  };

  assert.equal(await runMain([], io), 1);
  assert.equal(calls, 1);
  assert.equal(stdout, "");
  assert.equal(stderr, `${failureLine}\n`);
  assert.equal(exitCode, 1);
  assert.equal(stderr.includes("sensitive dependency payload"), false);

  stdout = "";
  stderr = "";
  exitCode = undefined;
  calls = 0;
  assert.equal(await runMain(["unexpected"], io), 1);
  assert.equal(calls, 0);
  assert.equal(stderr, `${failureLine}\n`);
});

test("prints one exact success line", async () => {
  let stdout = "";
  let stderr = "";
  let exitCode;
  const code = await runMain([], {
    stdout: { write: (value) => { stdout += value; } },
    stderr: { write: (value) => { stderr += value; } },
    setExitCode: (value) => { exitCode = value; },
    validateRepository: async () => ({ manifests: 9, dependencies: 12 }),
  });

  assert.equal(code, 0);
  assert.equal(exitCode, 0);
  assert.equal(stdout, `${successLine}\n`);
  assert.equal(stderr, "");
});
