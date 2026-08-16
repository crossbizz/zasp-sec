import { spawn } from "node:child_process";
import { isAbsolute, join, normalize } from "node:path";

import { PRODUCTS } from "./manifests.mjs";

export const SUCCESS_LINE = "Local product manifests passed: pods=4 ready=4 services=4 internal=true cleanup=true.";
export const FAILURE_CATEGORIES = Object.freeze([
  "build",
  "cleanup",
  "configuration",
  "deadline",
  "operation",
  "ownership",
  "panic",
  "provider",
  "readiness",
]);

const markerPattern = /^[0-9a-f]{16}$/;
const digestPattern = /^sha256:[0-9a-f]{64}$/;
const forbiddenEnvironmentPattern = /^(?:AWS_|AZURE_|GOOGLE_|CLOUDSDK_|KUBE(?:CONFIG|TOKEN)|DOCKER_HOST$|DOCKER_CONTEXT$|HTTP_PROXY$|HTTPS_PROXY$|ALL_PROXY$|NO_PROXY$)/i;

export class Failure extends Error {
  constructor(category = "operation", message = "local product operation failed") {
    super(message);
    this.name = "Failure";
    this.category = FAILURE_CATEGORIES.includes(category) ? category : "operation";
  }
}

export function buildServicePlan(product, paths, marker) {
  const expected = PRODUCTS.find((entry) => entry.name === product?.name);
  requireExactObject(product, ["image", "module", "name", "package"], "product");
  if (expected === undefined || !exactObject(product, expected)) throw new TypeError("product is invalid");
  requireExactObject(paths, [
    "contextRoot", "dockerConfig", "dockerfile", "goCache", "goModuleCache", "repositoryRoot",
  ], "build paths");
  for (const [name, value] of Object.entries(paths)) validateAbsolutePath(value, name);
  if (paths.dockerfile !== join(paths.repositoryRoot, "deploy/local/Dockerfile")) {
    throw new TypeError("Dockerfile path is invalid");
  }
  validateMarker(marker);

  const buildContext = join(paths.contextRoot, product.name);
  const binary = join(buildContext, "service");
  return Object.freeze({
    binary,
    buildContext,
    docker: Object.freeze({
      arguments: Object.freeze([
        "build", "--file", paths.dockerfile,
        "--build-arg", "BINARY=service",
        "--label", `zasp.dev/component=${product.name}`,
        "--label", "zasp.dev/proof=m1-30a",
        "--label", `zasp.dev/run=${marker}`,
        "--tag", product.image,
        buildContext,
      ]),
      command: "docker",
    }),
    go: Object.freeze({
      arguments: Object.freeze([
        "build", "-trimpath", "-ldflags=-s -w -X main.buildVersion=m1-30a",
        "-o", binary, product.package,
      ]),
      command: "go",
      cwd: join(paths.repositoryRoot, product.module),
      environment: Object.freeze({
        CGO_ENABLED: "0",
        GOCACHE: paths.goCache,
        GOENV: "off",
        GOMODCACHE: paths.goModuleCache,
        GOWORK: "off",
      }),
    }),
    image: product.image,
    name: product.name,
  });
}

export function buildChildEnvironment(hostEnvironment, paths) {
  try {
    if (!isPlainObject(hostEnvironment)) throw new TypeError("host environment is invalid");
    requireExactObject(paths, [
      "contextRoot", "dockerConfig", "dockerfile", "goCache", "goModuleCache", "repositoryRoot",
    ], "build paths");
    for (const [name, value] of Object.entries(paths)) validateAbsolutePath(value, name);
    for (const [name, value] of Object.entries(hostEnvironment)) {
      if (forbiddenEnvironmentPattern.test(name) && value !== undefined && value !== "") {
        throw new TypeError("host environment is invalid");
      }
    }
    validateAbsolutePath(hostEnvironment.HOME, "HOME");
    if (typeof hostEnvironment.PATH !== "string" || hostEnvironment.PATH.length === 0 ||
        hostEnvironment.PATH.length > 4096 || hostEnvironment.PATH.split(":").some((entry) => !safeAbsolutePath(entry))) {
      throw new TypeError("PATH is invalid");
    }
    return Object.freeze({
      DOCKER_CONFIG: paths.dockerConfig,
      HOME: hostEnvironment.HOME,
      LANG: "C.UTF-8",
      PATH: hostEnvironment.PATH,
    });
  } catch {
    throw new Failure("configuration");
  }
}

export function validateImageInspection(document, product, marker, platform, retained = undefined) {
  try {
    requireExactObject(product, ["image", "module", "name", "package"], "product");
    const expected = PRODUCTS.find((entry) => entry.name === product.name);
    if (expected === undefined || !exactObject(product, expected)) throw new TypeError("product is invalid");
    validateMarker(marker);
    if (!new Set(["linux/amd64", "linux/arm64"]).has(platform)) throw new TypeError("platform is invalid");
    if (!Array.isArray(document) || document.length !== 1) throw new TypeError("image inspection is invalid");
    const image = document[0];
    requireExactObject(image, ["Architecture", "Config", "Id", "Os", "RepoDigests", "RepoTags", "RootFS"], "image");
    requireExactObject(image.Config, [
      "AttachStderr", "AttachStdin", "AttachStdout", "Cmd", "Domainname", "Entrypoint", "Env",
      "ExposedPorts", "Healthcheck", "Hostname", "Image", "Labels", "OnBuild", "OpenStdin",
      "StdinOnce", "Tty", "User", "Volumes", "WorkingDir",
    ], "image config");
    requireExactObject(image.Config.Labels, ["zasp.dev/component", "zasp.dev/proof", "zasp.dev/run"], "image labels");
    requireExactObject(image.Config.ExposedPorts, ["8081/tcp"], "image ports");
    requireExactObject(image.Config.ExposedPorts["8081/tcp"], [], "image port");
    requireExactObject(image.RootFS, ["Layers", "Type"], "image rootfs");
    const architecture = platform.slice("linux/".length);
    if (
      image.Architecture !== architecture || image.Os !== "linux" || !digestPattern.test(image.Id) ||
      !Array.isArray(image.RepoDigests) || image.RepoDigests.length !== 0 ||
      !exactArray(image.RepoTags, [product.image]) || image.Config.AttachStderr !== false ||
      image.Config.AttachStdin !== false || image.Config.AttachStdout !== false || image.Config.Cmd !== null ||
      image.Config.Domainname !== "" || !exactArray(image.Config.Entrypoint, ["/service"]) ||
      image.Config.Env !== null || image.Config.Healthcheck !== null || image.Config.Hostname !== "" ||
      image.Config.Image !== "" || image.Config.OnBuild !== null || image.Config.OpenStdin !== false ||
      image.Config.StdinOnce !== false || image.Config.Tty !== false || image.Config.User !== "65532:65532" ||
      image.Config.Volumes !== null || image.Config.WorkingDir !== "" ||
      image.Config.Labels["zasp.dev/component"] !== product.name ||
      image.Config.Labels["zasp.dev/proof"] !== "m1-30a" || image.Config.Labels["zasp.dev/run"] !== marker ||
      image.RootFS.Type !== "layers" || !Array.isArray(image.RootFS.Layers) || image.RootFS.Layers.length !== 1 ||
      !digestPattern.test(image.RootFS.Layers[0])
    ) throw new TypeError("image inspection is invalid");
    if (retained !== undefined && (
      !isPlainObject(retained) || retained.id !== image.Id || retained.reference !== product.image ||
      retained.architecture !== architecture
    )) throw new TypeError("image identity changed");
    return Object.freeze({ architecture, id: image.Id, reference: product.image });
  } catch {
    throw new Failure("ownership");
  }
}

export function classifyMutationResult(result) {
  if (!isPlainObject(result)) return "ambiguous";
  if (result.thrown === true || result.timedOut === true || result.signal !== null) return "ambiguous";
  if (Number.isInteger(result.status) && result.status !== 0) return "definitive";
  if (result.status === 0 && result.signal === null && result.stdout === "" && result.stderr === "") return "applied";
  return "ambiguous";
}

export async function runBounded(command, arguments_, options, spawnProcess = spawn) {
  if (typeof command !== "string" || command.length === 0 || !Array.isArray(arguments_) ||
      !isPlainObject(options) || !isPlainObject(options.environment) ||
      !Number.isSafeInteger(options.outputLimit) || options.outputLimit < 1 ||
      !Number.isSafeInteger(options.timeoutMilliseconds) || options.timeoutMilliseconds < 1 ||
      typeof spawnProcess !== "function") throw new TypeError("process request is invalid");

  return await new Promise((resolve) => {
    let child;
    let stdout = Buffer.alloc(0);
    let stderr = Buffer.alloc(0);
    let closed = false;
    let thrown = false;
    let timedOut = false;
    let killed = false;
    let timer;

    const kill = () => {
      if (killed || child === undefined) return;
      killed = true;
      try { child.kill("SIGKILL"); } catch { thrown = true; }
    };
    const append = (kind, chunk) => {
      const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk));
      if (stdout.length + stderr.length + bytes.length > options.outputLimit) {
        thrown = true;
        kill();
        return;
      }
      if (kind === "stdout") stdout = Buffer.concat([stdout, bytes]);
      else stderr = Buffer.concat([stderr, bytes]);
    };
    const finish = (status, signal) => {
      if (closed) return;
      closed = true;
      clearTimeout(timer);
      resolve(Object.freeze({
        signal: signal ?? null,
        status: Number.isInteger(status) ? status : null,
        stderr: stderr.toString("utf8"),
        stdout: stdout.toString("utf8"),
        thrown,
        timedOut,
      }));
    };

    try {
      child = spawnProcess(command, arguments_, {
        cwd: options.cwd,
        env: options.environment,
        shell: false,
        stdio: ["ignore", "pipe", "pipe"],
      });
      child.stdout.on("data", (chunk) => append("stdout", chunk));
      child.stderr.on("data", (chunk) => append("stderr", chunk));
      child.stdout.on("error", () => { thrown = true; kill(); });
      child.stderr.on("error", () => { thrown = true; kill(); });
      child.on("error", () => { thrown = true; kill(); });
      child.once("close", finish);
      timer = setTimeout(() => {
        timedOut = true;
        kill();
      }, options.timeoutMilliseconds);
    } catch {
      thrown = true;
      finish(null, null);
    }
  });
}

function validateMarker(value) {
  if (typeof value !== "string" || !markerPattern.test(value)) throw new TypeError("marker is invalid");
}

function validateAbsolutePath(value, label) {
  if (!safeAbsolutePath(value)) throw new TypeError(`${label} is invalid`);
}

function safeAbsolutePath(value) {
  return typeof value === "string" && value.length > 1 && value.length <= 4096 &&
    isAbsolute(value) && normalize(value) === value && safePathCharacters(value);
}

function safePathCharacters(value) {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code <= 31 || code === 127) return false;
  }
  return true;
}

function requireExactObject(value, keys, label) {
  if (!isPlainObject(value)) throw new TypeError(`${label} is invalid`);
  const actual = Object.keys(value);
  if (actual.length !== keys.length || actual.some((key, index) => key !== keys[index])) {
    throw new TypeError(`${label} is invalid`);
  }
}

function exactObject(left, right) {
  return Object.keys(left).every((key) => left[key] === right[key]);
}

function exactArray(value, expected) {
  return Array.isArray(value) && value.length === expected.length &&
    value.every((item, index) => item === expected[index]);
}

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype;
}
