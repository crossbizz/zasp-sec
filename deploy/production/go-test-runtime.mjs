// Keep the caller's installed compiler/cache usable without forwarding product
// credentials or allowing Go to fetch a toolchain or dependencies during proof.
export function goTestRuntime(environment = process.env) {
  const executable = environment.ZASP_GO_BIN ?? "go";
  if (typeof executable !== "string" || executable.length === 0 || executable !== executable.trim() || /[\r\n\0]/.test(executable)) throw new Error("invalid Go executable");
  const env = {};
  for (const key of ["PATH", "HOME", "GOCACHE", "GOPATH", "GOMODCACHE", "TMPDIR", "TMP", "TEMP", "SYSTEMROOT", "CC", "CXX", "CGO_ENABLED"]) {
    if (typeof environment[key] === "string") env[key] = environment[key];
  }
  return { executable, env: { ...env, GOTOOLCHAIN: "local", GOPROXY: "off", GOSUMDB: "off", GOENV: "off" } };
}

export function requireGoTestVersion(output) {
  if (output !== "go1.26.8\n" && output !== "go1.26.8\r\n") throw new Error("Go 1.26.8 is required for rendered runtime verification");
}
