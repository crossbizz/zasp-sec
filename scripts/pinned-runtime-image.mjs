// Inspect locally before contacting a registry. Only Docker's exact missing-image
// response permits a download; daemon and permission failures remain failures.
// Deliberately limited to the harness's lowercase repository names, optional
// tags and SHA256 digests. Registry ports and IPv6 literals aren't supported.
const component = "[a-z0-9]+(?:[._-][a-z0-9]+)*";
const pinnedReference = new RegExp(`^${component}(?:/${component})*(?::[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?@sha256:[a-f0-9]{64}$`);
export async function preparePinnedRuntimeImage(command, image) {
  if (typeof command !== "function" || typeof image !== "string" ||
      !pinnedReference.test(image) || /\s/.test(image)) {
    throw new Error("pinned image rejected");
  }
  const inspect = () => command("docker", ["image", "inspect", "--format", "{{.Architecture}}", image], { timeout: 10_000, reject: false });
  let result = await inspect();
  if (result.status !== 0) {
    const diagnostic = (result.stderr ?? "").trim();
    if (![ `No such image: ${image}`, `Error response from daemon: No such image: ${image}` ].includes(diagnostic)) {
      throw new Error("pinned image inspection failed");
    }
    const pulled = await command("docker", ["pull", image], { timeout: 120_000, reject: false });
    if (pulled.status !== 0) throw new Error("pinned image pull failed");
    result = await inspect();
  }
  if (result.status !== 0) throw new Error("pinned image inspection failed");
  const architecture = result.stdout?.trim();
  if (!["arm64", "amd64"].includes(architecture)) throw new Error("pinned image architecture rejected");
  return architecture;
}
