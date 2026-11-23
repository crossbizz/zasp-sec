// Stage an immutable input directory for Microsoft's IntuneWinAppUtil. The
// installer and generated detection script verify Authenticode on Windows.
import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile, rm, stat } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));

export async function stage(binary, expectedDigest, thumbprint, output) {
  if (!/^[0-9a-f]{64}$/i.test(expectedDigest) || !/^[0-9a-f]{40}$/i.test(thumbprint)) {
    throw Error("Provide the approved release SHA-256 and Authenticode signer thumbprint");
  }
  const info = await stat(binary);
  if (!info.isFile() || info.size < 128 || info.size > 64 * 1024 * 1024) throw Error("Choose a bounded Windows CLI executable");
  const bytes = await readFile(binary);
  const pe = bytes.readUInt32LE(60);
  if (bytes.readUInt16LE(0) !== 0x5a4d || pe + 6 > bytes.length || bytes.readUInt32LE(pe) !== 0x4550) {
    throw Error("Expected a PE executable");
  }
  const machine = bytes.readUInt16LE(pe + 4);
  if (![0x8664, 0xaa64].includes(machine)) throw Error("Expected x64 or ARM64");
  const sha256 = createHash("sha256").update(bytes).digest("hex");
  if (sha256 !== expectedDigest.toLowerCase()) throw Error("Executable did not match approved release SHA-256");
  const signer = thumbprint.toUpperCase();
  const release = { schema_version:"zasp.intune-cli.v1", architecture:machine === 0xaa64 ? "arm64" : "x64", sha256, signer_thumbprint:signer };
  const installer = await readFile(join(here, "Manage-ZaspCli.ps1"));
  const detection = (await readFile(join(here, "Detect-ZaspCli.ps1.template"), "utf8"))
    .replace("__SHA256__", sha256).replace("__THUMBPRINT__", signer);
  // Never clobber an existing release folder, even on a failed retry.
  await mkdir(output, { mode: 0o700 });
  try {
    const input = join(output, "input");
    await mkdir(input, { mode: 0o700 });
    await writeFile(join(input,"zaspctl.exe"),bytes,{mode:0o600,flag:"wx"});
    await writeFile(join(input,"Manage-ZaspCli.ps1"),installer,{mode:0o600,flag:"wx"});
    await writeFile(join(input,"release.json"),JSON.stringify(release,null,2)+"\n",{mode:0o600,flag:"wx"});
    await writeFile(join(output,"Detect-ZaspCli.ps1"),detection,{mode:0o600,flag:"wx"});
  } catch (error) {
    await rm(output,{recursive:true,force:true});
    throw error;
  }
  return release;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv.length !== 6) {
    console.error("Usage: node stage.mjs SIGNED_EXE RELEASE_SHA256 SIGNER_THUMBPRINT NEW_DIRECTORY");
    process.exitCode=2;
  } else {
    try {
      const release = await stage(...process.argv.slice(2));
      console.log("Staged " + release.architecture + " CLI. Verify Authenticode and package with the approved Windows content prep tool.");
    } catch (error) { console.error(error.message); process.exitCode=1; }
  }
}
