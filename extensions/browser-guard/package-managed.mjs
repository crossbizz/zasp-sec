import { cp, mkdir, readFile, writeFile } from "node:fs/promises";
import { resolve, join } from "node:path";
import { fileURLToPath } from "node:url";

export async function packageManaged(raw, destination) {
  const api = new URL(raw);
  if (api.protocol !== "https:" || raw !== api.origin || api.username || api.password || ["https://claude.ai", "https://chatgpt.com"].includes(raw)) throw Error("Supply the exact HTTPS Zasp control-plane origin");
  const source = fileURLToPath(new URL("./extension/", import.meta.url));
  await mkdir(destination, { recursive: false });
  await cp(source, destination, { recursive: true });
  const manifestPath = join(destination, "manifest.json");
  const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
  manifest.host_permissions.push(api.origin + "/*");
  manifest.content_security_policy.extension_pages = manifest.content_security_policy.extension_pages.replace("connect-src 'none'", "connect-src " + api.origin);
  await writeFile(manifestPath, JSON.stringify(manifest, null, 2) + "\n");
  await writeFile(join(destination, "reporting-config.mjs"), "export const controlOrigin = " + JSON.stringify(api.origin) + ";\n");
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv.length !== 4) throw Error("Usage: node package-managed.mjs HTTPS_ORIGIN NEW_OUTPUT_DIRECTORY");
  await packageManaged(process.argv[2], resolve(process.argv[3]));
}
