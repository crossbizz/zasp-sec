import pin from "./cli-release-pin.json";

export type CLIRelease = {
  version: string;
  commit: string;
  manifest_sha256: string;
  assets: Array<{ name: string; bytes: number; sha256: string }>;
};

const platforms = new Map([
  ["zaspctl-linux-amd64", "Linux x64"],
  ["zaspctl-darwin-arm64", "macOS Apple silicon"],
  ["zaspctl-darwin-amd64", "macOS Intel"],
  ["zaspctl-windows-amd64.exe", "Windows x64"],
]);
const sha256 = /^[a-f0-9]{64}$/;

export function CLIReleaseDownloads({ release = pin }: { release?: CLIRelease }) {
  const valid = /^v(?:0|[1-9]\d{0,7})\.(?:0|[1-9]\d{0,7})\.(?:0|[1-9]\d{0,7})$/.test(release.version)
    && /^(?:[a-f0-9]{40}|[a-f0-9]{64})$/.test(release.commit) && sha256.test(release.manifest_sha256)
    && release.assets.length > 0 && release.assets.length <= platforms.size
    && new Set(release.assets.map((a) => a.name)).size === release.assets.length
    && release.assets.every((a) => platforms.has(a.name) && sha256.test(a.sha256) && Number.isSafeInteger(a.bytes) && a.bytes > 0);
  if (!valid) return <p>This deployment currently offers the source build below.</p>;
  const root = `/downloads/zaspctl/${release.version}/`;
  return (
    <section aria-label="Signed CLI downloads">
      <h3>Download zaspctl {release.version}</h3>
      <ul>
        {release.assets.map((asset) => (
          <li key={asset.name}>
            <a href={root + asset.name} download={asset.name}>{platforms.get(asset.name)}</a>
            {" · "}{(asset.bytes / (1024 * 1024)).toFixed(1)} MiB
          </li>
        ))}
      </ul>
      <details>
        <summary>Verify your download</summary>
        <p>Download the <a href={root + "manifest.json"} download>manifest</a> and <a href={root + "manifest.ed25519"} download>signature</a>. Obtain the release public key from your administrator through your organization’s trusted channel. Verify the signature with OpenSSL 3.</p>
        <code>openssl pkeyutl -verify -pubin -inkey release-public.pem -rawin -in manifest.json -sigfile manifest.ed25519</code>
        <p>After the signature verifies, find your filename in the signed manifest and compare its SHA-256 with the downloaded file. On Linux use <code>sha256sum FILE</code>, on macOS use <code>shasum -a 256 FILE</code>, and on Windows use <code>Get-FileHash FILE -Algorithm SHA256</code>.</p>
        <dl>{release.assets.map((asset) => <div key={asset.name}><dt>{platforms.get(asset.name)}</dt><dd><code>{asset.sha256}</code></dd></div>)}</dl>
        <p>Manifest SHA-256 <code>{release.manifest_sha256}</code>. Source commit <code>{release.commit}</code>.</p>
      </details>
      <p>On Linux or macOS, make the verified file executable with <code>chmod +x FILE</code> and run <code>./FILE addons inventory --local --project .</code>. On Windows, run <code>{".\\zaspctl-windows-amd64.exe addons inventory --local --project ."}</code>.</p>
    </section>
  );
}
