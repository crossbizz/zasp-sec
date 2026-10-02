// Render is read-only to the cluster. Deploy requires operator-created secrets,
// private DNS/databases/network policy and an explicit --deploy argument.
import { mkdtemp, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { resolve, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';

const directory = dirname(fileURLToPath(import.meta.url));
const mode = process.argv[2] ?? '--render';
if (!['--render', '--deploy'].includes(mode)) throw new Error('Expected --render or --deploy');
const cache = await mkdtemp(join(tmpdir(), 'zasp-runtime-charts-'));
if (mode === '--deploy') execFileSync('kubectl', ['apply', '-f', resolve(directory, 'temporal-openfga-network.yaml')], { stdio: 'inherit' });
const charts = [
  ['temporal', '1.7.0', 'https://github.com/temporalio/helm-charts/releases/download/temporal-1.7.0/temporal-1.7.0.tgz', 'f7b443f637b71fcbddd12900e5be9fe4c18cf741495d7b2cb247670681bf57d4'],
  ['openfga', '0.3.15', 'https://github.com/openfga/helm-charts/releases/download/openfga-0.3.15/openfga-0.3.15.tgz', 'bde4e1fa8962314f403c8f52a49294fd583597e920465be21a78ba165bcc0894'],
];
for (const [name, version, url, digest] of charts) {
  const archive = join(cache, `${name}-${version}.tgz`);
  execFileSync('curl', ['--fail', '--silent', '--show-error', '--location', '--max-time', '60', url, '--output', archive]);
  if (createHash('sha256').update(await readFile(archive)).digest('hex') !== digest) throw new Error('Chart checksum mismatch');
  // Always render the same pinned values before any installation.
  const rendered = execFileSync('helm', ['template', name, archive, '--namespace', 'zasp-runtime', '-f', resolve(directory, `${name}.values.yaml`)], { maxBuffer: 8 * 1024 * 1024 });
  if (mode === '--render') process.stdout.write(rendered);
  else {
    if (name === 'temporal') {
      const job = execFileSync('kubectl', ['create', '-f', resolve(directory, 'temporal-migrate.yaml'), '-o', 'name'], { encoding: 'utf8' }).trim();
      execFileSync('kubectl', ['wait', '-n', 'zasp-runtime', '--for=condition=complete', '--timeout=600s', job], { stdio: 'inherit' });
    }
    execFileSync('helm', ['upgrade', '--install', name, archive, '--namespace', 'zasp-runtime', '-f', resolve(directory, `${name}.values.yaml`), '--wait', '--wait-for-jobs', '--timeout', '10m'], { stdio: 'inherit' });
  }
}
if (mode === '--render') process.stdout.write(`\n---\n${await readFile(resolve(directory, 'temporal-migrate.yaml'), 'utf8')}`);
if (mode === '--render') process.stdout.write(`\n---\n${await readFile(resolve(directory, 'temporal-openfga-network.yaml'), 'utf8')}`);
