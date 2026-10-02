import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, copyFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { loadAll } from 'js-yaml';

const serviceName = 'openfga.zasp-runtime.svc.cluster.local';
const rendered = execFileSync(process.execPath, ['deploy/staging/temporal-openfga.mjs', '--render'], { encoding: 'utf8', timeout: 90000, maxBuffer: 8 * 1024 * 1024 });
const deployment = loadAll(rendered).find(doc => doc?.kind === 'Deployment' && doc.metadata.name === 'openfga');
const container = deployment.spec.template.spec.containers[0];

test('staging FGA health probes verify the service certificate while connecting locally', () => {
  for (const key of ['readinessProbe', 'livenessProbe']) {
    const probe = container[key];
    assert.ok(probe.exec.command.includes('-addr=127.0.0.1:8081'));
    assert.ok(probe.exec.command.includes(`-tls-server-name=${serviceName}`));
    assert.ok(probe.exec.command.includes('-tls'));
    assert.ok(probe.exec.command.includes('-tls-ca-cert=/etc/openfga-tls/ca.crt'));
    assert.ok(!probe.exec.command.includes('-tls-no-verify'));
    assert.ok(probe.timeoutSeconds > 0 && probe.timeoutSeconds <= 5);
  }
});

// One opt-in check of our rendered command with a DNS-only SAN. This tests the
// deployed TLS settings, not FGA authorization or gRPC's certificate engine.
test('rendered probe accepts the documented DNS-SAN certificate', { skip: process.env.ZASP_RUNTIME_TLS_PROBE_SMOKE !== '1', timeout: 30000 }, async () => {
  const directory = mkdtempSync(join(tmpdir(), 'zasp-fga-probe-cert-'));
  const name = `zasp-p1-probe-${process.pid}`;
  let started = false;
  try {
    execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', `/CN=${serviceName}`, '-addext', `subjectAltName=DNS:${serviceName}`, '-keyout', join(directory, 'tls.key'), '-out', join(directory, 'tls.crt')], { stdio: 'pipe', timeout: 10000 });
    copyFileSync(join(directory, 'tls.crt'), join(directory, 'ca.crt'));
    execFileSync('docker', ['create', '--name', name, '--network', 'none', '--user', '0:0', '--read-only', '--tmpfs', '/tmp', '--mount', `type=bind,source=${directory},target=/etc/openfga-tls,readonly`, container.image, 'run', '--datastore-engine', 'memory', '--playground-enabled=false', '--http-enabled=false', '--grpc-tls-enabled=true', '--grpc-tls-cert=/etc/openfga-tls/tls.crt', '--grpc-tls-key=/etc/openfga-tls/tls.key'], { stdio: 'pipe', timeout: 10000 });
    started = true;
    execFileSync('docker', ['start', name], { stdio: 'pipe', timeout: 10000 });
    let result;
    const deadline = Date.now() + 8000;
    do {
      result = spawnSync('docker', ['exec', name, ...container.readinessProbe.exec.command], { encoding: 'utf8', timeout: 3000 });
      if (result.status === 0) break;
      await new Promise(resolve => setTimeout(resolve, 100));
    } while (Date.now() < deadline);
    assert.equal(result.status, 0, result.stderr || result.error?.message);
    // A wrong DNS name must still fail, proving we retained verification.
    const wrongName = container.livenessProbe.exec.command.map(arg => arg.startsWith('-tls-server-name=') ? '-tls-server-name=wrong.internal' : arg);
    const rejected = spawnSync('docker', ['exec', name, ...wrongName], { encoding: 'utf8', timeout: 5000 });
    assert.notEqual(rejected.status, 0, 'mismatched certificate accepted');
  } finally {
    if (started) execFileSync('docker', ['rm', '-f', name], { stdio: 'pipe', timeout: 10000 });
    rmSync(directory, { recursive: true, force: true });
  }
});
