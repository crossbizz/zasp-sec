import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import test from 'node:test';

const compose = fileURLToPath(new URL('../deploy/local/temporal-openfga.compose.yaml', import.meta.url));
for (const [name, value, expected] of [
  ['unset', undefined, 'local-openfga-only'],
  ['empty', '', 'local-openfga-only'],
  ['URL-safe override', 'fixture-override-only', 'fixture-override-only'],
]) {
  test(`disposable OpenFGA compose preserves consistent ${name} credentials without loading .env`, () => {
    const env = {...process.env};
    delete env.ZASP_LOCAL_OPENFGA_PASSWORD;
    if (value !== undefined) env.ZASP_LOCAL_OPENFGA_PASSWORD = value;
    // Config rendering only: no daemon mutation, containers or network calls.
    const config = JSON.parse(execFileSync('docker', ['compose', '--env-file', '/dev/null', '-f', compose, 'config', '--format', 'json'], {env, encoding: 'utf8', timeout: 30000}));
    assert.equal(config.services['openfga-db'].environment.POSTGRES_PASSWORD, expected);
    for (const name of ['openfga', 'openfga-migrate']) {
      const uri = new URL(config.services[name].environment.OPENFGA_DATASTORE_URI);
      assert.equal(uri.username, 'openfga');
      assert.equal(uri.password, expected);
      assert.equal(uri.hostname, 'openfga-db');
      assert.equal(uri.port, '5432');
      assert.equal(uri.pathname, '/openfga');
      assert.equal(uri.search, '?sslmode=disable');
    }
    assert.ok(config.services.openfga.ports.every(port => port.host_ip === '127.0.0.1'));
  });
}
