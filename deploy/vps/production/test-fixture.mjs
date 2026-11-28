import {execFile} from 'node:child_process';
import {promisify} from 'node:util';
import {mkdtemp, writeFile, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {fileURLToPath} from 'node:url';
import {loadAll, JSON_SCHEMA} from 'js-yaml';
import {hostedReleaseInputs} from '../../production/release-contract.mjs';
import {canonicalRuntimeFixture, productionReleaseFixture} from '../../production/release-fixture.mjs';
import {authorizationTemporalChartValues} from '../../production/authorization-temporal-profile.mjs';

const exec = promisify(execFile);
const root = fileURLToPath(new URL('../../../', import.meta.url));

export async function renderChart(release, chart, namespace, args = []) {
  const {stdout} = await exec('helm', ['template', release, chart, '--namespace', namespace, ...args], {
    cwd: root, maxBuffer: 16 * 1024 * 1024,
  });
  return loadAll(stdout, undefined, {schema: JSON_SCHEMA}).filter(Boolean);
}

// Render the complete shipped chart using the same hosted fixture as its AWS tests.
// The operator overlay follows private site inputs, including their old endpoints.
export async function renderVpsFixture(sessionSearchPhase = 'precision-intake', extraArgs = []) {
  const options = sessionSearchPhase === 'precision-intake' ? canonicalRuntimeFixture() :
    {schemaVersion: 49, sessionSearchPhase};
  const {set, authorizationTemporal, runtimeServices} = hostedReleaseInputs(productionReleaseFixture, options);
  const site = {deploymentAdmin: {id: 'fixture-deployment'}};
  if (authorizationTemporal) Object.assign(site, {authorizationTemporal, runtimeServices}, authorizationTemporalChartValues(authorizationTemporal));
  for (const [path, value] of set) {
    const keys = path.replace(/\[(\d+)\]/g, '.$1').split('.');
    let object = site;
    for (const [index, key] of keys.entries()) {
      if (index === keys.length - 1) object[key] = value;
      else object = object[key] ??= /^\d+$/.test(keys[index+1]) ? [] : {};
    }
  }
  // The private site releases ingress ownership only after verifying the production service.
  site.ingress = {...site.ingress, enabled: false};
  const directory = await mkdtemp(tmpdir() + '/vps-chart-');
  try {
    await writeFile(directory + '/site.json', JSON.stringify(site), {mode: 0o600});
    return await renderChart('agentsec', 'deploy/staging/product', 'zasp', ['-f', directory + '/site.json', '-f', 'deploy/vps/production/values.yaml', ...extraArgs]);
  } finally {
    await rm(directory, {recursive: true, force: true});
  }
}
