import { readFile } from 'node:fs/promises';
import { spawn } from 'node:child_process';
import { pathToFileURL } from 'node:url';

export function selectorDeploymentCommands(config) {
  if (!config || Object.keys(config).sort().join(',') !== 'cadence_seconds,enabled,revision' || !Number.isInteger(config.revision) || config.revision < 1 || config.revision > 1000000 || !Number.isInteger(config.cadence_seconds) || config.cadence_seconds < 1 || config.cadence_seconds > 86400 || typeof config.enabled !== 'boolean') throw new Error('selector deployment configuration rejected');
  return [{ args: ['up-temporal-test-selector'], env: {} }, { args: ['configure-temporal-test-selector'], env: { ZASP_TEST_SELECTOR_CONFIGURATION: JSON.stringify(config) } }];
}

// Run only on an explicitly chosen application database with74 already ready.
// The migration CLI authenticates all registered principals and catalog pins.
export async function installTestSelector(executable, configurationPath) {
  if (!executable || !configurationPath) throw new Error('explicit executable and configuration path required');
  const commands = selectorDeploymentCommands(JSON.parse(await readFile(configurationPath, 'utf8')));
  for (const command of commands) {
    await new Promise((resolve, reject) => {
      const child = spawn(executable, command.args, { env: { ...process.env, ...command.env }, stdio: 'inherit' });
      child.once('error', reject);
      child.once('close', code => code === 0 ? resolve() : reject(new Error('selector deployment command failed')));
    });
  }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await installTestSelector(process.argv[2], process.argv[3]);
}
