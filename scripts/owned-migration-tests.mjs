import {randomBytes} from 'node:crypto';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {closeHeldTool, reopenOfficialHeldTool} from './official-held-tools.mjs';
import {spawnOwnedCommand} from './owned-command.mjs';
import {startOwnedMigrationRuntimeServices} from './owned-runtime-services.mjs';
import {migrationTestCommands} from './migration-test-partition.mjs';

const defaults = {
  reopen: reopenOfficialHeldTool,
  closeTool: closeHeldTool,
  start: startOwnedMigrationRuntimeServices,
  run(executable, args, env) {
    const command = spawnOwnedCommand(executable, args, {env});
    command.child.stdout.pipe(process.stdout, {end: false});
    command.child.stderr.pipe(process.stderr, {end: false});
    return command;
  },
};

export async function runOwnedMigrationTests(argv, env, signal, adapters = defaults) {
  const command = Object.values(migrationTestCommands).find(args =>
    argv[0] === '--' && argv.length === args.length + 1 && args.every((arg, i) => arg === argv[i + 1]));
  if (!command) throw new Error('unrecognized migration test command');
  const {RUNNER_TEMP: rootParent, ZASP_BROWSER_RUNTIME_ARCHIVE_ROOT: archives, ZASP_BROWSER_RUNTIME_RAW_ROOT: raw} = env;
  if (![rootParent, archives, raw].every(p => typeof p === 'string' && path.isAbsolute(p))) {
    throw new Error('migration tests require the pinned runtime intake');
  }
  const tools = {};
  let services, tests;
  const cancelled = () => { throw new Error('migration test run cancelled'); };
  const abort = () => { void tests?.stop().catch(() => {}); };
  signal?.addEventListener('abort', abort, {once: true});
  try {
    for (const name of ['temporal', 'openfga']) {
      if (signal?.aborted) cancelled();
      tools[name] = await adapters.reopen(name, path.join(archives, name + '.tar.gz'), path.join(raw, name + '-held'));
    }
    if (signal?.aborted) cancelled();
    services = await adapters.start({rootParent, tools, run: randomBytes(8).toString('hex')}, undefined, signal);
    if (signal?.aborted) cancelled();
    const childEnv = {
      ...env,
      ZASP_P6_NATIVE_OPENFGA_URL: services.environment.ZASP_OPENFGA_URL,
      ZASP_P6_NATIVE_OPENFGA_TOKEN_FILE: services.environment.ZASP_OPENFGA_TOKEN_FILE,
    };
    tests = adapters.run(command[0], command.slice(1), childEnv);
    const result = await Promise.race([
      tests.completed,
      services.completed.then(() => { throw new Error('migration runtime stopped during the Go tests'); }),
    ]);
    if (signal?.aborted) cancelled();
    if (result.signal || result.status !== 0) throw new Error('migration Go tests failed');
  } finally {
    signal?.removeEventListener('abort', abort);
    try {
      await tests?.stop();
    } finally {
      try {
        await services?.close();
      } finally {
        // Also covers a partial reopen or service startup failure.
        const closed = await Promise.allSettled(Object.values(tools).map(tool => adapters.closeTool(tool)));
        if (closed.some(result => result.status === 'rejected')) throw new Error('migration runtime tool cleanup failed');
      }
    }
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const controller = new AbortController();
  const cancel = () => controller.abort();
  process.once('SIGINT', cancel);
  process.once('SIGTERM', cancel);
  try {
    await runOwnedMigrationTests(process.argv.slice(2), process.env, controller.signal);
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  } finally {
    process.removeListener('SIGINT', cancel);
    process.removeListener('SIGTERM', cancel);
  }
}
