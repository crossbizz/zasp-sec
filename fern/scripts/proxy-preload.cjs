// Node preload that sends every fetch() through the proxy named in
// HTTPS_PROXY.
//
// The Fern CLI calls Fern's services with fetch(), and Node's fetch ignores
// HTTPS_PROXY. Behind a proxy the CLI then cannot reach them: `fern generate
// --docs` reports "registerApiDefinition failed ... rawError {}" and its debug
// log says "entering air-gapped mode".
//
// This file wraps globalThis.fetch so that each call carries an undici
// EnvHttpProxyAgent as its dispatcher. It is passed per call, so it holds
// whatever global dispatcher the program installs later. NO_PROXY is honoured
// by the agent.
//
// fern/scripts/fern.mjs adds this file to NODE_OPTIONS when HTTPS_PROXY is set
// and the package `undici` can be resolved. undici is not a dependency of this
// repository; without it this file does nothing. See "Behind an HTTP proxy" in
// fern/README.md.

"use strict";

// A preload given to Node with --require is CommonJS, so it loads undici with require().
/* eslint-disable @typescript-eslint/no-require-imports */

(function installProxyFetch() {
  if (!process.env.HTTPS_PROXY && !process.env.https_proxy) return;
  if (typeof globalThis.fetch !== "function" || globalThis.fetch.__zaspProxyFetch) return;
  let undici;
  try {
    undici = require(require.resolve("undici", { paths: [process.cwd(), __dirname] }));
  } catch {
    return;
  }
  if (typeof undici.EnvHttpProxyAgent !== "function") return;
  // Node's fetch is its own bundled undici. A dispatcher from another major
  // version is refused ("invalid onRequestStart method"), so use it only when
  // the majors match. Install the matching one with the version printed by
  // `node -p process.versions.undici`.
  let installed = "";
  try {
    installed = require(require.resolve("undici/package.json", { paths: [process.cwd(), __dirname] })).version;
  } catch {
    return;
  }
  const bundled = process.versions.undici || "";
  if (installed.split(".")[0] !== bundled.split(".")[0]) {
    process.emitWarning(`undici ${installed} does not match the undici ${bundled} of this Node; the proxy is not used for fetch. Install undici@${bundled}.`);
    return;
  }
  const agent = new undici.EnvHttpProxyAgent();
  const original = globalThis.fetch;
  const proxied = function fetch(input, init) {
    return original.call(this, input, { ...(init || {}), dispatcher: agent });
  };
  proxied.__zaspProxyFetch = true;
  globalThis.fetch = proxied;
})();
