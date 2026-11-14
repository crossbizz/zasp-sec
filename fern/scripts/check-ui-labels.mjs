#!/usr/bin/env node
// Checks that the user guide cites only labels the web application has.
//
// In docs/getting-started/user.md, a name in bold is a label of the web
// application, and a sentence in double quotes is a message it shows. This
// script looks each one up in the application's source (app/) and in the
// connector manifests, and fails when one is not there, so the guide cannot
// drift into describing screens that do not exist.
//
// Bold text that ends with a full stop or a colon inside the markers, such as
// a step heading, is prose and is skipped unless the source has it verbatim.
//
// Usage: node fern/scripts/check-ui-labels.mjs

import { readFileSync, readdirSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const guide = readFileSync(join(root, "docs", "getting-started", "user.md"), "utf8");

function sources(directory, out = []) {
  for (const name of readdirSync(directory)) {
    const path = join(directory, name);
    if (statSync(path).isDirectory()) sources(path, out);
    else if (/\.(ts|tsx)$/.test(name) && !/\.test\.(ts|tsx)$/.test(name)) out.push(path);
  }
  return out;
}

// JSX writes an apostrophe as &apos; and may break a sentence across
// expressions; compare on a form without entities and with single spaces.
function normalize(text) {
  return text.replaceAll("&apos;", "'").replaceAll("’", "'").replaceAll("&lt;", "<").replaceAll("&gt;", ">").replace(/\s+/g, " ");
}

const corpus = normalize([
  ...sources(join(root, "app")).map((path) => readFileSync(path, "utf8")),
  readFileSync(join(root, "services", "platform", "integration", "manifest.go"), "utf8"),
  readFileSync(join(root, "services", "platform", "identity", "roles.go"), "utf8"),
].join("\n"));

const prose = guide.replace(/```[\s\S]*?```/g, "");
const labels = new Set();
for (const match of prose.matchAll(/\*\*([^*\n]+(?:\n[^*\n]+)?)\*\*/g)) labels.add(normalize(match[1]));
const messages = new Set();
for (const match of prose.matchAll(/"([A-Z][^"\n]{12,}(?:\n[^"\n]+)?)"/g)) messages.add(normalize(match[1]));

const missing = [];
for (const label of labels) {
  if (corpus.includes(label)) continue;
  if (/[.:]$/.test(label)) continue; // a step heading, not a label
  missing.push(`label: ${label}`);
}
for (const message of messages) {
  // A quoted message may be the start of a longer one.
  const head = message.replace(/[.]$/, "");
  if (!corpus.includes(head)) missing.push(`message: ${message}`);
}

if (missing.length > 0) {
  console.error(`docs/getting-started/user.md cites ${missing.length} label(s) or message(s) the web application does not have:`);
  for (const entry of missing) console.error(`  ${entry}`);
  process.exit(1);
}
console.log(`user guide: ${labels.size} labels and ${messages.size} messages checked against the web application`);
