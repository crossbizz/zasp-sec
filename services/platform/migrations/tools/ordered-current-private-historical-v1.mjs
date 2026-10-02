// One immutable historical derivation, not an old-or-new helper compatibility list.
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath, pathToFileURL} from 'node:url';

const root = fileURLToPath(new URL('./ordered-current-private-historical-v1/', import.meta.url));
const manifestSHA256 = '8d4fee2253344603a4878751f70f96bcf7d4b4884a5cab2b6ee1016db9d40732';
const packetFileSHA256 = '6a487133102fb497db4e3209842a00ce3a0cec48ffd595c84dc3216a982a9cd0';
const packetJSONSHA256 = '3a93f396bd3a60ae3f95e9690ff6b937d31507f95ebabeda7fd84133780fdc08';
const sha = value => crypto.createHash('sha256').update(value).digest('hex');
const fail = message => { throw Error(`ordered-current private historical ${message}`); };

function verifyBundle() {
  try {
    // lstat precedes reads/traversal. Neither a bundle nor a child symlink is
    // admitted, even if it currently points at bytes with an allowed digest.
    if (!fs.lstatSync(root).isDirectory() || fs.realpathSync(root) !== path.resolve(root)) fail('bundle directory');
    const manifestPath = path.join(root, 'manifest.json');
    if (!fs.lstatSync(manifestPath).isFile()) fail('manifest file');
    const raw = fs.readFileSync(manifestPath);
    if (sha(raw) !== manifestSHA256) fail('manifest authority');
    const manifest = JSON.parse(raw);
    const expected = ['manifest.json', ...Object.keys(manifest.files)].sort();
    const actual = [];
    function walk(directory, prefix = '') {
      for (const entry of fs.readdirSync(directory, {withFileTypes:true})) {
        const relative = prefix + entry.name, absolute = path.join(directory, entry.name);
        const stat = fs.lstatSync(absolute);
        if (stat.isDirectory()) {
          if (relative !== 'tools' && relative !== 'sql') fail(`unexpected directory ${relative}`);
          walk(absolute, relative + '/');
        } else if (stat.isFile()) actual.push(relative);
        else fail(`nonregular input ${relative}`);
      }
    }
    walk(root);
    if (actual.sort().join('\n') !== expected.join('\n')) fail('closed file roster');
    for (const [file, digest] of Object.entries(manifest.files)) {
      if (sha(fs.readFileSync(path.join(root, file))) !== digest) fail(`source authority ${file}`);
    }
  } catch (error) {
    if (error.message.startsWith('ordered-current private historical ')) throw error;
    fail(`source read (${error.message})`);
  }
}

// Verification must run before the archived entry or any of its 25 imports is
// evaluated. The archived bytes retain their own seven original helper guards.
verifyBundle();
const historical = await import(pathToFileURL(path.join(root, 'tools/ordered-current-private-successor-reference.mjs')).href);
verifyBundle();

export function buildOrderedCurrentPrivateHistoricalPacketV1(...inputs) {
  if (inputs.length) fail('caller input');
  verifyBundle();
  const packet = historical.buildOrderedCurrentPrivateSuccessorPacketV1();
  verifyBundle();
  const json = JSON.stringify(packet);
  if (sha(json) !== packetJSONSHA256 || sha(json + '\n') !== packetFileSHA256) fail('packet authority');
  return packet;
}
