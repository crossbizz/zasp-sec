import { createHash, createPublicKey, verify } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, open, realpath } from 'node:fs/promises';
import path from 'node:path';

export const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
export const hex = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
export const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
export function requireThat(condition, message) {
  if (!condition) throw Error(message);
}
export function unique(items, field, label) {
  requireThat(Array.isArray(items) && items.every(object) && new Set(items.map(field)).size === items.length, 'Invalid or duplicate ' + label);
}
export function stamp(value) {
  requireThat(typeof value === 'string' && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{3})?Z$/.test(value), 'Invalid UTC timestamp');
  const ms = Date.parse(value);
  requireThat(Number.isFinite(ms) && new Date(ms).toISOString() === (value.includes('.') ? value : value.replace('Z', '.000Z')), 'Invalid UTC calendar date');
  return ms;
}
export async function fileHash(file, maxBytes = 16 * 1024 ** 3) {
  const fd = await open(file, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const before = await fd.stat({bigint:true});
    requireThat(before.isFile() && before.size <= BigInt(maxBytes), 'Invalid file size or type');
    const hash = createHash('sha256');
    let count = 0;
    for await (const chunk of fd.createReadStream({autoClose:false})) {
      count += chunk.length;
      requireThat(count <= maxBytes, 'File exceeds size limit');
      hash.update(chunk);
    }
    const after = await fd.stat({bigint:true});
    requireThat(BigInt(count) === before.size && before.mtimeNs === after.mtimeNs && before.ctimeNs === after.ctimeNs, 'File changed during verification');
    return hash.digest('hex');
  } finally { await fd.close(); }
}
export async function readBound(file, limit) {
  const fd = await open(file, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const s = await fd.stat();
    requireThat(s.isFile() && s.size > 0 && s.size <= limit, 'Invalid signed input size');
    const bytes = Buffer.alloc(s.size);
    let offset = 0;
    while (offset < bytes.length) {
      const {bytesRead} = await fd.read(bytes, offset, bytes.length - offset);
      requireThat(bytesRead > 0, 'Signed input changed');
      offset += bytesRead;
    }
    requireThat((await fd.read(Buffer.alloc(1))).bytesRead === 0, 'Signed input changed');
    return bytes;
  } finally { await fd.close(); }
}
export function publicKey(pem) {
  requireThat(typeof pem === 'string' && pem.startsWith('-----BEGIN PUBLIC KEY-----'), 'Trusted release public key missing');
  const key = createPublicKey(pem);
  requireThat(key.asymmetricKeyType === 'ed25519', 'Expected an Ed25519 release public key');
  return key;
}
export async function verifySigned(file, keyPem, format) {
  const raw = await readBound(file, 32 * 1024 ** 2);
  const signature = (await readBound(file + '.sig', 128)).toString('ascii').trim();
  const sig = Buffer.from(signature, 'base64');
  requireThat(sig.length === 64 && sig.toString('base64') === signature && verify(null, raw, publicKey(keyPem), sig), 'Invalid signed ' + format);
  const value = JSON.parse(new TextDecoder('utf-8', {fatal:true}).decode(raw));
  requireThat(object(value) && value.format === format, 'Unexpected signed schema: ' + format);
  return {value, sha256:sha256(raw)};
}
export async function bundleFile(dir, relative) {
  requireThat(typeof relative === 'string' && relative.length <= 512 && relative.split('/').every(p => /^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(p)), 'Unsafe evidence artifact path');
  const root = await realpath(dir);
  const file = path.join(root, relative);
  requireThat(await realpath(file) === file && (await lstat(file)).isFile(), 'Indirect evidence file refused');
  return file;
}
