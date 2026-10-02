// Extract the stored raw JSON member without a serializer or current renderer.
export function storedComplianceJSON(bytes) {
  const text = bytes.toString("utf8");
  const prefix = '"json":';
  const start = text.indexOf(prefix);
  if (start < 0 || text.indexOf(prefix, start + prefix.length) !== -1) throw new Error("ambiguous stored JSON");
  let offset = start + prefix.length;
  while (/\s/.test(text[offset] ?? "")) offset++;
  if (text[offset] !== "[") throw new Error("stored JSON is not an array");
  const begin = offset;
  let depth = 0, quoted = false, escaped = false;
  for (; offset < text.length; offset++) {
    const char = text[offset];
    if (quoted) { if (escaped) escaped = false; else if (char === "\\") escaped = true; else if (char === '"') quoted = false; continue; }
    if (char === '"') { quoted = true; continue; }
    if (char === "[" || char === "{") depth++;
    if (char === "]" || char === "}") depth--;
    if (depth === 0) { const raw = text.slice(begin, offset + 1); JSON.parse(raw); return Buffer.from(raw); }
  }
  throw new Error("incomplete stored JSON");
}
