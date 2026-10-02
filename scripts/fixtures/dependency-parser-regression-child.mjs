// This child performs only local module resolution and parsing of tiny fixed
// buffers. Its parent supplies no credential environment and owns its lifetime.
const vinextEntry = import.meta.resolve("vinext");
const metadataReader = new URL("./server/metadata-route-build-data.js", vinextEntry);
// The parent enables Node's second-argument ESM resolution. Resolve from the
// real metadata reader, including any scoped nested override, not this helper.
const parser = import.meta.resolve("image-size", metadataReader.href);
const { imageSize } = await import(parser);

function uint32(value) {
  const bytes = Buffer.alloc(4);
  bytes.writeUInt32BE(value);
  return bytes;
}

function box(type, payload) {
  return Buffer.concat([uint32(payload.length + 8), Buffer.from(type, "ascii"), payload]);
}

function fixture(name) {
  if (name === "icns-valid" || name === "icns-zero-entry") {
    // A 16-byte ICNS header with one icp5 header declares a 32x32 icon.
    return Buffer.concat([
      Buffer.from("icns"), uint32(16), Buffer.from("icp5"),
      uint32(name === "icns-valid" ? 8 : 0),
    ]);
  }
  if (name === "jxl-valid" || name === "jxl-zero-partial") {
    const signature = box("JXL ", Buffer.from([0x0d, 0x0a, 0x87, 0x0a]));
    const brand = box("ftyp", Buffer.concat([Buffer.from("jxl "), uint32(0), Buffer.from("jxl ")]));
    // Small-image bits encode height 8, explicit width 8. The invalid fixture
    // has only the partial index, then overwrites the 12-byte box size to zero.
    const partial = box("jxlp", name === "jxl-valid"
      ? Buffer.from([0x80, 0, 0, 0, 0xff, 0x0a, 0x01, 0x00])
      : Buffer.alloc(4));
    if (name === "jxl-zero-partial") partial.writeUInt32BE(0);
    return Buffer.concat([signature, brand, partial]);
  }
  if (name === "heif-valid" || name === "heif-zero-ispe") {
    const brand = box("ftyp", Buffer.concat([Buffer.from("heic"), uint32(0), Buffer.from("heic")]));
    const dimensions = box("ispe", Buffer.concat([uint32(0), uint32(16), uint32(24)]));
    const properties = box("iprp", box("ipco", dimensions));
    const meta = box("meta", Buffer.concat([uint32(0), properties]));
    const input = Buffer.concat([brand, meta]);
    if (name === "heif-zero-ispe") input.writeUInt32BE(0, 48);
    return input;
  }
  throw new Error("unknown parser regression fixture");
}

const input = fixture(process.argv[2]);
let result;
try {
  result = { parser, disposition: "dimensions", dimensions: imageSize(input) };
} catch (error) {
  result = { parser, disposition: "rejected", error: { name: error.name, message: error.message } };
}
process.stdout.write(JSON.stringify(result));
