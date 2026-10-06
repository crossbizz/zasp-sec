import fs from 'node:fs';
export function readOrderedCurrentLinuxProvenanceV1(){return JSON.parse(fs.readFileSync(new URL('./ordered-current-linux-provenance-v1.json',import.meta.url),'utf8'));}
export function admitOrderedCurrentLinuxProvenanceV1(value){return structuredClone(value);}
