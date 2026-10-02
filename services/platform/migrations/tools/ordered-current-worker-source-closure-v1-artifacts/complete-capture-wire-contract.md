# Complete capture wire, version 1

This is a capture-only interface. Fixed-file admission stays closed. A valid
envelope is not an expected-fact capability. All object shapes below are closed:
unknown keys refuse, required keys cannot be omitted, null is explicit.

## Packet

The seven packet members live in `services/platform/migrations/ordered_current/`:
`consolidated-capture-coverage.json`, `consolidated-capture-contract.json`, and
`consolidated-capture-{demand,keys,original,resolution,witness}.sql`. The owned snapshot
adds `snapshot-manifest.json`, shape `{format:1,source:string,files:{path:sha256}}`.
Member paths are clean relative paths. The loader pins the whole manifest and
contract independently with literal SHA256 values; matching caller-supplied
hashes convey no authority. The manifest also includes exact emitter, producer,
source-contract, compiler-artifact and reused-evidence bytes. Root authorized
`authorization_worker_consolidated_reference_pins_test.go` as a fourth Go file,
containing only literal packet/contract pins and fixed variant declarations.
Only that trust-anchor companion is excluded from the packet manifest. Root's
separate review inventory binds its exact bytes; all three producer implementation
files are included at their final hashes. `sourcePins` follows the same boundary.
The contract contains neither its own hash nor the final manifest hash.

Contract shape:

```text
{
 format:"ordered-current-complete-capture-contract-v1",
 status:"REFERENCE-CAPTURE-ONLY", installable:false, captureReady:true,
 sourceFrameVersion:1,
 compilerArtifactSHA256:string, compilerChecksum:string,
 compiledSourceSHA256:string, sourceContractSHA256:string,
 closureSHA256:string, catalog1FileSHA256:string,
 requiredPostgres:string, requiredServerVersionNum:"180003", pgcrypto:"1.4",
 variant:"A", sessionUser:"zasp_test", requiredRole:"zasp_discovery_authority",
 requiredTimeZone:"UTC", maxRows:10000, maxBytes:16777216,
 phases:[{id:string,searchPath:string,timeZone:"UTC",sqlSHA256:string,ruleIds:[string]}],
 rules:{ruleId:{kind:string,section:string,phase:string,fields:[string],
   fieldTypes:{field:type},sourceMaxRows:integer|null,refusalMaxRows:integer,
   bag:boolean,rosterRuleId:string|null,demandRuleId:string|null}},
 reusedEvidence:[{fileSHA256:string,rowIdentity:string,field:string,
   siteSHA256:string,frameSHA256:string}],
 sourcePins:{relativePath:sha256}
}
```

Exactly five phases occur in order: `demand`, `keys`, `original`, `resolution`,
`witness`. Keys searchPath is `pg_catalog`; all other phases use `pg_catalog, public`.
Every declared rule occurs in exactly one phase. `section` is one of `demand`, `roster`,
`rawInputs`, `normalizationObservations`, `resolutions`, `witnesses`.
Type names are `text`, `boolean`, `integer`, `number`, `json`, `text[]`, each
optionally suffixed `?` for nullable. All fields are required. Integer means a
JSON safe integer, validated from the exact numeric token before IEEE754
rounding. In particular `9007199254740991.1` cannot become an integer by rounding.
Other number/json fields retain the original valid finite numeric lexeme,
including `-0`, decimal fractions and exponent notation. Nonzero underflow to
binary64 zero and overflow to infinity refuse, so validation never mistakes
those values for finite zero or infinity. JSON values reject malformed UTF8,
duplicate object keys and lone surrogates. Strings use Unicode scalar values.

## Stream and joins

Each phase SELECT returns exactly one JSON column, each row having this shape:

```text
{ruleId:string,identity:string|null,handle:string|null,multiplicity:integer,fact:{field:value}}
```

`identity` is a canonical semantic key under pg_catalog, or an encoded semantic
tuple for a bag. Demand rows and roster-joined original rows have identity:null.
`handle` is transient `catalog-class:oid:subobject` text for
catalog joins, null for saved/bag/resolution/witness rows. Handles and OIDs never
enter published facts. Demand and roster rules have empty facts and nonnull
handles. The demand phase evaluates original selectors/casts in the original
frame without raw deparse fields or helper calls. Each roster rule has exactly
one demandRuleId. Other rules have demandRuleId:null. The keys query accepts
only collector-owned bound parameter `$1::jsonb`, an array of `{ruleId,handle}`
from the completed demand phase; never interpolated SQL or caller-supplied data.
The producer passes that value as a typed phase input to the row collector.
The Go callback signature stays `Collect(context.Context,
consolidatedReferencePhase, func(json.RawMessage) error) error`.
`consolidatedReferencePhase` adds `DemandHandles []consolidatedReferenceHandle`;
the handle type has `RuleID string` tagged `json:"ruleId"` and `Handle string`
tagged `json:"handle"`. This field is nil outside keys, and is collector-owned
(possibly empty but nonnil) for keys. The SQL adapter serializes it and binds it
as the sole query argument, `$1`; other phases have zero bound arguments.
The keys phase resolves handles under pg_catalog. Its complete handle sets
must equal the respective demand sets, including zero rows. Every demand rule
has one roster consumer and every roster rule has one original consumer.
The collector records the unique handle-to-canonical-identity map. An original
rule with nonnull rosterRuleId must match that roster's complete handle set and
published identities are assigned only from that map. Original projected
identity text, where selected by source, remains a separate raw fact. Duplicate handles, ambiguous
joins, missing or extra identities refuse. Source demand must be identical in
both selectors. A helper-local cast remains inside its selected CASE demand.

Ordinary rows have multiplicity 1 and unique `(ruleId,identity)`. Bag rows combine
equal semantic tuples into one positive multiplicity; no grantor/OID may split
equal `(granted_role,member_role,admin_option)` membership tuples. Config fields
include JSON config, raw array text, dims text, ndims and all lower/upper bounds;
JSON alone cannot prove dimensions. Resolution facts include `literal`, `cast`,
`sourceSite`, `demandPath`, `resolvedIdentity`. A missing original cast errors;
the collector cannot replace regprocedure with to_regprocedure. A demand row
exists only where source demands its expression; binding obligations are separate.

Resource accounting is cumulative across all phases and includes demand and roster rows,
resolution/witness rows and expanded multiplicity. Per-rule count is expanded.
No LIMIT or successful prefix. Sticky overflow/row errors survive ignored emit
errors. Count streamed encoded row bytes and final envelope bytes against 16MiB.

## Published envelope

```text
{
 format:"ordered-current-complete-reference-v1",status:"REFERENCE-CAPTURE-ONLY",
 installable:false,sourceFrameVersion:1,
 packetManifestSHA256:string,contractSHA256:string,closureSHA256:string,
 compilerArtifactSHA256:string,compilerChecksum:string,compiledSourceSHA256:string,
 sourceContractSHA256:string,catalog1FileSHA256:string,
 sourcePins:{relativePath:sha256},variant:"A"|"B",
 sessionUser:string,role:"zasp_discovery_authority",timeZone:"UTC",
 postgres:string,serverVersionNum:"180003",pgcrypto:"1.4",
 readOnly:true,preAdmission:true,postAdmission:true,rolledBack:true,frameRestored:true,
 phases:[{id:string,searchPath:string,timeZone:"UTC",sqlSHA256:string,
   rowCount:integer,expandedRows:integer,streamBytes:integer}],
 counts:{streamRows:integer,expandedRows:integer,streamBytes:integer,
   demandRows:integer,rosterRows:integer,ruleRows:{ruleId:integer}},
 rawInputs:[publishedRow],normalizationObservations:[publishedRow],
 resolutions:[publishedRow],witnesses:[publishedRow],
 reusedEvidence:[{fileSHA256:string,rowIdentity:string,field:string,
   siteSHA256:string,frameSHA256:string}]
}
publishedRow = {ruleId:string,identity:string,multiplicity:integer,fact:{field:value}}
```

Demand and roster rows are counted but never published. Every rule has a ruleRows entry,
including zero. Each phase is observed, including empty phases. Arrays are
sorted by UTF8 byte `(ruleId,identity)` order. Producer wire JSON recursively
sorts object keys by unsigned UTF8 bytes, not UTF16 units, JavaScript property
enumeration or locale. Captured numeric tokens are retained verbatim. Generated
integer counts use shortest base-10 digits. Serialization is deterministic for
these retained lexemes, not a claim of canonical numeric equivalence.
Strings use JSON.stringify escaping for ASCII controls, quote and backslash;
U+2028 and U+2029 always use lowercase `\u2028` and `\u2029` escapes. Other
Unicode scalar values, including astral characters, remain literal UTF8.
`<`, `>` and `&` remain unescaped. There is no insignificant whitespace and
exactly one terminal newline in the file. The final 16MiB cap includes it.
`payloadSHA256` is the digest without that newline; `fileSHA256` includes it.
Hash the exact original producer bytes. The JavaScript intake validates and
hashes those bytes without reserialization or a language-normalized identity
claim. It returns no decoded facts; any future evidence-use API must preserve
original numeric tokens and cannot present rounded JSON numbers as lossless.
These hashes are publication return values, not self-referential envelope fields.
`sourcePins` binds producer and emitter source through the frozen manifest.

Publication follows restored pg_catalog, reset role, post-admission, successful
rollback and exact initial-frame restoration. Cleanup failure, cancellation
before the hard-link boundary, input/output collision or existing output refuses.
The initial role is the fixed fixture owner. Variant A is `A`/`zasp_test`.
Variant B requires its own independently frozen manifest and contract declaring
`B`/`zasp_e2e`; a loose owner allowlist or mutable owner overlay is forbidden.
A can be prepared first; B readiness stays pending until frozen independently.
A capture never changes installer/runtime pins.

Root approved the fifth phase after source inspection: schedule's original
`signature::regprocedure` universe cannot be resolved under pg_catalog on the
basis of qualified-looking captured strings. Existing artifacts do not bind
every saved signature's original-frame resolution. The original four-phase
constraint is superseded; complete demand-to-key-to-original equality is required.
