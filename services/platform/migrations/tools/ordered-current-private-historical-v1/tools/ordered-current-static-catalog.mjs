// Fixed saved-release metadata only. This module emits SQL; it never executes it.
// Except for the explicit non-installable runtime/worker descriptors, fingerprints
// and predecessor modes remain original live-check obligations.
const registrationSchemas = [
  'zasp_ordered_public62',
  ...Array.from({length:14}, (_, i) => `zasp_temporal${65+i}`),
  'zasp_authorization79', 'zasp_authorization80',
  'zasp_authorization80_worker', 'zasp_authorization80_runtime',
  'zasp_authorization80_temporal'
];
const families = {
  saved_view: {
    sources: {zasp_authorization80_worker:['predecessor_views','signature']},
    columns:['definition'], fields:{definition:'s.definition::text'}
  },
  saved_constraint: {
    sources: {
      zasp_temporal76:['predecessor_constraints','signature'],
      zasp_sa_export_prior:['job_constraints','name']
    },
    columns:['definition'], fields:{definition:'s.definition::text'}
  },
  saved_trigger: {
    sources: {zasp_existing_tests_predecessor:['global_control_triggers','relation_name']},
    columns:['trigger_name','definition','enabled'],
    fields:{name:'s.trigger_name::text',definition:'s.definition::text',enabled:'s.enabled::text'}
  },
  registration: {
    sources:Object.fromEntries(registrationSchemas.map(ns=>[ns,['registration','singleton']])),
    columns:['singleton','checksum'], fields:{singleton:'s.singleton',checksum:'s.checksum::text'}
  },
  profile_registration: {
    sources:{zasp_authorization80_temporal:['registration','singleton']},
    columns:['singleton','checksum','profile_name'],
    fields:{singleton:'s.singleton',checksum:'s.checksum::text',profile_name:'s.profile_name::text'}
  },
  // worker.catalog_ready requires this raw tuple. Its development baseline is
  // portability-unresolved until Variant B; this is not release constant approval.
  runtime_registration: {
    sources:{zasp_authorization80_runtime:['registration','singleton']},
    columns:['singleton','checksum','fingerprint'],
    fields:{singleton:'s.singleton',checksum:'s.checksum::text',fingerprint:'s.fingerprint::text'}
  },
  // Original catalog_ready checks row cardinality and this self-fingerprint.
  // Same non-installable, Variant B-unresolved boundary as runtime_registration.
  worker_registration: {
    sources:{zasp_authorization80_worker:['registration','singleton']},
    columns:['fingerprint'], fields:{fingerprint:'s.fingerprint::text'}
  }
};

export const staticRelations = Object.freeze([...new Set(Object.values(families)
  .flatMap(f=>Object.entries(f.sources).map(([ns,[table]])=>`${ns}.${table}`)))].sort());

export function staticDescriptor(kind, namespaces) {
  if (typeof kind!=='string' || !Object.hasOwn(families,kind)) {
    throw new Error('unsupported static descriptor kind');
  }
  const family=families[kind];
  if (!Array.isArray(namespaces) || namespaces.length===0 ||
      new Set(namespaces).size!==namespaces.length ||
      namespaces.some(ns=>typeof ns!=='string' || !Object.hasOwn(family.sources,ns))) {
    throw new Error('unsupported static descriptor namespaces');
  }
  // Only names from the fixed map reach SQL. Do not filter, deduplicate, coalesce,
  // normalize or silently skip absent tables: missing required tables must error.
  const branches=[...namespaces].sort().map(ns=>{
    const [table,key]=family.sources[ns];
    return `SELECT '${ns}'::text AS namespace,'${ns}.${table}'::text AS source_table,${key} AS row_key,${family.columns.join(',')} FROM ${ns}.${table}`;
  });
  return Object.freeze({
    identity:"'['||pg_catalog.to_json(s.source_table::text)::text||','||pg_catalog.to_json(s.row_key)::text||']'",
    namespace:'s.namespace::text',
    from:`(${branches.join(' UNION ALL ')}) s`,
    fields:Object.freeze({...family.fields})
  });
}
