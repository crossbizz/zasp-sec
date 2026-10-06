// Audit calls retain their original execution context and CASE demand. This
// preflight authenticates the separately compiled boundary; it never rewrites it.
const savedOriginals = [
  {
    "signature": "zasp_sa_attack_lab_prior.audit_fingerprint()",
    "definitionHash": "47e83b715f449be757dec9b9f34f611080029ccd3f5528aaaf6b0e83c4981469",
    "owner": "zasp_discovery_authority",
    "acl": "{zasp_discovery_authority=X/zasp_discovery_authority}"
  },
  {
    "signature": "zasp_sa_attack_lab_prior.budget_fingerprint()",
    "definitionHash": "583e15af3ba7b44495777d3f4ba11f57b4b17ba69e1834bf9c7549537b4ef3df",
    "owner": "zasp_discovery_authority",
    "acl": "{zasp_discovery_authority=X/zasp_discovery_authority}"
  },
  {
    "signature": "zasp_sa_attack_lab_prior.run_context_fingerprint()",
    "definitionHash": "9093f488b9d7e8c6953761b7429a51d2841e1ed4a1ec5f6cab4b45ded62a9efb",
    "owner": "zasp_discovery_authority",
    "acl": "{zasp_discovery_authority=X/zasp_discovery_authority}"
  },
  {
    "signature": "zasp_sa_attack_lab_prior.existing_tests_fingerprint()",
    "definitionHash": "d1cc47d7a429d9776e3a3f424e48311ac11cc43503028e699499cefa592e5021",
    "owner": "zasp_discovery_authority",
    "acl": "{zasp_discovery_authority=X/zasp_discovery_authority}"
  },
  {
    "signature": "zasp_sa_attack_lab_prior.compliance_fingerprint()",
    "definitionHash": "b8223564cbcac2146f9352105cc350c43f689235998391c025e4eeb49a9703f9",
    "owner": "zasp_discovery_authority",
    "acl": "{zasp_discovery_authority=X/zasp_discovery_authority}"
  },
  {
    "signature": "zasp_sa_attack_lab_live_fingerprint()",
    "definitionHash": "2c9d57d5cd0cfef9a53da1333a16e59681fac38704ce78d0d4f54f0346d695dc",
    "owner": "zasp_discovery_authority",
    "acl": "{zasp_discovery_authority=X/zasp_discovery_authority}"
  }
];
export function auditWorkerBoundary(capture,{hash}) {
  const wrapper=capture.functions.find(f=>f.signature==='zasp_sa_attack_lab_live_fingerprint()');
  if(!wrapper||hash(wrapper.source)!=='2bba8a12807667b6c63a68215d134ae7c550477d44c57f200292ec182d67417f'
    ||hash(wrapper.definition)!=='09e2e679bd9b085d335e396f45705c0ebaab64ae059b028125791b3da24964c9'
    ||wrapper.owner!=='zasp_discovery_authority'||wrapper.acl!==savedOriginals[5].acl)throw Error('exact composed audit wrapper required');
  const originals=capture.functions.filter(f=>f.schema==='zasp_authorization80_audit');
  const roster=['audit_fingerprint()','budget_fingerprint()','catalog_ready()','compliance_fingerprint()','existing_tests_fingerprint()','fingerprint()','guard_ready()','immutable()','production_ready(text,text,text,text)','projected57()','run_context_fingerprint()','write_guard()'].map(x=>'zasp_authorization80_audit.'+x);
  if(originals.length!==12||new Set(originals.map(f=>f.signature)).size!==12||roster.some(x=>!originals.some(f=>f.signature===x))||originals.some(f=>f.owner!=='zasp_discovery_authority'))throw Error('exact audit boundary roster required');
  const live=[...originals,wrapper].map(f=>({signature:f.signature,definitionHash:hash(f.definition),sourceHash:hash(f.source),owner:f.owner,acl:f.acl}));
  const saved=savedOriginals;
  for(const p of saved.filter(f=>f.signature!=='zasp_sa_attack_lab_live_fingerprint()')) {
    const f=capture.functions.find(f=>f.signature===p.signature);
    if(!f||hash(f.definition)!==p.definitionHash||f.owner!==p.owner||f.acl!==p.acl)throw Error('exact canonical audit predecessor required');
  }
  const payload=JSON.stringify({live,saved});
  if(payload.includes('$audit_worker_records$'))throw Error('audit boundary delimiter');
  const sql=`-- Distinct composed audit boundary; no audit function is copied or fused.
DO $audit_worker_boundary$
DECLARE data jsonb:=$audit_worker_records$${payload}$audit_worker_records$::jsonb; p jsonb;d text;s text;saved_row record;
BEGIN
 IF (SELECT count(*) FROM pg_proc WHERE pronamespace='zasp_authorization80_audit'::regnamespace)<>12
 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='audit worker boundary roster changed';END IF;
 FOR p IN SELECT value FROM jsonb_array_elements(data->'live') LOOP
  SELECT pg_get_functiondef(oid),prosrc INTO STRICT d,s FROM pg_proc WHERE oid=(p->>'signature')::regprocedure;
  IF encode(digest(convert_to(d,'UTF8'),'sha256'),'hex')<>p->>'definitionHash'
   OR encode(digest(convert_to(s,'UTF8'),'sha256'),'hex')<>p->>'sourceHash'
   OR NOT EXISTS(SELECT 1 FROM pg_proc WHERE oid=(p->>'signature')::regprocedure AND proowner::regrole::text=p->>'owner' AND proacl::text IS NOT DISTINCT FROM p->>'acl')
  THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='audit worker exact boundary changed';END IF;
 END LOOP;
 IF (SELECT count(*) FROM zasp_authorization80_audit.predecessor_functions)<>6
 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='audit worker saved roster changed';END IF;
 FOR p IN SELECT value FROM jsonb_array_elements(data->'saved') LOOP
  IF NOT EXISTS(SELECT 1 FROM zasp_authorization80_audit.predecessor_functions WHERE signature=p->>'signature'
   AND encode(digest(convert_to(definition,'UTF8'),'sha256'),'hex')=p->>'definitionHash'
   AND owner_name=p->>'owner' AND acl IS NOT DISTINCT FROM p->>'acl')
  THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='audit worker exact saved predecessor changed';END IF;
 END LOOP;
 IF NOT COALESCE(zasp_authorization80_audit.catalog_ready(),false)
 THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='audit worker catalog rejected';END IF;
 -- The runtime worker fingerprint binds these exact live boundary functions
 -- as well as their immutable saved copies. Installation pins alone are not
 -- a substitute for detecting later catalog drift.
 FOR p IN SELECT value FROM jsonb_array_elements(data->'live') LOOP
  SELECT * INTO saved_row FROM zasp_authorization80_worker.predecessor_functions WHERE signature=p->>'signature';
  IF FOUND AND (saved_row.definition IS DISTINCT FROM pg_get_functiondef((p->>'signature')::regprocedure)
   OR saved_row.owner_name IS DISTINCT FROM p->>'owner' OR saved_row.acl IS DISTINCT FROM p->>'acl')
  THEN RAISE EXCEPTION USING ERRCODE='55000',MESSAGE='audit worker saved boundary changed';END IF;
  INSERT INTO zasp_authorization80_worker.predecessor_functions
   SELECT oid::regprocedure::text,pg_get_functiondef(oid),proowner::regrole::text,COALESCE(proacl::text,'') FROM pg_proc
   WHERE oid=(p->>'signature')::regprocedure ON CONFLICT(signature) DO NOTHING;
 END LOOP;
END $audit_worker_boundary$;
`;
  return {sql,live,saved};
}
