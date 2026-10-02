// Exact selected-field projection for the two independently pinned temporal72
// bodies. This never calls their historical fingerprint/readiness functions.
import {lowerOrderedTemporalCatalog} from './ordered-current-temporal-selectors.mjs';
const shapes=[
  ['72.retained_execution_fingerprint','table','relation',['name','owner','row_security','forced_row_security','execution_acl_text']],
  ['72.retained_execution_fingerprint','function','routine',['name','identity_arguments','owner','security_definer','execution_config_text','execution_acl_text','execution_body']],
  ['72.retained_execution_fingerprint','policy','policy',['relation_name','name','permissive','command','execution_roles_text','using','check']],
  ['72.retained_execution_fingerprint','trigger','trigger',['relation_name','name','execution_definition','enabled','function']],
  ['72.retained_execution_fingerprint','role','role',['name','login','inherit','superuser','create_db','create_role','replication','bypass_rls','execution_v1_managed_here']],
  ['72.retained_precision_fingerprint','function','routine',['namespace_name','name','identity_arguments','owner','security_definer','config_text_or_empty','acl_text_or_empty','precision_definition']]
];
export function lowerOrderedTemporal72Catalog(contract){
  // The accepted component verifies exact source/definition/full-frame pins.
  const original=lowerOrderedTemporalCatalog(contract),rules=[],sites=[],obligations=[];
  for(const [family,branch,kind,fields] of shapes){
    const matches=original.obligations.filter(o=>o.family===family&&o.branch===branch&&o.type==='original-transformation');
    if(matches.length!==1||!matches[0].selector)throw Error('temporal72 exact source site absent');
    const obligation=matches[0],site=original.sites.find(s=>s.sha256===obligation.siteSHA256);
    if(!site)throw Error('temporal72 source provenance absent');
    const id='temporal72:'+(family.includes('precision')?'precision-function':branch);
    rules.push({id,kind,namespaces:[],identities:[],fields:[...fields],selector:structuredClone(obligation.selector),...(kind==='trigger'?{predicate:'user-triggers'}:{})});
    sites.push({...site,ruleId:id});
    obligations.push({...obligation,ruleId:id,disposition:'source-selected direct expression emitted; original caller aggregate and frame obligations remain',required:'Preserve original NULL and empty semantics, SQL array/tuple order, scalar zero-row NULL and multiple-row errors, reg-object resolution errors, fresh role database-marker predicate, original digest and conditional demand/frame. Native expression parity remains unverified.'});
  }
  return {rules,sites,obligations,unsupported:[]};
}
