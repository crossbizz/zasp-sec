import {admitCollectorSource,inspectOrderedCallTokens} from './build-ordered-current-integrity.mjs';
import {definitionAdapter,definitionBody,definitionInstallSQL,identityAdapter,identityArgumentsAdapter,identityArgumentsBody,identityBody} from './ordered-current-deparse-frame.mjs';
const namespace='zasp_authorization80_ordered_current',fail=m=>{throw Error('ordered-current direct frame v1 '+m);},q=v=>"'"+v.replaceAll("'","''")+"'";
const freeze=value=>{if(value&&typeof value==='object')for(const child of Object.values(value))freeze(child);return Object.freeze(value);};
const existing=[{name:definitionAdapter,args:[['value','pg_catalog.oid','26']],body:definitionBody},{name:identityArgumentsAdapter,args:[['value','pg_catalog.oid','26']],body:identityArgumentsBody},{name:identityAdapter,args:[['value','pg_catalog.oid','26']],body:identityBody}];
const additions=[
['relation_identity_public',[['value','pg_catalog.oid','26']],`\nBEGIN\n RETURN value::pg_catalog.regclass::pg_catalog.text;\nEND\n`],
['type_identity_public',[['value','pg_catalog.oid','26']],`\nBEGIN\n RETURN value::pg_catalog.regtype::pg_catalog.text;\nEND\n`],
['format_type_public',[['type_oid','pg_catalog.oid','26'],['type_modifier','integer','23']],`\nBEGIN\n RETURN pg_catalog.format_type(type_oid,type_modifier);\nEND\n`],
['column_default_public',[['default_oid','pg_catalog.oid','26']],`\nBEGIN\n RETURN (SELECT pg_catalog.pg_get_expr(d.adbin,d.adrelid) FROM pg_catalog.pg_attrdef d WHERE d.oid=default_oid);\nEND\n`],
['constraint_definition_public',[['value','pg_catalog.oid','26']],`\nBEGIN\n RETURN pg_catalog.pg_get_constraintdef(value);\nEND\n`],
['constraint_definition_pretty_public',[['value','pg_catalog.oid','26']],`\nBEGIN\n RETURN pg_catalog.pg_get_constraintdef(value,true);\nEND\n`],
['index_definition_public',[['value','pg_catalog.oid','26']],`\nBEGIN\n RETURN pg_catalog.pg_get_indexdef(value);\nEND\n`],
['trigger_definition_public',[['value','pg_catalog.oid','26']],`\nBEGIN\n RETURN pg_catalog.pg_get_triggerdef(value);\nEND\n`],
['trigger_definition_pretty_public',[['value','pg_catalog.oid','26']],`\nBEGIN\n RETURN pg_catalog.pg_get_triggerdef(value,true);\nEND\n`],
['trigger_when_public',[['value','pg_catalog.oid','26']],`\nBEGIN\n RETURN (SELECT pg_catalog.pg_get_expr(t.tgqual,t.tgrelid) FROM pg_catalog.pg_trigger t WHERE t.oid=value);\nEND\n`],
['policy_using_public',[['value','pg_catalog.oid','26']],`\nBEGIN\n RETURN (SELECT pg_catalog.pg_get_expr(p.polqual,p.polrelid) FROM pg_catalog.pg_policy p WHERE p.oid=value);\nEND\n`],
['policy_check_public',[['value','pg_catalog.oid','26']],`\nBEGIN\n RETURN (SELECT pg_catalog.pg_get_expr(p.polwithcheck,p.polrelid) FROM pg_catalog.pg_policy p WHERE p.oid=value);\nEND\n`],
['policy_view_using_public',[['namespace_name','pg_catalog.text','25'],['relation_name','pg_catalog.text','25'],['policy_name','pg_catalog.text','25']],`\nBEGIN\n RETURN (SELECT v.qual::pg_catalog.text FROM pg_catalog.pg_policies v WHERE v.schemaname::pg_catalog.text=namespace_name AND v.tablename::pg_catalog.text=relation_name AND v.policyname::pg_catalog.text=policy_name);\nEND\n`],
['policy_view_check_public',[['namespace_name','pg_catalog.text','25'],['relation_name','pg_catalog.text','25'],['policy_name','pg_catalog.text','25']],`\nBEGIN\n RETURN (SELECT v.with_check::pg_catalog.text FROM pg_catalog.pg_policies v WHERE v.schemaname::pg_catalog.text=namespace_name AND v.tablename::pg_catalog.text=relation_name AND v.policyname::pg_catalog.text=policy_name);\nEND\n`],
['index_view_definition_public',[['namespace_name','pg_catalog.text','25'],['relation_name','pg_catalog.text','25'],['index_name','pg_catalog.text','25']],`\nBEGIN\n RETURN (SELECT v.indexdef::pg_catalog.text FROM pg_catalog.pg_indexes v WHERE v.schemaname::pg_catalog.text=namespace_name AND v.tablename::pg_catalog.text=relation_name AND v.indexname::pg_catalog.text=index_name);\nEND\n`]
].map(([short,args,body])=>({short,name:namespace+'.'+short,args,body}));
export const directFrameVersion=1;
export const directFrameAdaptersV1=freeze([...existing,...additions]);
export const directFrameRuleFieldMatrixV1=freeze([
  {
    "id": "worker:projected_domain:table",
    "kind": "relation",
    "siteSHA256": "5ca344c2a4d66a27a22639d7321edf7cc8d99b06c1d2f6fcc1ac316a7f192aa5",
    "fields": [
      {
        "name": "name",
        "source": "c.relname",
        "adapter": null
      },
      {
        "name": "kind",
        "source": "c.relkind",
        "adapter": null
      },
      {
        "name": "persistence",
        "source": "c.relpersistence",
        "adapter": null
      },
      {
        "name": "owner",
        "source": "c.relowner::regrole::text",
        "adapter": null
      },
      {
        "name": "row_security",
        "source": "c.relrowsecurity",
        "adapter": null
      },
      {
        "name": "forced_row_security",
        "source": "c.relforcerowsecurity",
        "adapter": null
      },
      {
        "name": "acl_text_or_empty",
        "source": "COALESCE(c.relacl::text,'')",
        "adapter": null
      }
    ]
  },
  {
    "id": "worker:projected_domain:foreign-key-trigger",
    "kind": "foreign_key_trigger",
    "siteSHA256": "b8b6991dd738872efe2932a4fc2d89f42cfd875699bf42ba48307a6b04b5d756",
    "fields": [
      {
        "name": "relation",
        "source": "k.conrelid::regclass::text",
        "adapter": "relation_identity_public"
      },
      {
        "name": "name",
        "source": "k.conname",
        "adapter": null
      },
      {
        "name": "referenced_relation",
        "source": "k.confrelid::regclass::text",
        "adapter": "relation_identity_public"
      },
      {
        "name": "trigger_relation",
        "source": "t.tgrelid::regclass::text",
        "adapter": "relation_identity_public"
      },
      {
        "name": "constraint_relation",
        "source": "t.tgconstrrelid::regclass::text",
        "adapter": "relation_identity_public"
      },
      {
        "name": "function",
        "source": "t.tgfoid::regprocedure::text",
        "adapter": "function_identity_public"
      },
      {
        "name": "event_bits",
        "source": "t.tgtype",
        "adapter": null
      },
      {
        "name": "enabled",
        "source": "t.tgenabled",
        "adapter": null
      },
      {
        "name": "deferrable",
        "source": "t.tgdeferrable",
        "adapter": null
      },
      {
        "name": "deferred",
        "source": "t.tginitdeferred",
        "adapter": null
      },
      {
        "name": "argument_count",
        "source": "t.tgnargs",
        "adapter": null
      },
      {
        "name": "arguments",
        "source": "encode(t.tgargs,'hex')",
        "adapter": null
      },
      {
        "name": "columns_text",
        "source": "t.tgattr::text",
        "adapter": null
      },
      {
        "name": "when_text_or_empty",
        "source": "COALESCE(pg_get_expr(t.tgqual,t.tgrelid),'')",
        "adapter": "trigger_when_public"
      }
    ]
  },
  {
    "id": "worker:projected62:table",
    "kind": "relation",
    "siteSHA256": "5e0d8abfcd71ee389fbd5d85e15cfb734343c1bc6c11c0bab8830c09534ebc2e",
    "fields": [
      {
        "name": "name",
        "source": "c.relname",
        "adapter": null
      },
      {
        "name": "kind",
        "source": "c.relkind",
        "adapter": null
      },
      {
        "name": "persistence",
        "source": "c.relpersistence",
        "adapter": null
      },
      {
        "name": "owner",
        "source": "c.relowner::regrole::text",
        "adapter": null
      },
      {
        "name": "row_security",
        "source": "c.relrowsecurity",
        "adapter": null
      },
      {
        "name": "forced_row_security",
        "source": "c.relforcerowsecurity",
        "adapter": null
      },
      {
        "name": "acl_text_or_empty",
        "source": "COALESCE(c.relacl::text,'')",
        "adapter": null
      }
    ]
  },
  {
    "id": "worker:projected68:table",
    "kind": "relation",
    "siteSHA256": "04b2160aeca4c65873c0e2e238576d8c71e9bd12e3c8dd25b471fc9b51d5595a",
    "fields": [
      {
        "name": "name",
        "source": "c.relname",
        "adapter": null
      },
      {
        "name": "kind",
        "source": "c.relkind",
        "adapter": null
      },
      {
        "name": "persistence",
        "source": "c.relpersistence",
        "adapter": null
      },
      {
        "name": "owner",
        "source": "c.relowner::regrole::text",
        "adapter": null
      },
      {
        "name": "row_security",
        "source": "c.relrowsecurity",
        "adapter": null
      },
      {
        "name": "forced_row_security",
        "source": "c.relforcerowsecurity",
        "adapter": null
      },
      {
        "name": "acl_text_or_empty",
        "source": "COALESCE(c.relacl::text,'')",
        "adapter": null
      }
    ]
  },
  {
    "id": "worker:projected68:foreign-key-trigger",
    "kind": "foreign_key_trigger",
    "siteSHA256": "c22a3d1aa479d22de639f2a5020a43ba4dd6fcfce349f107ee909a588bc48db4",
    "fields": [
      {
        "name": "relation",
        "source": "k.conrelid::regclass::text",
        "adapter": "relation_identity_public"
      },
      {
        "name": "name",
        "source": "k.conname",
        "adapter": null
      },
      {
        "name": "referenced_relation",
        "source": "k.confrelid::regclass::text",
        "adapter": "relation_identity_public"
      },
      {
        "name": "trigger_relation",
        "source": "t.tgrelid::regclass::text",
        "adapter": "relation_identity_public"
      },
      {
        "name": "constraint_relation",
        "source": "t.tgconstrrelid::regclass::text",
        "adapter": "relation_identity_public"
      },
      {
        "name": "function",
        "source": "t.tgfoid::regprocedure::text",
        "adapter": "function_identity_public"
      },
      {
        "name": "event_bits",
        "source": "t.tgtype",
        "adapter": null
      },
      {
        "name": "enabled",
        "source": "t.tgenabled",
        "adapter": null
      },
      {
        "name": "deferrable",
        "source": "t.tgdeferrable",
        "adapter": null
      },
      {
        "name": "deferred",
        "source": "t.tginitdeferred",
        "adapter": null
      },
      {
        "name": "argument_count",
        "source": "t.tgnargs",
        "adapter": null
      },
      {
        "name": "arguments",
        "source": "encode(t.tgargs,'hex')",
        "adapter": null
      },
      {
        "name": "columns_text",
        "source": "t.tgattr::text",
        "adapter": null
      },
      {
        "name": "when_text_or_empty",
        "source": "COALESCE(pg_get_expr(t.tgqual,t.tgrelid),'')",
        "adapter": "trigger_when_public"
      }
    ]
  },
  {
    "id": "worker:projected69:table",
    "kind": "relation",
    "siteSHA256": "a6584034a47ba7f356ca7eadbb3a3333242135b676bbb374b6e75cca6e8d3b92",
    "fields": [
      {
        "name": "name",
        "source": "c.relname",
        "adapter": null
      },
      {
        "name": "kind",
        "source": "c.relkind",
        "adapter": null
      },
      {
        "name": "persistence",
        "source": "c.relpersistence",
        "adapter": null
      },
      {
        "name": "owner",
        "source": "c.relowner::regrole::text",
        "adapter": null
      },
      {
        "name": "row_security",
        "source": "c.relrowsecurity",
        "adapter": null
      },
      {
        "name": "forced_row_security",
        "source": "c.relforcerowsecurity",
        "adapter": null
      },
      {
        "name": "acl_text_or_empty",
        "source": "COALESCE(c.relacl::text,'')",
        "adapter": null
      }
    ]
  },
  {
    "id": "worker:projected69:foreign-key-trigger",
    "kind": "foreign_key_trigger",
    "siteSHA256": "f66d2096573693cf60be96afdb4bdd4903d27638ae3dfa3368fc2e6270cf0681",
    "fields": [
      {
        "name": "relation",
        "source": "k.conrelid::regclass::text",
        "adapter": "relation_identity_public"
      },
      {
        "name": "name",
        "source": "k.conname",
        "adapter": null
      },
      {
        "name": "referenced_relation",
        "source": "k.confrelid::regclass::text",
        "adapter": "relation_identity_public"
      },
      {
        "name": "trigger_relation",
        "source": "t.tgrelid::regclass::text",
        "adapter": "relation_identity_public"
      },
      {
        "name": "constraint_relation",
        "source": "t.tgconstrrelid::regclass::text",
        "adapter": "relation_identity_public"
      },
      {
        "name": "function",
        "source": "t.tgfoid::regprocedure::text",
        "adapter": "function_identity_public"
      },
      {
        "name": "event_bits",
        "source": "t.tgtype",
        "adapter": null
      },
      {
        "name": "enabled",
        "source": "t.tgenabled",
        "adapter": null
      },
      {
        "name": "deferrable",
        "source": "t.tgdeferrable",
        "adapter": null
      },
      {
        "name": "deferred",
        "source": "t.tginitdeferred",
        "adapter": null
      },
      {
        "name": "argument_count",
        "source": "t.tgnargs",
        "adapter": null
      },
      {
        "name": "arguments",
        "source": "encode(t.tgargs,'hex')",
        "adapter": null
      },
      {
        "name": "columns_text",
        "source": "t.tgattr::text",
        "adapter": null
      },
      {
        "name": "when_text_or_empty",
        "source": "COALESCE(pg_get_expr(t.tgqual,t.tgrelid),'')",
        "adapter": "trigger_when_public"
      }
    ]
  },
  {
    "id": "worker:projected72:table",
    "kind": "relation",
    "siteSHA256": "f1f7bc44bf035dfccaa8d3e13553a9f491953f0929018db432185a7fed7e045b",
    "fields": [
      {
        "name": "name",
        "source": "c.relname",
        "adapter": null
      },
      {
        "name": "kind",
        "source": "c.relkind",
        "adapter": null
      },
      {
        "name": "persistence",
        "source": "c.relpersistence",
        "adapter": null
      },
      {
        "name": "owner",
        "source": "c.relowner::regrole::text",
        "adapter": null
      },
      {
        "name": "row_security",
        "source": "c.relrowsecurity",
        "adapter": null
      },
      {
        "name": "forced_row_security",
        "source": "c.relforcerowsecurity",
        "adapter": null
      },
      {
        "name": "acl_text_or_empty",
        "source": "COALESCE(c.relacl::text,'')",
        "adapter": null
      }
    ]
  },
  {
    "id": "worker:projected72:foreign-key-trigger",
    "kind": "foreign_key_trigger",
    "siteSHA256": "4301790b86838905142e493e60d784d75f72a3d913223bd09085ef45d63fc987",
    "fields": [
      {
        "name": "relation",
        "source": "k.conrelid::regclass::text",
        "adapter": "relation_identity_public"
      },
      {
        "name": "name",
        "source": "k.conname",
        "adapter": null
      },
      {
        "name": "referenced_relation",
        "source": "k.confrelid::regclass::text",
        "adapter": "relation_identity_public"
      },
      {
        "name": "trigger_relation",
        "source": "t.tgrelid::regclass::text",
        "adapter": "relation_identity_public"
      },
      {
        "name": "constraint_relation",
        "source": "t.tgconstrrelid::regclass::text",
        "adapter": "relation_identity_public"
      },
      {
        "name": "function",
        "source": "t.tgfoid::regprocedure::text",
        "adapter": "function_identity_public"
      },
      {
        "name": "event_bits",
        "source": "t.tgtype",
        "adapter": null
      },
      {
        "name": "enabled",
        "source": "t.tgenabled",
        "adapter": null
      },
      {
        "name": "deferrable",
        "source": "t.tgdeferrable",
        "adapter": null
      },
      {
        "name": "deferred",
        "source": "t.tginitdeferred",
        "adapter": null
      },
      {
        "name": "argument_count",
        "source": "t.tgnargs",
        "adapter": null
      },
      {
        "name": "arguments",
        "source": "encode(t.tgargs,'hex')",
        "adapter": null
      },
      {
        "name": "columns_text",
        "source": "t.tgattr::text",
        "adapter": null
      },
      {
        "name": "when_text_or_empty",
        "source": "COALESCE(pg_get_expr(t.tgqual,t.tgrelid),'')",
        "adapter": "trigger_when_public"
      }
    ]
  },
  {
    "id": "worker:projected78:table",
    "kind": "relation",
    "siteSHA256": "63ebe8e7e5b6f968107135cc6d75df37f977a64fead02d1e74258c736c581ab9",
    "fields": [
      {
        "name": "name",
        "source": "c.relname",
        "adapter": null
      },
      {
        "name": "kind",
        "source": "c.relkind",
        "adapter": null
      },
      {
        "name": "persistence",
        "source": "c.relpersistence",
        "adapter": null
      },
      {
        "name": "owner",
        "source": "c.relowner::regrole::text",
        "adapter": null
      },
      {
        "name": "row_security",
        "source": "c.relrowsecurity",
        "adapter": null
      },
      {
        "name": "forced_row_security",
        "source": "c.relforcerowsecurity",
        "adapter": null
      },
      {
        "name": "acl_text_or_empty",
        "source": "COALESCE(c.relacl::text,'')",
        "adapter": null
      }
    ]
  },
  {
    "id": "worker:projected78:foreign-key-trigger",
    "kind": "foreign_key_trigger",
    "siteSHA256": "bebeda2b3cd7c21569cb8ac2fc9ac4547eb57d6e1e6487c841d382784b216e93",
    "fields": [
      {
        "name": "relation",
        "source": "k.conrelid::regclass::text",
        "adapter": "relation_identity_public"
      },
      {
        "name": "name",
        "source": "k.conname",
        "adapter": null
      },
      {
        "name": "referenced_relation",
        "source": "k.confrelid::regclass::text",
        "adapter": "relation_identity_public"
      },
      {
        "name": "trigger_relation",
        "source": "t.tgrelid::regclass::text",
        "adapter": "relation_identity_public"
      },
      {
        "name": "constraint_relation",
        "source": "t.tgconstrrelid::regclass::text",
        "adapter": "relation_identity_public"
      },
      {
        "name": "function",
        "source": "t.tgfoid::regprocedure::text",
        "adapter": "function_identity_public"
      },
      {
        "name": "event_bits",
        "source": "t.tgtype",
        "adapter": null
      },
      {
        "name": "enabled",
        "source": "t.tgenabled",
        "adapter": null
      },
      {
        "name": "deferrable",
        "source": "t.tgdeferrable",
        "adapter": null
      },
      {
        "name": "deferred",
        "source": "t.tginitdeferred",
        "adapter": null
      },
      {
        "name": "argument_count",
        "source": "t.tgnargs",
        "adapter": null
      },
      {
        "name": "arguments",
        "source": "encode(t.tgargs,'hex')",
        "adapter": null
      },
      {
        "name": "columns_text",
        "source": "t.tgattr::text",
        "adapter": null
      },
      {
        "name": "when_text_or_empty",
        "source": "COALESCE(pg_get_expr(t.tgqual,t.tgrelid),'')",
        "adapter": "trigger_when_public"
      }
    ]
  },
  {
    "id": "worker-edge:gateway_projected24:2",
    "kind": "relation",
    "siteSHA256": "e9c9fe4be8deb3c910d9122d6fa875c7c7423d54f45499c8b963877e4d9d4a75",
    "fields": [
      {
        "name": "name",
        "source": "class.relname",
        "adapter": null
      },
      {
        "name": "owner",
        "source": "owner.rolname",
        "adapter": null
      },
      {
        "name": "row_security",
        "source": "class.relrowsecurity",
        "adapter": null
      },
      {
        "name": "forced_row_security",
        "source": "class.relforcerowsecurity",
        "adapter": null
      },
      {
        "name": "acl_text_or_empty",
        "source": "COALESCE(class.relacl::text,'')",
        "adapter": null
      }
    ]
  },
  {
    "id": "worker-edge:gateway_projected24:3",
    "kind": "column_name",
    "siteSHA256": "46350524406c96806713733d4f462a6f4b84e7e1f0aa1946944e08a4c67f6d23",
    "fields": [
      {
        "name": "name",
        "source": "attribute.attname",
        "adapter": null
      },
      {
        "name": "type_identity",
        "source": "attribute.atttypid::regtype::text",
        "adapter": "type_identity_public"
      },
      {
        "name": "not_null",
        "source": "attribute.attnotnull",
        "adapter": null
      },
      {
        "name": "identity",
        "source": "attribute.attidentity",
        "adapter": null
      },
      {
        "name": "generated",
        "source": "attribute.attgenerated",
        "adapter": null
      },
      {
        "name": "default_text_or_empty",
        "source": "COALESCE(pg_get_expr(default_value.adbin,default_value.adrelid),'')",
        "adapter": "column_default_public"
      }
    ]
  },
  {
    "id": "worker-edge:gateway_projected24:4",
    "kind": "constraint",
    "siteSHA256": "68ebaa4333b7b8517434c8ab86ab609d7aeb6c6a7b7ab3b8682db3f3ff5d960c",
    "fields": [
      {
        "name": "name",
        "source": "constraint_value.conname",
        "adapter": null
      },
      {
        "name": "constraint_type",
        "source": "constraint_value.contype",
        "adapter": null
      },
      {
        "name": "validated",
        "source": "constraint_value.convalidated",
        "adapter": null
      },
      {
        "name": "deferrable",
        "source": "constraint_value.condeferrable",
        "adapter": null
      },
      {
        "name": "deferred",
        "source": "constraint_value.condeferred",
        "adapter": null
      },
      {
        "name": "definition_pretty",
        "source": "pg_get_constraintdef(constraint_value.oid,true)",
        "adapter": "constraint_definition_pretty_public"
      }
    ]
  },
  {
    "id": "worker-edge:gateway_projected24:5",
    "kind": "index",
    "siteSHA256": "1efeac2037574c90ab05cd942361bedc4dd26aad8a581db327dc8cdadae2c42f",
    "fields": [
      {
        "name": "name",
        "source": "index_class.relname",
        "adapter": null
      },
      {
        "name": "valid",
        "source": "index_value.indisvalid",
        "adapter": null
      },
      {
        "name": "ready",
        "source": "index_value.indisready",
        "adapter": null
      },
      {
        "name": "unique",
        "source": "index_value.indisunique",
        "adapter": null
      },
      {
        "name": "primary",
        "source": "index_value.indisprimary",
        "adapter": null
      },
      {
        "name": "definition",
        "source": "pg_get_indexdef(index_value.indexrelid)",
        "adapter": "index_definition_public"
      }
    ]
  },
  {
    "id": "worker-edge:gateway_projected24:7",
    "kind": "constraint",
    "siteSHA256": "d1ab331b4310d553ae5ffa9d2476d69a2b34c2266c0c64c7616dfb3f13dd3ce0",
    "fields": [
      {
        "name": "name",
        "source": "conname",
        "adapter": null
      },
      {
        "name": "validated",
        "source": "convalidated",
        "adapter": null
      },
      {
        "name": "definition_pretty",
        "source": "pg_get_constraintdef(oid,true)",
        "adapter": "constraint_definition_pretty_public"
      }
    ]
  },
  {
    "id": "worker-edge:gateway_projected27:2",
    "kind": "role",
    "siteSHA256": "b0b465c0d40fc3c9ca132503cc6849e140037b6575d13933d3ea56aac2d41a3d",
    "fields": [
      {
        "name": "name",
        "source": "rolname",
        "adapter": null
      },
      {
        "name": "superuser",
        "source": "rolsuper",
        "adapter": null
      },
      {
        "name": "inherit",
        "source": "rolinherit",
        "adapter": null
      },
      {
        "name": "create_role",
        "source": "rolcreaterole",
        "adapter": null
      },
      {
        "name": "create_db",
        "source": "rolcreatedb",
        "adapter": null
      },
      {
        "name": "login",
        "source": "rolcanlogin",
        "adapter": null
      },
      {
        "name": "replication",
        "source": "rolreplication",
        "adapter": null
      },
      {
        "name": "bypass_rls",
        "source": "rolbypassrls",
        "adapter": null
      }
    ]
  },
  {
    "id": "worker-edge:gateway_projected27:4",
    "kind": "relation",
    "siteSHA256": "245ddcb83299b58ea6f413cd4cb034359cbec8746e75a17d262f79203e7fc6d4",
    "fields": [
      {
        "name": "name",
        "source": "class.relname",
        "adapter": null
      },
      {
        "name": "owner",
        "source": "owner.rolname",
        "adapter": null
      },
      {
        "name": "row_security",
        "source": "class.relrowsecurity",
        "adapter": null
      },
      {
        "name": "forced_row_security",
        "source": "class.relforcerowsecurity",
        "adapter": null
      },
      {
        "name": "acl_text_or_empty",
        "source": "COALESCE(class.relacl::text,'')",
        "adapter": null
      }
    ]
  },
  {
    "id": "worker-edge:gateway_projected27:5",
    "kind": "class_index",
    "siteSHA256": "f94f8450370782ba61e236387f6eeb4ee25549d37cd2a2ce4e3b4ee31922073d",
    "fields": [
      {
        "name": "name",
        "source": "class.relname",
        "adapter": null
      },
      {
        "name": "definition",
        "source": "pg_get_indexdef(class.oid)",
        "adapter": "index_definition_public"
      }
    ]
  },
  {
    "id": "worker-edge:gateway_projected27:6",
    "kind": "column_name",
    "siteSHA256": "10de19c7fc4fdd536e76c20260c4450cfc928015bd01b247bcd90b82fc2bf5e9",
    "fields": [
      {
        "name": "relation_name",
        "source": "class.relname",
        "adapter": null
      },
      {
        "name": "name",
        "source": "attribute.attname",
        "adapter": null
      },
      {
        "name": "type_identity",
        "source": "attribute.atttypid::regtype::text",
        "adapter": "type_identity_public"
      },
      {
        "name": "not_null",
        "source": "attribute.attnotnull",
        "adapter": null
      },
      {
        "name": "default_text_or_empty",
        "source": "COALESCE(pg_get_expr(default_value.adbin,default_value.adrelid),'')",
        "adapter": "column_default_public"
      }
    ]
  },
  {
    "id": "worker-edge:gateway_projected27:7",
    "kind": "constraint",
    "siteSHA256": "44cd6c19c5ad613a1f37c54615f42ec14809553986c54d607325632cda37cff9",
    "fields": [
      {
        "name": "relation_name",
        "source": "class.relname",
        "adapter": null
      },
      {
        "name": "name",
        "source": "constraint_value.conname",
        "adapter": null
      },
      {
        "name": "constraint_type",
        "source": "constraint_value.contype",
        "adapter": null
      },
      {
        "name": "validated",
        "source": "constraint_value.convalidated",
        "adapter": null
      },
      {
        "name": "definition_pretty",
        "source": "pg_get_constraintdef(constraint_value.oid,true)",
        "adapter": "constraint_definition_pretty_public"
      }
    ]
  },
  {
    "id": "worker-edge:gateway_projected27:8",
    "kind": "column_all",
    "siteSHA256": "df5bafd1e8a67a80b8dadee8c07c53e07ad22d372eec6ed615261e4636cabdd5",
    "fields": [
      {
        "name": "relation_name",
        "source": "class.relname",
        "adapter": null
      },
      {
        "name": "name",
        "source": "attribute.attname",
        "adapter": null
      },
      {
        "name": "type_identity",
        "source": "attribute.atttypid::regtype::text",
        "adapter": "type_identity_public"
      },
      {
        "name": "not_null",
        "source": "attribute.attnotnull",
        "adapter": null
      },
      {
        "name": "default_text_or_empty",
        "source": "COALESCE(pg_get_expr(default_value.adbin,default_value.adrelid),'')",
        "adapter": "column_default_public"
      }
    ]
  },
  {
    "id": "worker-edge:gateway_projected27:9",
    "kind": "constraint",
    "siteSHA256": "52e2cbac575b4f2df5e7c2fe7286813a9ae412d98757fdf81ef59b5fbeff7642",
    "fields": [
      {
        "name": "relation_name",
        "source": "class.relname",
        "adapter": null
      },
      {
        "name": "name",
        "source": "constraint_value.conname",
        "adapter": null
      },
      {
        "name": "constraint_type",
        "source": "constraint_value.contype",
        "adapter": null
      },
      {
        "name": "validated",
        "source": "constraint_value.convalidated",
        "adapter": null
      },
      {
        "name": "definition_pretty",
        "source": "pg_get_constraintdef(constraint_value.oid,true)",
        "adapter": "constraint_definition_pretty_public"
      }
    ]
  },
  {
    "id": "worker-edge:gateway_projected27:10",
    "kind": "index",
    "siteSHA256": "f7c4c120b46d969cc189e03ffaa185863e11590c5bbe210a77831c4ed443eeb2",
    "fields": [
      {
        "name": "name",
        "source": "index_class.relname",
        "adapter": null
      },
      {
        "name": "owner",
        "source": "owner.rolname",
        "adapter": null
      },
      {
        "name": "valid",
        "source": "index_value.indisvalid",
        "adapter": null
      },
      {
        "name": "ready",
        "source": "index_value.indisready",
        "adapter": null
      },
      {
        "name": "unique",
        "source": "index_value.indisunique",
        "adapter": null
      },
      {
        "name": "primary",
        "source": "index_value.indisprimary",
        "adapter": null
      },
      {
        "name": "definition",
        "source": "pg_get_indexdef(index_value.indexrelid)",
        "adapter": "index_definition_public"
      }
    ]
  },
  {
    "id": "worker-edge:gateway_projected27:11",
    "kind": "policy",
    "siteSHA256": "afb257d1776d2ed31461c69a15317d0ddae44eaa182db54e050bbd7f5be491a4",
    "fields": [
      {
        "name": "relation_name",
        "source": "class.relname",
        "adapter": null
      },
      {
        "name": "name",
        "source": "policy.polname",
        "adapter": null
      },
      {
        "name": "permissive",
        "source": "policy.polpermissive",
        "adapter": null
      },
      {
        "name": "using",
        "source": "pg_get_expr(policy.polqual,policy.polrelid)",
        "adapter": "policy_using_public"
      },
      {
        "name": "check",
        "source": "pg_get_expr(policy.polwithcheck,policy.polrelid)",
        "adapter": "policy_check_public"
      }
    ]
  },
  {
    "id": "worker-edge:gateway_projected27:12",
    "kind": "trigger",
    "siteSHA256": "be9387bc9be2e60c2ff8990a462255091b1110f1ecae9bdfbb689156fe7fc133",
    "fields": [
      {
        "name": "relation_name",
        "source": "class.relname",
        "adapter": null
      },
      {
        "name": "name",
        "source": "trigger.tgname",
        "adapter": null
      },
      {
        "name": "definition_pretty",
        "source": "pg_get_triggerdef(trigger.oid,true)",
        "adapter": "trigger_definition_pretty_public"
      }
    ]
  },
  {
    "id": "worker-edge:ordered_projected28:2",
    "kind": "role",
    "siteSHA256": "f0d87fde1d7025ae277659b6af43554bbf485658b619fde670df71f11e978808",
    "fields": [
      {
        "name": "name",
        "source": "rolname",
        "adapter": null
      },
      {
        "name": "superuser",
        "source": "rolsuper",
        "adapter": null
      },
      {
        "name": "inherit",
        "source": "rolinherit",
        "adapter": null
      },
      {
        "name": "create_role",
        "source": "rolcreaterole",
        "adapter": null
      },
      {
        "name": "create_db",
        "source": "rolcreatedb",
        "adapter": null
      },
      {
        "name": "login",
        "source": "rolcanlogin",
        "adapter": null
      },
      {
        "name": "replication",
        "source": "rolreplication",
        "adapter": null
      },
      {
        "name": "bypass_rls",
        "source": "rolbypassrls",
        "adapter": null
      }
    ]
  },
  {
    "id": "worker-edge:ordered_projected28:4",
    "kind": "relation",
    "siteSHA256": "c2b425562b4ae48b4d79a55d34ead5929fceaf4b38cb71a4fbbe01036d1a0205",
    "fields": [
      {
        "name": "name",
        "source": "class.relname",
        "adapter": null
      },
      {
        "name": "owner",
        "source": "owner.rolname",
        "adapter": null
      },
      {
        "name": "row_security",
        "source": "class.relrowsecurity",
        "adapter": null
      },
      {
        "name": "forced_row_security",
        "source": "class.relforcerowsecurity",
        "adapter": null
      },
      {
        "name": "acl_text_or_empty",
        "source": "COALESCE(class.relacl::text,'')",
        "adapter": null
      }
    ]
  },
  {
    "id": "worker-edge:ordered_projected28:5",
    "kind": "column_name",
    "siteSHA256": "e0bcf92804a634db1f253bc43dcb9262fcbd906df8f5eb69b9bcfe736c56fc1b",
    "fields": [
      {
        "name": "relation_name",
        "source": "class.relname",
        "adapter": null
      },
      {
        "name": "name",
        "source": "attribute.attname",
        "adapter": null
      },
      {
        "name": "type_identity",
        "source": "attribute.atttypid::regtype::text",
        "adapter": "type_identity_public"
      },
      {
        "name": "not_null",
        "source": "attribute.attnotnull",
        "adapter": null
      },
      {
        "name": "identity",
        "source": "attribute.attidentity",
        "adapter": null
      },
      {
        "name": "generated",
        "source": "attribute.attgenerated",
        "adapter": null
      },
      {
        "name": "default_text_or_empty",
        "source": "COALESCE(pg_get_expr(default_value.adbin,default_value.adrelid),'')",
        "adapter": "column_default_public"
      }
    ]
  },
  {
    "id": "worker-edge:ordered_projected28:6",
    "kind": "class_index",
    "siteSHA256": "b5a99215fe700e3ac2b79d35a6457c1bdd74d8f50454fe237bf036228824437b",
    "fields": [
      {
        "name": "name",
        "source": "class.relname",
        "adapter": null
      },
      {
        "name": "definition",
        "source": "pg_get_indexdef(class.oid)",
        "adapter": "index_definition_public"
      }
    ]
  },
  {
    "id": "worker-edge:ordered_projected28:7",
    "kind": "constraint",
    "siteSHA256": "ddd6842407161173ed4c7029d78a4c009894c85af63d35a2562234bd33f20d77",
    "fields": [
      {
        "name": "relation_name",
        "source": "class.relname",
        "adapter": null
      },
      {
        "name": "name",
        "source": "constraint_value.conname",
        "adapter": null
      },
      {
        "name": "constraint_type",
        "source": "constraint_value.contype",
        "adapter": null
      },
      {
        "name": "validated",
        "source": "constraint_value.convalidated",
        "adapter": null
      },
      {
        "name": "definition_pretty",
        "source": "pg_get_constraintdef(constraint_value.oid,true)",
        "adapter": "constraint_definition_pretty_public"
      }
    ]
  },
  {
    "id": "worker-edge:ordered_projected28:8",
    "kind": "policy",
    "siteSHA256": "72ad6aa1ae7ef515dd891f96f93068293e2b25c4c2cbc2d3280c76180f16c34c",
    "fields": [
      {
        "name": "relation_name",
        "source": "class.relname",
        "adapter": null
      },
      {
        "name": "name",
        "source": "policy.polname",
        "adapter": null
      },
      {
        "name": "permissive",
        "source": "policy.polpermissive",
        "adapter": null
      },
      {
        "name": "using",
        "source": "pg_get_expr(policy.polqual,policy.polrelid)",
        "adapter": "policy_using_public"
      },
      {
        "name": "check",
        "source": "pg_get_expr(policy.polwithcheck,policy.polrelid)",
        "adapter": "policy_check_public"
      }
    ]
  },
  {
    "id": "worker-edge:ordered_projected28:9",
    "kind": "trigger",
    "siteSHA256": "b48e38ee107d8084d71e348f2695df99dacf88104cf842ef416c1a2dd2b95aed",
    "fields": [
      {
        "name": "relation_name",
        "source": "class.relname",
        "adapter": null
      },
      {
        "name": "name",
        "source": "trigger.tgname",
        "adapter": null
      },
      {
        "name": "definition_pretty",
        "source": "pg_get_triggerdef(trigger.oid,true)",
        "adapter": "trigger_definition_pretty_public"
      }
    ]
  },
  {
    "id": "worker-edge:runtime_projected40:3",
    "kind": "relation",
    "siteSHA256": "e6eb18e969bb007f7d1d08d5548f062396f1eca6d7caea530b0686b009cdc838",
    "fields": [
      {
        "name": "name",
        "source": "relname",
        "adapter": null
      },
      {
        "name": "owner",
        "source": "relowner::regrole::text",
        "adapter": null
      },
      {
        "name": "row_security",
        "source": "relrowsecurity",
        "adapter": null
      },
      {
        "name": "forced_row_security",
        "source": "relforcerowsecurity",
        "adapter": null
      },
      {
        "name": "acl_text_or_empty",
        "source": "COALESCE(relacl::text,'')",
        "adapter": null
      }
    ]
  },
  {
    "id": "worker-edge:runtime_projected40:4",
    "kind": "constraint",
    "siteSHA256": "650dccd48b1213d5f2698b04b42ba2fad9ac0b2f9ec40374e2c562032a0d081c",
    "fields": [
      {
        "name": "name",
        "source": "conname",
        "adapter": null
      },
      {
        "name": "definition",
        "source": "pg_get_constraintdef(oid)",
        "adapter": "constraint_definition_public"
      },
      {
        "name": "validated",
        "source": "convalidated",
        "adapter": null
      }
    ]
  },
  {
    "id": "worker-edge:runtime_projected40:5",
    "kind": "column_name",
    "siteSHA256": "fb3b63008e3c892a7ddde4be7e4de3a219a8e8e6313b20ee4f943a0470d392e6",
    "fields": [
      {
        "name": "relation",
        "source": "attrelid::regclass::text",
        "adapter": "relation_identity_public"
      },
      {
        "name": "name",
        "source": "attname",
        "adapter": null
      },
      {
        "name": "type",
        "source": "format_type(atttypid,atttypmod)",
        "adapter": "format_type_public"
      },
      {
        "name": "not_null",
        "source": "attnotnull",
        "adapter": null
      }
    ]
  },
  {
    "id": "worker-edge:runtime_projected40:6",
    "kind": "policy_view",
    "siteSHA256": "cba972a0aed323021da16bbcf8218c825d8ccb4c6cf205646e96c7abc5655e7d",
    "fields": [
      {
        "name": "namespace_name",
        "source": "schemaname",
        "adapter": null
      },
      {
        "name": "table_name",
        "source": "tablename",
        "adapter": null
      },
      {
        "name": "name",
        "source": "policyname",
        "adapter": null
      },
      {
        "name": "roles_text",
        "source": "roles::text",
        "adapter": null
      },
      {
        "name": "command",
        "source": "cmd",
        "adapter": null
      },
      {
        "name": "using",
        "source": "qual",
        "adapter": "policy_view_using_public"
      },
      {
        "name": "check",
        "source": "with_check",
        "adapter": "policy_view_check_public"
      }
    ]
  },
  {
    "id": "worker-edge:runtime_projected40:7",
    "kind": "index_view",
    "siteSHA256": "dffb28eb1661e5639fd2c0c01b6383f9d81a8b4cfe344ca0524c7939684af6ac",
    "fields": [
      {
        "name": "name",
        "source": "indexname",
        "adapter": null
      },
      {
        "name": "definition",
        "source": "indexdef",
        "adapter": "index_view_definition_public"
      }
    ]
  },
  {
    "id": "worker-edge:runtime_projected50_binding:3",
    "kind": "routine",
    "siteSHA256": "f121c97497d151d2e0c1afda4e8bce501e6a9a658f4f7a4643d7b0a2fd7cdad8",
    "fields": [
      {
        "name": "name",
        "source": "p.proname",
        "adapter": null
      },
      {
        "name": "identity_arguments",
        "source": "pg_get_function_identity_arguments(p.oid)",
        "adapter": "function_identity_arguments_public"
      },
      {
        "name": "owner",
        "source": "r.rolname",
        "adapter": null
      },
      {
        "name": "security_definer",
        "source": "p.prosecdef",
        "adapter": null
      },
      {
        "name": "config_text_or_empty",
        "source": "COALESCE(p.proconfig::text,'')",
        "adapter": null
      },
      {
        "name": "acl_text_or_empty",
        "source": "COALESCE(p.proacl::text,'')",
        "adapter": null
      },
      {
        "name": "definition",
        "source": "pg_get_functiondef(p.oid)",
        "adapter": "function_definition_public"
      },
      {
        "name": "config_json",
        "source": "to_jsonb(p.proconfig)",
        "adapter": null
      },
      {
        "name": "config_raw",
        "source": "p.proconfig::text",
        "adapter": null
      },
      {
        "name": "config_dims",
        "source": "array_dims(p.proconfig)",
        "adapter": null
      },
      {
        "name": "config_ndims",
        "source": "array_ndims(p.proconfig)",
        "adapter": null
      },
      {
        "name": "config_bounds",
        "source": "(SELECT jsonb_agg(jsonb_build_array(array_lower(p.proconfig,dimension),array_upper(p.proconfig,dimension)) ORDER BY dimension) FROM generate_series(1,array_ndims(p.proconfig)) dimension)",
        "adapter": null
      }
    ]
  },
  {
    "id": "worker-edge:runtime_projected50_binding:4",
    "kind": "trigger",
    "siteSHA256": "3eddfb5f9059e4e585be99b6f18c1a23b77152cb8730f2d322db609903e63bd4",
    "fields": [
      {
        "name": "name",
        "source": "t.tgname",
        "adapter": null
      },
      {
        "name": "enabled",
        "source": "t.tgenabled",
        "adapter": null
      },
      {
        "name": "definition_pretty",
        "source": "pg_get_triggerdef(t.oid,true)",
        "adapter": "trigger_definition_pretty_public"
      }
    ]
  },
  {
    "id": "worker-edge:runtime_projected50_binding:5",
    "kind": "routine",
    "siteSHA256": "d2c6c0101d5b181aa4ef5bde3b19bdfd77c421fee844151bfee35a98c3b0ad1f",
    "fields": [
      {
        "name": "name",
        "source": "p.proname",
        "adapter": null
      },
      {
        "name": "identity_arguments",
        "source": "pg_get_function_identity_arguments(p.oid)",
        "adapter": "function_identity_arguments_public"
      },
      {
        "name": "owner",
        "source": "r.rolname",
        "adapter": null
      },
      {
        "name": "security_definer",
        "source": "p.prosecdef",
        "adapter": null
      },
      {
        "name": "config_text_or_empty",
        "source": "COALESCE(p.proconfig::text,'')",
        "adapter": null
      },
      {
        "name": "acl_text_or_empty",
        "source": "COALESCE(p.proacl::text,'')",
        "adapter": null
      },
      {
        "name": "definition",
        "source": "pg_get_functiondef(p.oid)",
        "adapter": "function_definition_public"
      },
      {
        "name": "config_json",
        "source": "to_jsonb(p.proconfig)",
        "adapter": null
      },
      {
        "name": "config_raw",
        "source": "p.proconfig::text",
        "adapter": null
      },
      {
        "name": "config_dims",
        "source": "array_dims(p.proconfig)",
        "adapter": null
      },
      {
        "name": "config_ndims",
        "source": "array_ndims(p.proconfig)",
        "adapter": null
      },
      {
        "name": "config_bounds",
        "source": "(SELECT jsonb_agg(jsonb_build_array(array_lower(p.proconfig,dimension),array_upper(p.proconfig,dimension)) ORDER BY dimension) FROM generate_series(1,array_ndims(p.proconfig)) dimension)",
        "adapter": null
      }
    ]
  },
  {
    "id": "worker-edge:runtime_projected50_binding:6",
    "kind": "column_name",
    "siteSHA256": "20d93878604962d4266abe0fb48b1d7cdc93d55151f18e4e78f310d206760037",
    "fields": [
      {
        "name": "name",
        "source": "attname",
        "adapter": null
      },
      {
        "name": "acl_text_or_empty",
        "source": "COALESCE(attacl::text,'')",
        "adapter": null
      }
    ]
  },
  {
    "id": "worker-edge:runtime_projected50_binding:7",
    "kind": "routine",
    "siteSHA256": "f5c3c0faa3cea9960342917f7d4ad1a8f0ac2ddcd62984fe39653b203d6b709b",
    "fields": [
      {
        "name": "name",
        "source": "p.proname",
        "adapter": null
      },
      {
        "name": "identity_arguments",
        "source": "pg_get_function_identity_arguments(p.oid)",
        "adapter": "function_identity_arguments_public"
      },
      {
        "name": "owner",
        "source": "r.rolname",
        "adapter": null
      },
      {
        "name": "security_definer",
        "source": "p.prosecdef",
        "adapter": null
      },
      {
        "name": "config_text_or_empty",
        "source": "COALESCE(p.proconfig::text,'')",
        "adapter": null
      },
      {
        "name": "acl_text_or_empty",
        "source": "COALESCE(p.proacl::text,'')",
        "adapter": null
      },
      {
        "name": "definition",
        "source": "pg_get_functiondef(p.oid)",
        "adapter": "function_definition_public"
      },
      {
        "name": "config_json",
        "source": "to_jsonb(p.proconfig)",
        "adapter": null
      },
      {
        "name": "config_raw",
        "source": "p.proconfig::text",
        "adapter": null
      },
      {
        "name": "config_dims",
        "source": "array_dims(p.proconfig)",
        "adapter": null
      },
      {
        "name": "config_ndims",
        "source": "array_ndims(p.proconfig)",
        "adapter": null
      },
      {
        "name": "config_bounds",
        "source": "(SELECT jsonb_agg(jsonb_build_array(array_lower(p.proconfig,dimension),array_upper(p.proconfig,dimension)) ORDER BY dimension) FROM generate_series(1,array_ndims(p.proconfig)) dimension)",
        "adapter": null
      }
    ]
  },
  {
    "id": "worker-edge:runtime_projected50_binding:8",
    "kind": "routine",
    "siteSHA256": "f6aa4e7d2f81029aca3b8dd55b2fc622566f0585f2d8e666e41018ffd07a788a",
    "fields": [
      {
        "name": "name",
        "source": "p.proname",
        "adapter": null
      },
      {
        "name": "identity_arguments",
        "source": "pg_get_function_identity_arguments(p.oid)",
        "adapter": "function_identity_arguments_public"
      },
      {
        "name": "owner",
        "source": "r.rolname",
        "adapter": null
      },
      {
        "name": "security_definer",
        "source": "p.prosecdef",
        "adapter": null
      },
      {
        "name": "config_text_or_empty",
        "source": "COALESCE(p.proconfig::text,'')",
        "adapter": null
      },
      {
        "name": "acl_text_or_empty",
        "source": "COALESCE(p.proacl::text,'')",
        "adapter": null
      },
      {
        "name": "definition",
        "source": "pg_get_functiondef(p.oid)",
        "adapter": "function_definition_public"
      },
      {
        "name": "config_json",
        "source": "to_jsonb(p.proconfig)",
        "adapter": null
      },
      {
        "name": "config_raw",
        "source": "p.proconfig::text",
        "adapter": null
      },
      {
        "name": "config_dims",
        "source": "array_dims(p.proconfig)",
        "adapter": null
      },
      {
        "name": "config_ndims",
        "source": "array_ndims(p.proconfig)",
        "adapter": null
      },
      {
        "name": "config_bounds",
        "source": "(SELECT jsonb_agg(jsonb_build_array(array_lower(p.proconfig,dimension),array_upper(p.proconfig,dimension)) ORDER BY dimension) FROM generate_series(1,array_ndims(p.proconfig)) dimension)",
        "adapter": null
      }
    ]
  },
  {
    "id": "worker-edge:runtime_projected50_search:4",
    "kind": "relation",
    "siteSHA256": "50db93b00c09cbb5eef92959ba2537c24421037076e79c617df6bdc4c96e609f",
    "fields": [
      {
        "name": "name",
        "source": "relname",
        "adapter": null
      },
      {
        "name": "owner",
        "source": "relowner::regrole::text",
        "adapter": null
      },
      {
        "name": "row_security",
        "source": "relrowsecurity",
        "adapter": null
      },
      {
        "name": "forced_row_security",
        "source": "relforcerowsecurity",
        "adapter": null
      },
      {
        "name": "acl_text_or_empty",
        "source": "COALESCE(relacl::text,'')",
        "adapter": null
      }
    ]
  },
  {
    "id": "worker-edge:runtime_projected50_search:5",
    "kind": "constraint",
    "siteSHA256": "6328a179e9b52935e06e713838622e63e000eb063b4597573085195dbf11a278",
    "fields": [
      {
        "name": "name",
        "source": "conname",
        "adapter": null
      },
      {
        "name": "definition",
        "source": "pg_get_constraintdef(oid)",
        "adapter": "constraint_definition_public"
      },
      {
        "name": "validated",
        "source": "convalidated",
        "adapter": null
      }
    ]
  },
  {
    "id": "worker-edge:runtime_projected50_search:6",
    "kind": "column_name",
    "siteSHA256": "fced3aef4f4259490e9a993a3b194c813793bbcaede9fb5bbc3d36d20c5eb2b2",
    "fields": [
      {
        "name": "name",
        "source": "attname",
        "adapter": null
      },
      {
        "name": "type",
        "source": "format_type(atttypid,atttypmod)",
        "adapter": "format_type_public"
      },
      {
        "name": "not_null",
        "source": "attnotnull",
        "adapter": null
      },
      {
        "name": "acl_text_or_empty",
        "source": "COALESCE(attacl::text,'')",
        "adapter": null
      },
      {
        "name": "default_text_or_empty",
        "source": "COALESCE(pg_get_expr(d.adbin,d.adrelid),'')",
        "adapter": "column_default_public"
      }
    ]
  },
  {
    "id": "worker-edge:runtime_projected50_search:7",
    "kind": "policy_view",
    "siteSHA256": "44e137548ca73830fe9fd3dc05491ca79cec05d9bb8099a554ba538cd8cbe884",
    "fields": [
      {
        "name": "name",
        "source": "policyname",
        "adapter": null
      },
      {
        "name": "roles_text",
        "source": "roles::text",
        "adapter": null
      },
      {
        "name": "command",
        "source": "cmd",
        "adapter": null
      },
      {
        "name": "using",
        "source": "qual",
        "adapter": "policy_view_using_public"
      },
      {
        "name": "check",
        "source": "with_check",
        "adapter": "policy_view_check_public"
      }
    ]
  },
  {
    "id": "worker-edge:runtime_projected50_search:8",
    "kind": "index_view",
    "siteSHA256": "7477722b06765e6d09a2f3ae4c85096efa44fb34b22c42130f61564b332eb00a",
    "fields": [
      {
        "name": "name",
        "source": "indexname",
        "adapter": null
      },
      {
        "name": "definition",
        "source": "indexdef",
        "adapter": "index_view_definition_public"
      }
    ]
  },
  {
    "id": "worker-edge:runtime_projected50_search:9",
    "kind": "trigger",
    "siteSHA256": "1ec1db3130f6e3e9fe412d3909d3226c94f822ef4fcc445f53f0beed48afb252",
    "fields": [
      {
        "name": "relation",
        "source": "tgrelid::regclass::text",
        "adapter": "relation_identity_public"
      },
      {
        "name": "name",
        "source": "tgname",
        "adapter": null
      },
      {
        "name": "enabled",
        "source": "tgenabled",
        "adapter": null
      },
      {
        "name": "definition",
        "source": "pg_get_triggerdef(oid)",
        "adapter": "trigger_definition_public"
      }
    ]
  }
]);
export const directFrameRulesV1=freeze([
  {
    "id": "worker:projected_domain:table",
    "kind": "relation",
    "namespaces": [],
    "identities": [],
    "fields": [
      "name",
      "kind",
      "persistence",
      "owner",
      "row_security",
      "forced_row_security",
      "acl_text_or_empty"
    ],
    "selector": {
      "all": [
        {
          "field": "namespace",
          "equals": "public"
        },
        {
          "any": [
            {
              "field": "name",
              "equals": "zasp_integrations"
            },
            {
              "field": "name",
              "equals": "zasp_integration_connections"
            },
            {
              "field": "name",
              "equals": "zasp_discovery_connection_subjects"
            },
            {
              "field": "name",
              "equals": "zasp_connector_credentials"
            },
            {
              "field": "name",
              "equals": "zasp_discovery_syncs"
            },
            {
              "field": "name",
              "equals": "zasp_discovery_outbox"
            },
            {
              "field": "name",
              "equals": "zasp_discovery_outbox_topic_fairness"
            },
            {
              "field": "name",
              "equals": "zasp_discovery_generation_reservations"
            },
            {
              "field": "name",
              "equals": "zasp_discovery_jobs"
            },
            {
              "field": "name",
              "equals": "zasp_discovery_job_authorities"
            },
            {
              "field": "name",
              "equals": "zasp_discovery_job_checkpoints"
            },
            {
              "field": "name",
              "equals": "zasp_discovery_execution_quotas"
            },
            {
              "field": "name",
              "equals": "zasp_discovery_snapshots"
            },
            {
              "field": "name",
              "equals": "zasp_discovery_cursors"
            },
            {
              "field": "name",
              "equals": "zasp_inventory_entities"
            },
            {
              "field": "name",
              "equals": "zasp_inventory_evidence"
            },
            {
              "field": "name",
              "equals": "zasp_inventory_source_observations"
            },
            {
              "field": "name",
              "equals": "zasp_inventory_relationships"
            },
            {
              "field": "name",
              "equals": "zasp_inventory_identity_rules"
            },
            {
              "field": "name",
              "equals": "zasp_inventory_identity_bindings"
            },
            {
              "field": "name",
              "equals": "zasp_projection_work"
            },
            {
              "field": "name",
              "equals": "zasp_discovery_snapshot_inputs"
            },
            {
              "field": "name",
              "equals": "zasp_discovery_snapshot_projection_items"
            }
          ]
        }
      ]
    }
  },
  {
    "id": "worker:projected_domain:foreign-key-trigger",
    "kind": "foreign_key_trigger",
    "namespaces": [],
    "identities": [],
    "fields": [
      "relation",
      "name",
      "referenced_relation",
      "trigger_relation",
      "constraint_relation",
      "function",
      "event_bits",
      "enabled",
      "deferrable",
      "deferred",
      "argument_count",
      "arguments",
      "columns_text",
      "when_text_or_empty"
    ],
    "selector": {
      "all": [
        {
          "field": "namespace",
          "equals": "public"
        },
        {
          "any": [
            {
              "field": "relation_name",
              "equals": "zasp_integrations"
            },
            {
              "field": "relation_name",
              "equals": "zasp_integration_connections"
            },
            {
              "field": "relation_name",
              "equals": "zasp_discovery_connection_subjects"
            },
            {
              "field": "relation_name",
              "equals": "zasp_connector_credentials"
            },
            {
              "field": "relation_name",
              "equals": "zasp_discovery_syncs"
            },
            {
              "field": "relation_name",
              "equals": "zasp_discovery_outbox"
            },
            {
              "field": "relation_name",
              "equals": "zasp_discovery_outbox_topic_fairness"
            },
            {
              "field": "relation_name",
              "equals": "zasp_discovery_generation_reservations"
            },
            {
              "field": "relation_name",
              "equals": "zasp_discovery_jobs"
            },
            {
              "field": "relation_name",
              "equals": "zasp_discovery_job_authorities"
            },
            {
              "field": "relation_name",
              "equals": "zasp_discovery_job_checkpoints"
            },
            {
              "field": "relation_name",
              "equals": "zasp_discovery_execution_quotas"
            },
            {
              "field": "relation_name",
              "equals": "zasp_discovery_snapshots"
            },
            {
              "field": "relation_name",
              "equals": "zasp_discovery_cursors"
            },
            {
              "field": "relation_name",
              "equals": "zasp_inventory_entities"
            },
            {
              "field": "relation_name",
              "equals": "zasp_inventory_evidence"
            },
            {
              "field": "relation_name",
              "equals": "zasp_inventory_source_observations"
            },
            {
              "field": "relation_name",
              "equals": "zasp_inventory_relationships"
            },
            {
              "field": "relation_name",
              "equals": "zasp_inventory_identity_rules"
            },
            {
              "field": "relation_name",
              "equals": "zasp_inventory_identity_bindings"
            },
            {
              "field": "relation_name",
              "equals": "zasp_projection_work"
            },
            {
              "field": "relation_name",
              "equals": "zasp_discovery_snapshot_inputs"
            },
            {
              "field": "relation_name",
              "equals": "zasp_discovery_snapshot_projection_items"
            }
          ]
        }
      ]
    }
  },
  {
    "id": "worker:projected62:table",
    "kind": "relation",
    "namespaces": [],
    "identities": [],
    "fields": [
      "name",
      "kind",
      "persistence",
      "owner",
      "row_security",
      "forced_row_security",
      "acl_text_or_empty"
    ],
    "selector": {
      "field": "namespace",
      "equals": "zasp_ordered_public62"
    }
  },
  {
    "id": "worker:projected68:table",
    "kind": "relation",
    "namespaces": [],
    "identities": [],
    "fields": [
      "name",
      "kind",
      "persistence",
      "owner",
      "row_security",
      "forced_row_security",
      "acl_text_or_empty"
    ],
    "selector": {
      "field": "namespace",
      "equals": "zasp_temporal68"
    }
  },
  {
    "id": "worker:projected68:foreign-key-trigger",
    "kind": "foreign_key_trigger",
    "namespaces": [],
    "identities": [],
    "fields": [
      "relation",
      "name",
      "referenced_relation",
      "trigger_relation",
      "constraint_relation",
      "function",
      "event_bits",
      "enabled",
      "deferrable",
      "deferred",
      "argument_count",
      "arguments",
      "columns_text",
      "when_text_or_empty"
    ],
    "selector": {
      "field": "namespace",
      "equals": "zasp_temporal68"
    }
  },
  {
    "id": "worker:projected69:table",
    "kind": "relation",
    "namespaces": [],
    "identities": [],
    "fields": [
      "name",
      "kind",
      "persistence",
      "owner",
      "row_security",
      "forced_row_security",
      "acl_text_or_empty"
    ],
    "selector": {
      "field": "namespace",
      "equals": "zasp_temporal69"
    }
  },
  {
    "id": "worker:projected69:foreign-key-trigger",
    "kind": "foreign_key_trigger",
    "namespaces": [],
    "identities": [],
    "fields": [
      "relation",
      "name",
      "referenced_relation",
      "trigger_relation",
      "constraint_relation",
      "function",
      "event_bits",
      "enabled",
      "deferrable",
      "deferred",
      "argument_count",
      "arguments",
      "columns_text",
      "when_text_or_empty"
    ],
    "selector": {
      "field": "namespace",
      "equals": "zasp_temporal69"
    }
  },
  {
    "id": "worker:projected72:table",
    "kind": "relation",
    "namespaces": [],
    "identities": [],
    "fields": [
      "name",
      "kind",
      "persistence",
      "owner",
      "row_security",
      "forced_row_security",
      "acl_text_or_empty"
    ],
    "selector": {
      "field": "namespace",
      "equals": "zasp_temporal72"
    }
  },
  {
    "id": "worker:projected72:foreign-key-trigger",
    "kind": "foreign_key_trigger",
    "namespaces": [],
    "identities": [],
    "fields": [
      "relation",
      "name",
      "referenced_relation",
      "trigger_relation",
      "constraint_relation",
      "function",
      "event_bits",
      "enabled",
      "deferrable",
      "deferred",
      "argument_count",
      "arguments",
      "columns_text",
      "when_text_or_empty"
    ],
    "selector": {
      "field": "namespace",
      "equals": "zasp_temporal72"
    }
  },
  {
    "id": "worker:projected78:table",
    "kind": "relation",
    "namespaces": [],
    "identities": [],
    "fields": [
      "name",
      "kind",
      "persistence",
      "owner",
      "row_security",
      "forced_row_security",
      "acl_text_or_empty"
    ],
    "selector": {
      "field": "namespace",
      "equals": "zasp_temporal78"
    }
  },
  {
    "id": "worker:projected78:foreign-key-trigger",
    "kind": "foreign_key_trigger",
    "namespaces": [],
    "identities": [],
    "fields": [
      "relation",
      "name",
      "referenced_relation",
      "trigger_relation",
      "constraint_relation",
      "function",
      "event_bits",
      "enabled",
      "deferrable",
      "deferred",
      "argument_count",
      "arguments",
      "columns_text",
      "when_text_or_empty"
    ],
    "selector": {
      "field": "namespace",
      "equals": "zasp_temporal78"
    }
  },
  {
    "id": "worker-edge:gateway_projected24:2",
    "kind": "relation",
    "namespaces": [],
    "identities": [],
    "fields": [
      "name",
      "owner",
      "row_security",
      "forced_row_security",
      "acl_text_or_empty"
    ],
    "selector": {
      "all": [
        {
          "field": "namespace",
          "equals": "public"
        },
        {
          "all": [
            {
              "field": "name",
              "equals": "zasp_security_agent_temporary_policy_targets"
            },
            {
              "any": [
                {
                  "field": "relation_kind",
                  "equals": "r"
                },
                {
                  "field": "relation_kind",
                  "equals": "i"
                }
              ]
            }
          ]
        }
      ]
    }
  },
  {
    "id": "worker-edge:gateway_projected24:3",
    "kind": "column_name",
    "namespaces": [],
    "identities": [],
    "fields": [
      "name",
      "type_identity",
      "not_null",
      "identity",
      "generated",
      "default_text_or_empty"
    ],
    "selector": {
      "field": "relation",
      "equals": "public.zasp_security_agent_temporary_policy_targets"
    }
  },
  {
    "id": "worker-edge:gateway_projected24:4",
    "kind": "constraint",
    "namespaces": [],
    "identities": [],
    "fields": [
      "name",
      "constraint_type",
      "validated",
      "deferrable",
      "deferred",
      "definition_pretty"
    ],
    "selector": {
      "field": "relation",
      "equals": "public.zasp_security_agent_temporary_policy_targets"
    }
  },
  {
    "id": "worker-edge:gateway_projected24:5",
    "kind": "index",
    "namespaces": [],
    "identities": [],
    "fields": [
      "name",
      "valid",
      "ready",
      "unique",
      "primary",
      "definition"
    ],
    "selector": {
      "any": [
        {
          "all": [
            {
              "field": "relation",
              "equals": "public.zasp_runtime_gateway_events"
            },
            {
              "field": "name",
              "equals": "zasp_runtime_gateway_events_session_v24_idx"
            }
          ]
        },
        {
          "field": "relation",
          "equals": "public.zasp_security_agent_temporary_policy_targets"
        }
      ]
    }
  },
  {
    "id": "worker-edge:gateway_projected24:7",
    "kind": "constraint",
    "namespaces": [],
    "identities": [],
    "fields": [
      "name",
      "validated",
      "definition_pretty"
    ],
    "selector": {
      "all": [
        {
          "field": "relation",
          "equals": "public.zasp_security_agent_definitions"
        },
        {
          "field": "name",
          "equals": "zasp_security_agent_session_isolation_supervised_check"
        }
      ]
    }
  },
  {
    "id": "worker-edge:gateway_projected27:2",
    "kind": "role",
    "namespaces": [],
    "identities": [],
    "fields": [
      "name",
      "superuser",
      "inherit",
      "create_role",
      "create_db",
      "login",
      "replication",
      "bypass_rls"
    ],
    "selector": {
      "any": [
        {
          "field": "name",
          "equals": "zasp_recovery_worker"
        },
        {
          "field": "name",
          "equals": "zasp_recovery_outbox_worker"
        }
      ]
    }
  },
  {
    "id": "worker-edge:gateway_projected27:4",
    "kind": "relation",
    "namespaces": [],
    "identities": [],
    "fields": [
      "name",
      "owner",
      "row_security",
      "forced_row_security",
      "acl_text_or_empty"
    ],
    "selector": {
      "all": [
        {
          "field": "namespace",
          "equals": "public"
        },
        {
          "all": [
            {
              "field": "name",
              "like": "zasp_recovery_%"
            },
            {
              "any": [
                {
                  "field": "relation_kind",
                  "equals": "r"
                },
                {
                  "field": "relation_kind",
                  "equals": "i"
                }
              ]
            }
          ]
        }
      ]
    }
  },
  {
    "id": "worker-edge:gateway_projected27:5",
    "kind": "class_index",
    "namespaces": [],
    "identities": [],
    "fields": [
      "name",
      "definition"
    ],
    "selector": {
      "all": [
        {
          "field": "namespace",
          "equals": "public"
        },
        {
          "all": [
            {
              "field": "name",
              "like": "zasp_recovery_%"
            },
            {
              "field": "relation_kind",
              "equals": "i"
            }
          ]
        }
      ]
    }
  },
  {
    "id": "worker-edge:gateway_projected27:6",
    "kind": "column_name",
    "namespaces": [],
    "identities": [],
    "fields": [
      "relation_name",
      "name",
      "type_identity",
      "not_null",
      "default_text_or_empty"
    ],
    "selector": {
      "all": [
        {
          "field": "namespace",
          "equals": "public"
        },
        {
          "field": "relation_name",
          "like": "zasp_recovery_%"
        }
      ]
    }
  },
  {
    "id": "worker-edge:gateway_projected27:7",
    "kind": "constraint",
    "namespaces": [],
    "identities": [],
    "fields": [
      "relation_name",
      "name",
      "constraint_type",
      "validated",
      "definition_pretty"
    ],
    "selector": {
      "field": "relation_name",
      "like": "zasp_recovery_%"
    }
  },
  {
    "id": "worker-edge:gateway_projected27:8",
    "kind": "column_all",
    "namespaces": [],
    "identities": [],
    "fields": [
      "relation_name",
      "name",
      "type_identity",
      "not_null",
      "default_text_or_empty"
    ],
    "selector": {
      "all": [
        {
          "field": "namespace",
          "equals": "public"
        },
        {
          "all": [
            {
              "field": "relation_name",
              "equals": "zasp_runtime_gateway_events"
            },
            {
              "field": "name",
              "equals": "policy_ids"
            }
          ]
        }
      ]
    }
  },
  {
    "id": "worker-edge:gateway_projected27:9",
    "kind": "constraint",
    "namespaces": [],
    "identities": [],
    "fields": [
      "relation_name",
      "name",
      "constraint_type",
      "validated",
      "definition_pretty"
    ],
    "selector": {
      "all": [
        {
          "field": "relation_name",
          "equals": "zasp_runtime_gateway_events"
        },
        {
          "field": "name",
          "equals": "zasp_runtime_gateway_events_policy_ids_v27_ck"
        }
      ]
    }
  },
  {
    "id": "worker-edge:gateway_projected27:10",
    "kind": "index",
    "namespaces": [],
    "identities": [],
    "fields": [
      "name",
      "owner",
      "valid",
      "ready",
      "unique",
      "primary",
      "definition"
    ],
    "selector": {
      "all": [
        {
          "field": "relation",
          "equals": "public.zasp_runtime_gateway_events"
        },
        {
          "any": [
            {
              "field": "name",
              "equals": "zasp_runtime_gateway_events_policy_ids_v27_idx"
            },
            {
              "field": "name",
              "equals": "zasp_runtime_gateway_events_policy_history_v27_idx"
            }
          ]
        }
      ]
    }
  },
  {
    "id": "worker-edge:gateway_projected27:11",
    "kind": "policy",
    "namespaces": [],
    "identities": [],
    "fields": [
      "relation_name",
      "name",
      "permissive",
      "using",
      "check"
    ],
    "selector": {
      "field": "relation_name",
      "like": "zasp_recovery_%"
    }
  },
  {
    "id": "worker-edge:gateway_projected27:12",
    "kind": "trigger",
    "namespaces": [],
    "identities": [],
    "fields": [
      "relation_name",
      "name",
      "definition_pretty"
    ],
    "selector": {
      "all": [
        {
          "field": "namespace",
          "equals": "public"
        },
        {
          "field": "name",
          "like": "%_recovery_hold"
        }
      ]
    },
    "predicate": "user-triggers"
  },
  {
    "id": "worker-edge:ordered_projected28:2",
    "kind": "role",
    "namespaces": [],
    "identities": [],
    "fields": [
      "name",
      "superuser",
      "inherit",
      "create_role",
      "create_db",
      "login",
      "replication",
      "bypass_rls"
    ],
    "selector": {
      "field": "name",
      "equals": "zasp_policy_deployment_worker"
    }
  },
  {
    "id": "worker-edge:ordered_projected28:4",
    "kind": "relation",
    "namespaces": [],
    "identities": [],
    "fields": [
      "name",
      "owner",
      "row_security",
      "forced_row_security",
      "acl_text_or_empty"
    ],
    "selector": {
      "all": [
        {
          "field": "namespace",
          "equals": "public"
        },
        {
          "all": [
            {
              "field": "name",
              "like": "zasp_policy_deployment_%"
            },
            {
              "any": [
                {
                  "field": "relation_kind",
                  "equals": "r"
                },
                {
                  "field": "relation_kind",
                  "equals": "i"
                }
              ]
            }
          ]
        }
      ]
    }
  },
  {
    "id": "worker-edge:ordered_projected28:5",
    "kind": "column_name",
    "namespaces": [],
    "identities": [],
    "fields": [
      "relation_name",
      "name",
      "type_identity",
      "not_null",
      "identity",
      "generated",
      "default_text_or_empty"
    ],
    "selector": {
      "all": [
        {
          "field": "namespace",
          "equals": "public"
        },
        {
          "any": [
            {
              "field": "relation_name",
              "like": "zasp_policy_deployment_%"
            },
            {
              "any": [
                {
                  "field": "relation_name",
                  "equals": "zasp_security_agent_temporary_policy_targets"
                },
                {
                  "field": "relation_name",
                  "equals": "zasp_security_agent_session_policy_targets"
                }
              ]
            }
          ]
        }
      ]
    }
  },
  {
    "id": "worker-edge:ordered_projected28:6",
    "kind": "class_index",
    "namespaces": [],
    "identities": [],
    "fields": [
      "name",
      "definition"
    ],
    "selector": {
      "all": [
        {
          "field": "namespace",
          "equals": "public"
        },
        {
          "all": [
            {
              "field": "name",
              "like": "zasp_policy_deployment_%"
            },
            {
              "field": "relation_kind",
              "equals": "i"
            }
          ]
        }
      ]
    }
  },
  {
    "id": "worker-edge:ordered_projected28:7",
    "kind": "constraint",
    "namespaces": [],
    "identities": [],
    "fields": [
      "relation_name",
      "name",
      "constraint_type",
      "validated",
      "definition_pretty"
    ],
    "selector": {
      "field": "relation_name",
      "like": "zasp_policy_deployment_%"
    }
  },
  {
    "id": "worker-edge:ordered_projected28:8",
    "kind": "policy",
    "namespaces": [],
    "identities": [],
    "fields": [
      "relation_name",
      "name",
      "permissive",
      "using",
      "check"
    ],
    "selector": {
      "field": "relation_name",
      "like": "zasp_policy_deployment_%"
    }
  },
  {
    "id": "worker-edge:ordered_projected28:9",
    "kind": "trigger",
    "namespaces": [],
    "identities": [],
    "fields": [
      "relation_name",
      "name",
      "definition_pretty"
    ],
    "selector": {
      "any": [
        {
          "field": "name",
          "like": "%policy_deployment%"
        },
        {
          "field": "name",
          "like": "%policy_sequence"
        },
        {
          "field": "name",
          "like": "%policy_verify"
        }
      ]
    }
  },
  {
    "id": "worker-edge:runtime_projected40:3",
    "kind": "relation",
    "namespaces": [],
    "identities": [],
    "fields": [
      "name",
      "owner",
      "row_security",
      "forced_row_security",
      "acl_text_or_empty"
    ],
    "selector": {
      "any": [
        {
          "field": "identity",
          "equals": "public.zasp_runtime_session_events"
        },
        {
          "field": "identity",
          "equals": "public.zasp_runtime_session_projection_receipts"
        }
      ]
    }
  },
  {
    "id": "worker-edge:runtime_projected40:4",
    "kind": "constraint",
    "namespaces": [],
    "identities": [],
    "fields": [
      "name",
      "definition",
      "validated"
    ],
    "selector": {
      "any": [
        {
          "field": "relation",
          "equals": "public.zasp_runtime_session_events"
        },
        {
          "field": "relation",
          "equals": "public.zasp_runtime_session_projection_receipts"
        }
      ]
    }
  },
  {
    "id": "worker-edge:runtime_projected40:5",
    "kind": "column_name",
    "namespaces": [],
    "identities": [],
    "fields": [
      "relation",
      "name",
      "type",
      "not_null"
    ],
    "selector": {
      "any": [
        {
          "field": "relation",
          "equals": "public.zasp_runtime_session_events"
        },
        {
          "field": "relation",
          "equals": "public.zasp_runtime_session_projection_receipts"
        }
      ]
    }
  },
  {
    "id": "worker-edge:runtime_projected40:6",
    "kind": "policy_view",
    "namespaces": [],
    "identities": [],
    "fields": [
      "namespace_name",
      "table_name",
      "name",
      "roles_text",
      "command",
      "using",
      "check"
    ],
    "selector": {
      "all": [
        {
          "field": "namespace",
          "equals": "public"
        },
        {
          "any": [
            {
              "field": "table_name",
              "equals": "zasp_runtime_session_events"
            },
            {
              "field": "table_name",
              "equals": "zasp_runtime_session_projection_receipts"
            }
          ]
        }
      ]
    }
  },
  {
    "id": "worker-edge:runtime_projected40:7",
    "kind": "index_view",
    "namespaces": [],
    "identities": [],
    "fields": [
      "name",
      "definition"
    ],
    "selector": {
      "all": [
        {
          "field": "namespace",
          "equals": "public"
        },
        {
          "any": [
            {
              "field": "table_name",
              "equals": "zasp_runtime_session_events"
            },
            {
              "field": "table_name",
              "equals": "zasp_runtime_session_projection_receipts"
            }
          ]
        }
      ]
    }
  },
  {
    "id": "worker-edge:runtime_projected50_binding:3",
    "kind": "routine",
    "namespaces": [],
    "identities": [],
    "fields": [
      "name",
      "identity_arguments",
      "owner",
      "security_definer",
      "config_text_or_empty",
      "acl_text_or_empty",
      "definition"
    ],
    "selector": {
      "all": [
        {
          "field": "namespace",
          "equals": "public"
        },
        {
          "any": [
            {
              "field": "name",
              "equals": "zasp_runtime_claim_session_stage_compatible"
            },
            {
              "field": "name",
              "equals": "zasp_runtime_session_claim_version_guard"
            },
            {
              "field": "name",
              "equals": "zasp_runtime_claim_projection_v2"
            },
            {
              "field": "name",
              "equals": "zasp_runtime_claim_completion_v2"
            }
          ]
        }
      ]
    }
  },
  {
    "id": "worker-edge:runtime_projected50_binding:4",
    "kind": "trigger",
    "namespaces": [],
    "identities": [],
    "fields": [
      "name",
      "enabled",
      "definition_pretty"
    ],
    "selector": {
      "all": [
        {
          "field": "relation",
          "equals": "public.zasp_runtime_stage_work"
        },
        {
          "field": "name",
          "equals": "zasp_runtime_session_claim_version"
        }
      ]
    }
  },
  {
    "id": "worker-edge:runtime_projected50_binding:5",
    "kind": "routine",
    "namespaces": [],
    "identities": [],
    "fields": [
      "name",
      "identity_arguments",
      "owner",
      "security_definer",
      "config_text_or_empty",
      "acl_text_or_empty",
      "definition"
    ],
    "selector": {
      "field": "identity",
      "equals": "public.zasp_runtime_finish_sandbox_session_projection(text,text,text,text,bigint,text,text,integer,bytea,text,text,bytea,text,text,bytea,text,integer,bytea)"
    }
  },
  {
    "id": "worker-edge:runtime_projected50_binding:6",
    "kind": "column_name",
    "namespaces": [],
    "identities": [],
    "fields": [
      "name",
      "acl_text_or_empty"
    ],
    "selector": {
      "field": "relation",
      "equals": "public.zasp_runtime_session_events"
    }
  },
  {
    "id": "worker-edge:runtime_projected50_binding:7",
    "kind": "routine",
    "namespaces": [],
    "identities": [],
    "fields": [
      "name",
      "identity_arguments",
      "owner",
      "security_definer",
      "config_text_or_empty",
      "acl_text_or_empty",
      "definition"
    ],
    "selector": {
      "any": [
        {
          "field": "identity",
          "regprocedureEquals": "public.zasp_runtime_sandbox_session_event_page(text,text,text,text,text,timestamptz,text,integer)"
        },
        {
          "field": "identity",
          "regprocedureEquals": "public.zasp_runtime_sandbox_session_event_get(text,text,text,text,text,text)"
        }
      ]
    }
  },
  {
    "id": "worker-edge:runtime_projected50_binding:8",
    "kind": "routine",
    "namespaces": [],
    "identities": [],
    "fields": [
      "name",
      "identity_arguments",
      "owner",
      "security_definer",
      "config_text_or_empty",
      "acl_text_or_empty",
      "definition"
    ],
    "selector": {
      "all": [
        {
          "field": "namespace",
          "equals": "public"
        },
        {
          "any": [
            {
              "field": "name",
              "equals": "zasp_runtime_claim_stage_sandbox_compatible"
            },
            {
              "field": "name",
              "equals": "zasp_runtime_claim_correlation_v3"
            },
            {
              "field": "name",
              "equals": "zasp_runtime_freeze_sandbox_candidates"
            },
            {
              "field": "name",
              "equals": "zasp_production_runtime_sandbox_binding_security_ready"
            },
            {
              "field": "name",
              "equals": "zasp_production_runtime_sandbox_binding_readiness"
            },
            {
              "field": "name",
              "equals": "zasp_production_runtime_correlation_routing_readiness_v49"
            },
            {
              "field": "name",
              "equals": "zasp_production_runtime_candidate_authority_live_fingerprint"
            }
          ]
        }
      ]
    }
  },
  {
    "id": "worker-edge:runtime_projected50_search:4",
    "kind": "relation",
    "namespaces": [],
    "identities": [],
    "fields": [
      "name",
      "owner",
      "row_security",
      "forced_row_security",
      "acl_text_or_empty"
    ],
    "selector": {
      "field": "identity",
      "equals": "public.zasp_runtime_sandbox_search_outbox"
    }
  },
  {
    "id": "worker-edge:runtime_projected50_search:5",
    "kind": "constraint",
    "namespaces": [],
    "identities": [],
    "fields": [
      "name",
      "definition",
      "validated"
    ],
    "selector": {
      "field": "relation",
      "equals": "public.zasp_runtime_sandbox_search_outbox"
    }
  },
  {
    "id": "worker-edge:runtime_projected50_search:6",
    "kind": "column_name",
    "namespaces": [],
    "identities": [],
    "fields": [
      "name",
      "type",
      "not_null",
      "acl_text_or_empty",
      "default_text_or_empty"
    ],
    "selector": {
      "field": "relation",
      "equals": "public.zasp_runtime_sandbox_search_outbox"
    }
  },
  {
    "id": "worker-edge:runtime_projected50_search:7",
    "kind": "policy_view",
    "namespaces": [],
    "identities": [],
    "fields": [
      "name",
      "roles_text",
      "command",
      "using",
      "check"
    ],
    "selector": {
      "all": [
        {
          "field": "namespace",
          "equals": "public"
        },
        {
          "field": "table_name",
          "equals": "zasp_runtime_sandbox_search_outbox"
        }
      ]
    }
  },
  {
    "id": "worker-edge:runtime_projected50_search:8",
    "kind": "index_view",
    "namespaces": [],
    "identities": [],
    "fields": [
      "name",
      "definition"
    ],
    "selector": {
      "all": [
        {
          "field": "namespace",
          "equals": "public"
        },
        {
          "field": "table_name",
          "equals": "zasp_runtime_sandbox_search_outbox"
        }
      ]
    }
  },
  {
    "id": "worker-edge:runtime_projected50_search:9",
    "kind": "trigger",
    "namespaces": [],
    "identities": [],
    "fields": [
      "relation",
      "name",
      "enabled",
      "definition"
    ],
    "selector": {
      "any": [
        {
          "field": "relation",
          "equals": "public.zasp_runtime_session_projection_receipts"
        },
        {
          "field": "relation",
          "equals": "public.zasp_runtime_sandbox_search_outbox"
        },
        {
          "field": "relation",
          "equals": "public.zasp_runtime_session_search_outbox"
        }
      ]
    },
    "predicate": "user-triggers"
  }
]);
if(directFrameAdaptersV1.length!==18||directFrameRuleFieldMatrixV1.length!==50||directFrameRulesV1.length!==50||directFrameRuleFieldMatrixV1.reduce((n,r)=>n+r.fields.length,0)!==321||directFrameRuleFieldMatrixV1.flatMap(r=>r.fields).filter(f=>f.adapter!==null).length!==76)fail('static inventory');
const ddl=s=>`CREATE FUNCTION ${s.name}(${s.args.map(([n,t])=>n+' '+t).join(', ')})
RETURNS pg_catalog.text LANGUAGE plpgsql STABLE SECURITY INVOKER PARALLEL UNSAFE
SET search_path=pg_catalog,public SET TimeZone='UTC'
AS $body$${s.body}$body$;
ALTER FUNCTION ${s.name}(${s.args.map(([,t])=>t).join(', ')}) OWNER TO zasp_discovery_authority;
REVOKE ALL ON FUNCTION ${s.name}(${s.args.map(([,t])=>t).join(', ')}) FROM PUBLIC;`;
export const directFrameInstallSQL=definitionInstallSQL+'\n'+additions.map(ddl).join('\n');
const expected=directFrameAdaptersV1.map(s=>`(${q(s.name.split('.').at(-1))},${q(s.args.map(a=>a[2]).join(' '))}::pg_catalog.oidvector,ARRAY[${s.args.map(a=>q(a[0])).join(',')}]::pg_catalog.text[],${q(s.body)},${s.args.length})`).join(',');
export const directFrameAdmissionSQL=`WITH expected AS (VALUES ${expected})
SELECT count(*)=18 AND count(DISTINCT p.proname)=18 AND COALESCE(bool_and((
 n.nspowner='zasp_discovery_authority'::pg_catalog.regrole AND n.nspacl::text='{zasp_discovery_authority=UC/zasp_discovery_authority}'
 AND p.proowner='zasp_discovery_authority'::pg_catalog.regrole AND p.proacl::text='{zasp_discovery_authority=X/zasp_discovery_authority}'
 AND l.lanname='plpgsql' AND p.prokind='f' AND NOT p.prosecdef AND p.provolatile='s' AND NOT p.proisstrict AND p.proparallel='u' AND NOT p.proleakproof
 AND NOT p.proretset AND p.prorettype='pg_catalog.text'::pg_catalog.regtype AND p.pronargs=e.column5
 AND p.proargtypes=e.column2 AND p.proargnames=e.column3 AND p.proallargtypes IS NULL AND p.proargmodes IS NULL
 AND p.pronargdefaults=0 AND p.proargdefaults IS NULL AND p.provariadic=0 AND p.prosupport=0 AND p.protrftypes IS NULL
 AND p.procost=100 AND p.prorows=0 AND p.proconfig=ARRAY['search_path=pg_catalog, public','TimeZone=UTC']::pg_catalog.text[]
 AND p.prosrc=e.column4 AND p.probin IS NULL AND p.prosqlbody IS NULL) IS TRUE),false) AS admitted
FROM expected e JOIN pg_catalog.pg_proc p ON p.proname=e.column1
JOIN pg_catalog.pg_namespace n ON n.oid=p.pronamespace AND n.nspname=${q(namespace)}
JOIN pg_catalog.pg_language l ON l.oid=p.prolang`;
const byRule=new Map(directFrameRuleFieldMatrixV1.map(r=>[r.id,r])),sourceRuleById=new Map(directFrameRulesV1.map(r=>[r.id,r])),extras=['config_json','config_raw','config_dims','config_ndims','config_bounds'];
export function bindOrderedDirectFrameV1(rules){if(!Array.isArray(rules)||rules.length!==50)fail('rule coverage');const seen=new Set();for(const r of rules){const e=byRule.get(r?.id),source=sourceRuleById.get(r?.id);if(!e||!source||seen.has(r.id)||r.kind!==e.kind||JSON.stringify(r)!==JSON.stringify(source))fail('rule binding');seen.add(r.id);const f=r.kind==='routine'&&r.id.startsWith('worker-edge:runtime_projected50_binding:')?[...r.fields,...extras]:r.fields;if(JSON.stringify(f)!==JSON.stringify(e.fields.map(x=>x.name)))fail(r.id+' selected fields');}if(seen.size!==50)fail('rule closure');return directFrameRuleFieldMatrixV1;}
const call=(n,a)=>namespace+'.'+n+'('+a.join(',')+')';
export function directFrameExpressionV1(ruleId,kind,field,base){const r=byRule.get(ruleId),e=r?.fields.find(x=>x.name===field);if(!r||r.kind!==kind||!e||typeof base!=='string'||!base)fail('field binding');if(e.adapter===null)return base;const fk={relation:'k.conrelid',referenced_relation:'k.confrelid',trigger_relation:'t.tgrelid',constraint_relation:'t.tgconstrrelid'};switch(e.adapter){case'function_definition_public':return definitionAdapter+'(p.oid)';case'function_identity_arguments_public':return identityArgumentsAdapter+'(p.oid)';case'function_identity_public':return identityAdapter+'(t.tgfoid)';case'relation_identity_public':return call(e.adapter,[kind==='foreign_key_trigger'?fk[field]:kind==='trigger'?'t.tgrelid':'a.attrelid']);case'type_identity_public':return call(e.adapter,['a.atttypid']);case'format_type_public':return call(e.adapter,['a.atttypid','a.atttypmod']);case'column_default_public':return 'COALESCE('+call(e.adapter,['d.oid'])+",'')";case'constraint_definition_public':case'constraint_definition_pretty_public':return call(e.adapter,['k.oid']);case'index_definition_public':return call(e.adapter,[kind==='class_index'?'c.oid':'i.indexrelid']);case'trigger_definition_public':case'trigger_definition_pretty_public':case'trigger_when_public':return (e.adapter==='trigger_when_public'?'COALESCE(':'')+call(e.adapter,['t.oid'])+(e.adapter==='trigger_when_public'?",'')":'');case'policy_using_public':case'policy_check_public':return call(e.adapter,['p.oid']);case'policy_view_using_public':case'policy_view_check_public':return call(e.adapter,['v.schemaname::text','v.tablename::text','v.policyname::text']);case'index_view_definition_public':return call(e.adapter,['v.schemaname::text','v.tablename::text','v.indexname::text']);default:fail('adapter binding');}}
export function admitOrderedDirectFrameSourceV1(sql){if(typeof sql!=='string'||!sql.includes(directFrameAdmissionSQL))fail('admission gate');const calls=inspectOrderedCallTokens(sql).filter(t=>t.name.startsWith(namespace+'.')),names=new Set(calls.map(t=>t.name)),wanted=new Set(directFrameAdaptersV1.map(s=>s.name));if(names.size!==18||[...names].some(n=>!wanted.has(n)))fail('adapter call closure');const safe=new Map(directFrameAdaptersV1.map(s=>[s.name,s.args.length===1?'pg_catalog.pg_get_functiondef':'pg_catalog.format']));let inspected=sql;for(const t of calls.toReversed())inspected=inspected.slice(0,t.start)+safe.get(t.name)+inspected.slice(t.start+t.name.length);admitCollectorSource(inspected);return true;}
