import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {lowerOrderedTemporalTransforms} from './ordered-current-temporal-transforms.mjs';
import {lowerOrderedPublicFunctionTransforms} from './ordered-current-public-function-transforms.mjs';
const component=await import('./ordered-current-transform-compiler.mjs').catch(()=>({}));
const field=field=>({op:'field',field});
const literal=value=>({op:'literal',value});
const saved={op:'saved-scalar',schema:'zasp_temporal74',signature:'zasp_temporal66.fingerprint()',field:'definition'};
const ast={op:'replace',input:{op:'identity-case',cases:[{identity:'zasp_temporal66.fingerprint()',then:saved}],else:field('definition')},from:'abc',to:'<pin>'};
const row={identity:'zasp_temporal66.fingerprint()',definition:'live abc',acl:null};
const environment=()=>({identities:new Set(['zasp_temporal66.fingerprint()']),savedTables:{zasp_temporal74:{columns:['signature','definition','acl'],rows:[{signature:'zasp_temporal66.fingerprint()',definition:'saved abc abc',acl:null}]}}});
test('closed AST compiles exact fixed bindings and evaluates ordered original substitutions',()=>{
  assert.equal(typeof component.compileOrderedTransformAST,'function');
  assert.equal(component.evaluateOrderedTransform(ast,row,environment()),'saved <pin> <pin>');
  const sql=component.compileOrderedTransformAST(ast);
  assert.match(sql,/object_identity::regprocedure='zasp_temporal66.fingerprint\(\)'::regprocedure/);
  assert.match(sql,/SELECT definition::text FROM zasp_temporal74.predecessor_functions/);
  assert.match(sql,/pg_catalog.replace\(/);
  assert.equal(component.evaluateOrderedTransform({op:'coalesce',args:[field('acl'),literal('')]},row,environment()),'');
  assert.equal(component.evaluateOrderedTransform({op:'replace',input:literal(null),from:'x',to:'y'},row,environment()),null);
});
test('scalar demand is lazy but original binding checks precede value evaluation',()=>{
  assert.equal(typeof component.evaluateOrderedTransform,'function');
  const missing=environment();missing.savedTables.zasp_temporal74.rows=[];
  assert.equal(component.evaluateOrderedTransform(ast,row,missing),null);
  const duplicate=environment();duplicate.savedTables.zasp_temporal74.rows.push({...duplicate.savedTables.zasp_temporal74.rows[0]});
  assert.throws(()=>component.evaluateOrderedTransform(ast,row,duplicate),/multiple/);
  const unselected={...row,identity:'public.other()',definition:'original abc'};
  assert.equal(component.evaluateOrderedTransform(ast,unselected,duplicate),'original <pin>');
  const absent=environment();delete absent.savedTables.zasp_temporal74;
  assert.throws(()=>component.evaluateOrderedTransform(ast,unselected,absent),/binding/);
  const missingColumn=environment();missingColumn.savedTables.zasp_temporal74.columns=['signature'];
  assert.throws(()=>component.evaluateOrderedTransform(ast,unselected,missingColumn),/binding/);
  const unresolved=environment();unresolved.identities.clear();
  assert.throws(()=>component.evaluateOrderedTransform(ast,unselected,unresolved),/regprocedure/);
});
test('unknown op, fields, keys, schema and malformed scalar input refuse',()=>{
  assert.equal(typeof component.compileOrderedTransformAST,'function');
  for(const value of [{op:'execute',sql:'SELECT true'},{op:'field',field:'raw_sql'},{...saved,schema:'public'},{...saved,extra:true},{op:'replace',input:literal('a'),from:field('definition'),to:'x'},{op:'identity-case',cases:[],else:literal('x')}])assert.throws(()=>component.compileOrderedTransformAST(value));
});
test('nine source-bound recipes compile through one shared raw catalog input without old calls',()=>{
  assert.equal(typeof component.compileOrderedTransforms,'function');
  const contract=JSON.parse(fs.readFileSync(new URL('./ordered-current-worker-source-closure-v1-artifacts/effective-contract3.json',import.meta.url)));
  const lowered=lowerOrderedTemporalTransforms(contract);
  const output=component.compileOrderedTransforms(lowered.recipes);
  assert.equal(output.recipes,9);
  assert.equal((output.sql.match(/direct_routine AS MATERIALIZED/g)??[]).length,1);
  assert.equal((output.sql.match(/AS kind/g)??[]).length,18);
  assert.match(output.sql,/transform_inputs AS MATERIALIZED/);
  assert.match(output.sql,/zasp_temporal78.predecessor_functions/);
  assert.throws(()=>component.compileOrderedTransforms([...lowered.recipes,lowered.recipes[0]]),/duplicate/);
});
test('reference transformation consumes only matching captured input and retains projected key',()=>{
  assert.equal(typeof component.projectOrderedTransforms,'function');
  const recipe={ruleId:'temporal:fixture:function',kind:'routine',fields:{identity:field('identity'),definition:ast,acl:{op:'coalesce',args:[field('acl'),literal('')]}}};
  const input={kind:'routine',identity:'["raw-transform:temporal:fixture:function","zasp_temporal66.fingerprint()"]',fact:{definition:'live abc',acl:null}};
  assert.deepEqual(component.projectOrderedTransforms([recipe],[input],environment()),[{kind:'routine',identity:'["temporal:fixture:function","zasp_temporal66.fingerprint()"]',fact:{acl:'',definition:'saved <pin> <pin>',identity:'zasp_temporal66.fingerprint()'}}]);
  assert.throws(()=>component.projectOrderedTransforms([recipe],[input,input],environment()),/duplicate/);
  const absent=environment();delete absent.savedTables.zasp_temporal74;
  assert.throws(()=>component.projectOrderedTransforms([recipe],[],absent),/binding/);
});
test('replacement text is literal for all admitted dollar forms and empty search preserves input',()=>{
  for(const replacement of ['$&',"$'",'$`','$$','$1']){
    const value={op:'replace',input:literal('axxb'),from:'x',to:replacement};
    assert.equal(component.evaluateOrderedTransform(value,{},{}),'a'+replacement+replacement+'b',replacement);
    assert.ok(component.compileOrderedTransformAST(value).endsWith(","+"'"+replacement.replaceAll("'","''")+"')"));
  }
  assert.equal(component.evaluateOrderedTransform({op:'replace',input:literal('abc'),from:'',to:'$&'},{},{}),'abc');
});
test('typed pass-through keeps boolean versus text values and rejects mixed operators',()=>{
  for(const name of ['security_definer','strict','leakproof']){
    assert.equal(component.compileOrderedTransformAST(field(name)),"(fact->>"+"'"+name+"')::boolean");
    for(const value of [true,false,null])assert.equal(component.evaluateOrderedTransform(field(name),{[name]:value},{}),value);
    for(const value of ['true',1,{},[]])assert.throws(()=>component.evaluateOrderedTransform(field(name),{[name]:value},{}),/field|type/);
    assert.throws(()=>component.compileOrderedTransformAST({op:'replace',input:field(name),from:'true',to:'x'}),/type/);
    assert.throws(()=>component.compileOrderedTransformAST({op:'coalesce',args:[field(name),literal('false')]}),/type/);
  }
  for(const name of ['namespace_name','volatility','parallel','config_text_or_empty']){
    assert.equal(component.evaluateOrderedTransform(field(name),{[name]:'raw text'},{}),'raw text');
    assert.throws(()=>component.evaluateOrderedTransform(field(name),{[name]:true},{}),/field|type/);
  }
  assert.throws(()=>component.compileOrderedTransformAST({op:'identity-case',cases:[{identity:'public.fixed()',then:field('strict')}],else:literal('false')}),/type/);
  assert.throws(()=>component.compileOrderedTransformAST(field('live_oid')),/field/);
  assert.throws(()=>component.compileOrderedTransformAST({op:'cast',type:'boolean',input:literal('true')}),/op/);
  const nullableBoolean={op:'coalesce',args:[field('strict'),literal(null)]};
  assert.equal(component.compileOrderedTransformAST(nullableBoolean),"COALESCE((fact->>'strict')::boolean,NULL::boolean)");
  assert.equal(component.evaluateOrderedTransform(nullableBoolean,{strict:false},{}),false);
  assert.equal(component.compileOrderedTransformAST({op:'coalesce',args:[field('strict'),{op:'coalesce',args:[literal(null),literal(null)]}]}),"COALESCE((fact->>'strict')::boolean,COALESCE(NULL::boolean,NULL::boolean))");
  const booleanCase={op:'identity-case',cases:[{identity:'public.fixed()',then:field('strict')}],else:literal(null)};
  assert.ok(component.compileOrderedTransformAST(booleanCase).endsWith('ELSE NULL::boolean END)'));
  for(const fields of [{strict:literal('false')},{live_oid:literal('42')}]){
    const recipe={ruleId:'fixture',kind:'routine',fields};
    assert.throws(()=>component.projectOrderedTransforms([recipe],[],{}),/field|recipe|type/,'empty input must not bypass output type admission');
  }
});
test('four fixed public input mappings consume nonempty rows and compile with the nine temporal recipes',()=>{
  const contract=JSON.parse(fs.readFileSync(new URL('./ordered-current-worker-source-closure-v1-artifacts/effective-contract3.json',import.meta.url)));
  const publicRecipes=lowerOrderedPublicFunctionTransforms(contract).recipes;
  const recipes=[...lowerOrderedTemporalTransforms(contract).recipes,...publicRecipes];
  const emitted=component.compileOrderedTransforms(recipes);
  assert.equal(emitted.recipes,13);
  assert.equal((emitted.sql.match(/direct_routine AS MATERIALIZED/g)??[]).length,1);
  assert.equal((emitted.sql.match(/\)::boolean/g)??[]).length,12);
  const families=['sa_attack_lab','sa_export','sa_multistep','sa_webhook'];
  const raw=families.map(family=>({kind:'routine',identity:JSON.stringify(['raw-transform:public:'+family,'public.fixture()']),fact:{namespace_name:'public',name:'fixture',identity_arguments:'',owner:'bound_owner',security_definer:true,volatility:'s',parallel:'u',strict:false,leakproof:false,config_text_or_empty:'{"search_path=pg_catalog, public"}',acl:null,definition:'SELECT $& literal'}}));
  const facts=component.projectOrderedTransforms(publicRecipes,raw,{});
  assert.equal(facts.length,4,'a wrong raw rule key must not silently produce no facts');
  for(const family of families){
    const fact=facts.find(row=>JSON.parse(row.identity)[0]==='public:'+family+':function');
    assert.ok(fact,family);assert.equal(fact.fact.security_definer,true);assert.equal(fact.fact.strict,false);assert.equal(fact.fact.leakproof,false);assert.equal(fact.fact.acl,'');assert.equal(fact.fact.config_text_or_empty,'{"search_path=pg_catalog, public"}');assert.equal(fact.fact.definition,'SELECT $& literal');
    assert.equal(Object.hasOwn(fact.fact,'namespace_name'),family!=='sa_multistep');
    assert.ok(emitted.rawRules.some(rule=>rule.id==='raw-transform:public:'+family));
  }
  const unsupportedRecipe={...publicRecipes[0],ruleId:'public:other:function'};
  const matchingOnlyBySuffix={...raw[0],identity:'["raw-transform:public:other","public.fixture()"]'};
  assert.deepEqual(component.projectOrderedTransforms([unsupportedRecipe],[matchingOnlyBySuffix],{}),[],'mapping must not strip arbitrary function suffixes');
  const missingWitness=structuredClone(raw);delete missingWitness[0].fact.config_text_or_empty;missingWitness[0].fact.config=['search_path=pg_catalog, public'];
  assert.throws(()=>component.projectOrderedTransforms(publicRecipes,missingWitness,{}),/field/);
});
