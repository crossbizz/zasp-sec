import crypto from 'node:crypto';

const sha=value=>crypto.createHash('sha256').update(value).digest('hex');
const frameFields=['owner','acl','config','language','security_definer','volatility','parallel','strict','leakproof','cost','rows','arguments','result'];
const authority='zasp_discovery_authority';
const authorityACL='{zasp_discovery_authority=X/zasp_discovery_authority}';
const searchPath=['search_path=pg_catalog, public'];

const sqlFrame=(security_definer=false,result='text',argumentsText='')=>({
 owner:authority,acl:authorityACL,config:searchPath,language:'sql',security_definer,
 volatility:'s',parallel:'u',strict:false,leakproof:false,cost:100,rows:0,
 arguments:argumentsText,result
});

const sourceSpecs={
 'zasp_temporal68.predecessor_ready(text,text)':{
  short:'predecessor68',sourceSHA256:'dd0f5fe44a5f0eb1c5853f555adce40e13e43e5fcd70cb3c0f5361a6f4afac4c',definitionSHA256:'c6eed3d3fd1aad9eb53690e2a1e364dc576e1910224af2fec91813189c944bb6',
  frame:{...sqlFrame(true,'boolean','c text, f text'),language:'plpgsql'}
 },
 'zasp_temporal68.ready(text,text)':{
  short:'ready68',sourceSHA256:'fe58995a0e48312eb5c54cca509a217a471c1464129f09c7475933a8d2f1dab9',definitionSHA256:'f9557bcb94debad45801d1715181e4592c47be92fa79005b3c811b6281757f83',
  frame:{...sqlFrame(true,'boolean','c text, f text'),acl:'{zasp_discovery_authority=X/zasp_discovery_authority,zasp_temporal_executor=X/zasp_discovery_authority,zasp_temporal_compensation=X/zasp_discovery_authority,zasp_security_agent_api=X/zasp_discovery_authority,zasp_security_agent_worker=X/zasp_discovery_authority}'}
 },
 'zasp_temporal78.ready(text,text)':{
  short:'ready78',sourceSHA256:'06023c0cf59ce604e0585d8b182f1c2ec094ca1c34aa6a9052201ecae66abc76',definitionSHA256:'a6a988fd4b42b6c63dc66b34a2de51476a0bfe9452ef4536b061206d120999ac',frame:sqlFrame(true,'boolean','c text, f text')
 },
 'zasp_temporal77.base67_fingerprint()':{
  short:'base67',sourceSHA256:'2e205ba34a6d5267f51b8436d1b5021c9fc7161f776b3b525a085615ae6f556c',definitionSHA256:'ae6456305a2ffc9aa054dd32e085fd7595859714c1cdf56946c8d837c082e907',frame:sqlFrame(false)
 },
 'zasp_authorization80_temporal.projected_domain()':{
  short:'projected-domain',sourceSHA256:'25fc7e8a4a5b2782d02bc2bee96469cbe354ea74c77919014c8a7b2101058fee',definitionSHA256:'18d540807398454068dec0475c138dc076cf7716448f0b8cde7095fcadbecaf5',frame:sqlFrame(true)
 },
 'public.zasp_recovery_execution_live_fingerprint()':{short:'recovery-execution',sourceSHA256:'d67773464f945932cc767caabc6b2c56cd0fde13faee305c9fbfd3dc82af0767',definitionSHA256:'8379bf47ecbbc21d65b2c917d5356a371f4d706dda869be5bb4dc03e5153cc73',frame:sqlFrame()},
 'public.zasp_security_agent_session_isolation_live_fingerprint()':{short:'session-isolation',sourceSHA256:'1758a218a35d1fb67def7c9e958b4f7f2e5549b42881f1e565eee5b5bb94d7da',definitionSHA256:'b4f922737ac4e6cea06e28cb373c26f0f14fc6337015c1617d0a016fbcd20a9b',frame:sqlFrame()},
 'public.zasp_policy_deployment_execution_live_fingerprint()':{short:'policy-deployment',sourceSHA256:'f8e351130849bcd3b18ce1ed28e16fc87e7dba53255be5f642ef8fdbf0841513',definitionSHA256:'b4ab27589016a77049e2a3b0eed86a99339d473a1cfde22492ddaa3a3457c6d1',frame:sqlFrame()},
 'public.zasp_production_runtime_sessions_live_fingerprint()':{short:'runtime-sessions',sourceSHA256:'83a869dbeb2ad0a8129879b270a54de4692730f5bfb9c5eef450ee201e9ed04b',definitionSHA256:'12857815bf14d231369905b7528434d2f528f7ec2dacbdfc65b124bf6df0ca0b',frame:sqlFrame()},
 'zasp_authorization80_temporal.projected68()':{short:'temporal-projected68',sourceSHA256:'1782880ced20ac9230c543d93e64292443477b2a742e60d20c564aab75cc1361',definitionSHA256:'644154419e3a8efe11347ec35f71bdb3c7361f87089796914008efd08a98aef7',frame:sqlFrame(true)},
 'zasp_ordered_public62.fingerprint()':{short:'ordered-public62',sourceSHA256:'17405e12d315514e925a9b431d141613f507755f707675b2937bf19fafe1e4b8',definitionSHA256:'e13491491a9bb3873884553dbafd2d1286c05d4d7110d2a4a2cac6e53fe91ed8',frame:sqlFrame()},
 'public.zasp_execution_live_fingerprint()':{short:'execution',sourceSHA256:'f1d736c4922a17308f45c4f37099374f9d6a2f5304b8f828f81a169a605f6eda',definitionSHA256:'4a69fac36145097b86491b3ae71a13072ead01656ac59813f4b4ca0c7294a0d6',frame:sqlFrame(true)},
 'public.zasp_production_runtime_precision_live_fingerprint()':{short:'runtime-precision',sourceSHA256:'b6f6310ddee97053ec8dbb36b2e18a0604bdf8272d5bc0e1faeaadfb02118892',definitionSHA256:'2540e996d735a54a96a1fd3add0c1ff3bdd034b5f0d67825ab9fee137603c797',frame:sqlFrame()},
 'zasp_authorization80_temporal.projected72()':{short:'temporal-projected72',sourceSHA256:'829710c308583f54d55fe97f34a931bce24a9a30b4353aa48f52b319bbc5e8fd',definitionSHA256:'854710213d0c79dbdd21954527f8c60606fab88dc6f5e9a276d053c03a377710',frame:sqlFrame(true)},
 'zasp_temporal72.roles_ready()':{short:'roles-ready',sourceSHA256:'8a3061ecf9feaf2c1b4dbd28efcd424628a132043266a209ec3a56b5036def4e',definitionSHA256:'0b8ae5981086f6edd3fe93a356311b622426208955830c18a25bae6e97162d0f',frame:sqlFrame(true,'boolean')},
 'zasp_authorization80_worker.catalog_ready()':{short:'worker-catalog-ready',sourceSHA256:'28bc26660db8eae036fd2f36bc215fcf2e27c1aba6d2c7c42d5d6a58e73c5016',definitionSHA256:'3b46aa8607e042925c3cc56b66605244a0a6fe9ff2db41fcd339c8e6c7bebac8',frame:sqlFrame(true,'boolean')}
};

Object.assign(sourceSpecs,{
 'zasp_temporal76.catalog_ready()':{short:'temporal76-catalog-ready',sourceSHA256:'5b5e56e7208980e813b6cbbd6e6f954bef0f13adcfa90fcefabab709635dac06',definitionSHA256:'3a1c11d2ade3088683d4c69e59377a5ff1e4a1849849597ddcce043908e1cfa7',frame:{...sqlFrame(true,'boolean'),language:'plpgsql'}},
 'zasp_temporal77.catalog_ready()':{short:'temporal77-catalog-ready',sourceSHA256:'fd38073071e2f9ab33593a9b23bdcdf2f52e2de5b870fdcbbb382606a7fbae6a',definitionSHA256:'31391042a9b56c34133854319f25f2b294fd9fd8c7706b8c4e9b732c4f374aad',frame:{...sqlFrame(true,'boolean'),language:'plpgsql'}},
 'zasp_temporal78.catalog_ready()':{short:'temporal78-catalog-ready',sourceSHA256:'ddc95b7c69c846783c02579bf63c358a69e077e3e915a50e65c8f83aacc9287b',definitionSHA256:'7331800f6d1449cd1ebba41c9ff2f21057f1b2bc1a9ba4158cc850fc4b0bbaf2',frame:{...sqlFrame(true,'boolean'),language:'plpgsql'}},
 'zasp_authorization80_temporal.catalog_ready()':{short:'authorization80-temporal-catalog-ready',sourceSHA256:'332f99b997ef4b3d38ac58402a6219ae993d030b8d4dc1566aae46356bc5efda',definitionSHA256:'0cdbc2dc8b017422fd116b9c1dd47a922bcc27458888af30b1ff8ecd50b9fb09',frame:sqlFrame(true,'boolean')}
});

const conditionalSpecs={
 '65.fingerprint':{identity:'zasp_temporal65.fingerprint()',sourceSHA256:'aa4f2ab29e9b1c81a8b9e0da4f73de2accb039ce84365882a4a57a5970473072',definitionSHA256:'a606299a4a5bd5c863265d7209c245d96611820a6c8ff8ec97e2e6e78566ac46',targets:['zasp_temporal74.fingerprint()','zasp_temporal74.outbox65_fingerprint()']},
 '66.fingerprint':{identity:'zasp_temporal66.fingerprint()',sourceSHA256:'1ec22f54dd5c4658953d6c7a7fbc406a5bf01c3bd67b81954fdef275195b5edc',definitionSHA256:'da1ed733ec5c56a1cd4aacec03d9a94ab54b98cbed1a94d443dd9b6e5b75dfd4',targets:['zasp_temporal74.fingerprint()','zasp_temporal74.owner66_fingerprint()']},
 '67.base_fingerprint':{identity:'zasp_temporal67.base_fingerprint()',sourceSHA256:'4c82e4587582f2a0d2edd52499a0d65ea224d89083c3444d3f6b3d135afe7aa9',definitionSHA256:'3f9f793ea29cd864a19e0807cf3061c6224bccb4ee4e15477de54c2a11554f5c',targets:['zasp_temporal77.catalog_ready()','zasp_temporal77.base67_fingerprint()']},
 '67.fingerprint':{identity:'zasp_temporal67.fingerprint()',sourceSHA256:'f3dda0215658d125e02fc033647602f021ab917b605ea32b4d3ec50ce227b020',definitionSHA256:'ee4a2f643d6ce40300dd7cdb480bc636d00466ff47ffc7e12c096777c7446f21',targets:['zasp_temporal77.catalog_ready()','zasp_temporal77.domain67_fingerprint()']},
 '69.fingerprint':{identity:'zasp_temporal69.fingerprint()',sourceSHA256:'534bfddac036cdb8aa0020be1ab86a9a9c8b948ddb1d37cef0fb2c136f9ea5e1',definitionSHA256:'a05b5c3a51f4f31fb0127ccd7275e54e411f710e56d76088eee6c53ddb372b18',targets:['zasp_authorization80_worker.catalog_ready()','zasp_authorization80_worker.projected69()']},
 '72.fingerprint':{identity:'zasp_temporal72.fingerprint()',sourceSHA256:'1ec25170f7d2d2451c8dfb16ffefec0fbc7330eca7221638cb4c18ecdf74d41d',definitionSHA256:'43b3d082bbec543ee3ba1717a090d2c4fef3305fdb41006a2338ff4422554725',targets:['zasp_authorization80_temporal.catalog_ready()','zasp_authorization80_temporal.projected72()']},
 '73.fingerprint':{identity:'zasp_temporal73.fingerprint()',sourceSHA256:'ffc8e725dca2ee8b5815a343c6c59fe4267e693156ba0d4ab73657b7f41059ae',definitionSHA256:'63e60546045a88b0b0e17b91b27c6c93d8ce864ab7b178584a22958640633536',targets:['zasp_temporal78.catalog_ready()','zasp_temporal78.predecessor73_fingerprint()']},
 '74.fingerprint':{identity:'zasp_temporal74.fingerprint()',sourceSHA256:'964b512abe7b8699e1e0ec54be6cfdb575f743fb045af10c6278eeb306b87d49',definitionSHA256:'027e596cd9d68d9e24fed8b025ff964738b6e0687afa4d06e60803a90cbf3258',targets:['zasp_temporal76.catalog_ready()','zasp_temporal76.executor74_fingerprint()']},
 '76.executor74_fingerprint':{identity:'zasp_temporal76.executor74_fingerprint()',sourceSHA256:'98b0d9a64415be0f40d844d3a02361fcf73527434258a6ca2eaee5fe09e9d670',definitionSHA256:'eeeee1f5537fbbfc0c7632e81eac07f067b2bd80dddecf512a8259fcc075baf5',targets:['zasp_authorization80_worker.catalog_ready()','zasp_authorization80_worker.projected74()']},
 '76.fingerprint':{identity:'zasp_temporal76.fingerprint()',sourceSHA256:'7189e1537e779cf9011d129201d5eca54e4932455b1aa40a33d9bc80417e3c56',definitionSHA256:'0cc5aed7dafe94d7c4c6622e12c55a3c4eb85e569187ab9794e355d4377ef5a5',targets:['zasp_temporal78.catalog_ready()','zasp_temporal78.predecessor76_fingerprint()']},
 '77.fingerprint':{identity:'zasp_temporal77.fingerprint()',sourceSHA256:'9d3653a189af7908d72e3021e706c800d01546fdf20e9bf3f556a8bbade408f5',definitionSHA256:'981e93626e7b96a7385bfa975e5360895b36155398d8802eb183aca7b08553f5',targets:['zasp_temporal78.catalog_ready()','zasp_temporal78.predecessor77_fingerprint()']},
 '78.fingerprint':{identity:'zasp_temporal78.fingerprint()',sourceSHA256:'c465e2bed58a2be8f35cda526dca81e62473d8564770219a45697e67bff5ea00',definitionSHA256:'48a239da1b4b6805c4e2bc04b6e2341fb0a67d79bbf510a3b69386575862c735',targets:['zasp_authorization80_worker.catalog_ready()','zasp_authorization80_worker.projected78()']}
};
for(const spec of Object.values(conditionalSpecs))sourceSpecs[spec.identity]={short:null,sourceSHA256:spec.sourceSHA256,definitionSHA256:spec.definitionSHA256,frame:sqlFrame()};

const richIdentities=['zasp_temporal68.predecessor_ready(text,text)','zasp_temporal68.ready(text,text)','zasp_temporal78.ready(text,text)','zasp_temporal77.base67_fingerprint()'];
const publicConditionals={
 'public.zasp_recovery_execution_live_fingerprint()':['zasp_authorization80_worker.catalog_ready()','zasp_authorization80_worker.gateway_projected27()'],
 'public.zasp_security_agent_session_isolation_live_fingerprint()':['zasp_authorization80_worker.catalog_ready()','zasp_authorization80_worker.gateway_projected24()'],
 'public.zasp_policy_deployment_execution_live_fingerprint()':['zasp_authorization80_worker.catalog_ready()','zasp_authorization80_worker.ordered_projected28()'],
 'public.zasp_production_runtime_sessions_live_fingerprint()':['zasp_authorization80_worker.catalog_ready()','zasp_authorization80_worker.runtime_projected40()']
};
const additionalConditionals={
 'zasp_authorization80_temporal.projected68()':['zasp_authorization80_worker.catalog_ready()','zasp_authorization80_worker.projected68()'],
 'zasp_ordered_public62.fingerprint()':['zasp_authorization80_worker.catalog_ready()','zasp_authorization80_worker.projected62()'],
 'public.zasp_execution_live_fingerprint()':['zasp_temporal72.fingerprint()','zasp_temporal72.retained_execution_fingerprint()'],
 'public.zasp_production_runtime_precision_live_fingerprint()':['zasp_temporal72.fingerprint()','zasp_temporal72.retained_precision_fingerprint()']
};

const readyRegistrationPins={
 'zasp_temporal68.ready(text,text)':{
  'zasp_authorization80_temporal.registration':[[3531,3598,'79546c481e9a72af2f409e7a552bb94d98f6ea9a89a992136982b0e89c553dbd'],[3610,3795,'ca7eda320cef08390d2fcd048303bf30ae98bbc9265470fed6f33e87f000a987']],
  'zasp_authorization79.registration':[[3906,4035,'b272803aa286f8dfa731e1e3c8475bd11d88a007d4cdcc042a93c4bac80a0020']],
  'zasp_authorization80.registration':[[4163,4345,'6b0e1a319c5e3a6238af9e90abbc614a19410301262352dd26f87f83790ff750']],
  'zasp_temporal68.registration':[[4755,4808,'29ef2bd45ffd052a1a1e74e9a5d10e922d3fd7606b96d400a8a8742d8f3d2225'],[4819,4898,'e0338fb5464d1d4597d33aebfb8f28a39378dc5d6fef2ed9f610464eff5e19b1'],[5801,5854,'29ef2bd45ffd052a1a1e74e9a5d10e922d3fd7606b96d400a8a8742d8f3d2225'],[5865,5944,'e0338fb5464d1d4597d33aebfb8f28a39378dc5d6fef2ed9f610464eff5e19b1'],[6852,6905,'29ef2bd45ffd052a1a1e74e9a5d10e922d3fd7606b96d400a8a8742d8f3d2225'],[6916,6995,'e0338fb5464d1d4597d33aebfb8f28a39378dc5d6fef2ed9f610464eff5e19b1']]
 },
 'zasp_temporal78.ready(text,text)':{
  'zasp_temporal78.registration':[[1986,2039,'26c6bb3b188bfe1618f70daab700796599ec61a1f820018dd5c55b20f7af70ec'],[2050,2259,'ff9935d9e12899ade536cd37b9e0607fd032c1370ab0f3f8f3787f3e53f82887']],
  'zasp_temporal77.registration':[[2560,2613,'e730e3699f692fed1088a0659c2555d5ee1e4e4069b9f6e1a8b3578c8fa5b342'],[2624,2833,'b874fe044a45362936667c174db1575cd9a94100443803d4cc0a2b1ccd47d198']],
  'zasp_temporal76.registration':[[3134,3187,'c6980802c47c99475f94a60a471ac7b820333f15c525151f732dcdb6567f5167'],[3198,3407,'d971911ddf5b26be2c84cd7a53ce91be22208b6bd2c81b1ba15b2448eebe97fb']],
  'zasp_authorization80_temporal.registration':[[16647,16714,'79546c481e9a72af2f409e7a552bb94d98f6ea9a89a992136982b0e89c553dbd'],[16726,16911,'f1aacf8a7311295d95d4ad6929c08dbe5a9f3972ef0fee0dff237778f09f41af'],[20595,20662,'79546c481e9a72af2f409e7a552bb94d98f6ea9a89a992136982b0e89c553dbd'],[20674,20859,'f1aacf8a7311295d95d4ad6929c08dbe5a9f3972ef0fee0dff237778f09f41af']],
  'zasp_authorization79.registration':[[17023,17153,'31d267e2726cf8d953a39ccbe83c5c7d2b0fe69ab78dd26a763654c5184a24f1'],[20971,21101,'cf4d6fc061ef15ba8e62cebc378f659f03ac427ad4468ed17812be70d2e86a14']],
  'zasp_authorization80.registration':[[17282,17464,'6b0e1a319c5e3a6238af9e90abbc614a19410301262352dd26f87f83790ff750'],[21230,21412,'6b0e1a319c5e3a6238af9e90abbc614a19410301262352dd26f87f83790ff750']],
  'zasp_temporal68.registration':[[17912,17965,'29ef2bd45ffd052a1a1e74e9a5d10e922d3fd7606b96d400a8a8742d8f3d2225'],[17976,18093,'9057f0e8b80c82d99a98b277c7be295099a3b1c1f531c51ec17e9b2ec97c27b9']],
  'zasp_temporal69.registration':[[18996,19049,'f24c97216a28e25d4590cd977df8450f75f00578af17ad3ad61fe27d39b21f55'],[19061,19178,'c5e8f67303b2688252156e3f0762f8216217451f96624fc7b0d5d00476dfb87f']],
  'zasp_temporal70.registration':[[19444,19497,'f81bc17555376ce8c720a2f1efd9e8b43d414abd001ba54251618cfb82d2f46d'],[19509,19626,'ac9ba182b97081079fe250ae1323125a3555258f2d729c944d15ca6e8958611c']],
  'zasp_temporal71.registration':[[19892,19945,'99ac233c570160a83a47f7967e6171ca16047e961b8cdda17ac5ff7dd059349e'],[19956,20073,'8a74669e54f25147e64034a8e24a75c7dedd96f307bce6d163efeda7ede2b483']],
  'zasp_temporal72.registration':[[20338,20391,'58e2c95591a89c95d0df85f010425e336bb6b9bccc33cee21717f4d0c8007073'],[20403,20520,'8e0635c6c8b63b973ca8e208bf93b6b5d678c9f71879967d8c9ca7821f6aad96']],
  'zasp_temporal73.registration':[[22772,22825,'4efe7f1cbede8565e3486846ea988c4a779f3504fc357d088b784229f68fed6e'],[22837,22954,'cafcd7ee80fff9de21882b770f2fc50a4d85256e8aefe0267c9b753cbe441185']],
  'zasp_temporal74.registration':[[23220,23273,'a01e40f215eebea2103617f4eb9655768b5be08a4389902082cb80553cf32595'],[23284,23401,'a8cbef2de430b9e0f4ccd13cff3a6d1f980113ccd01ac635885b4c70c4d46212']],
  'zasp_temporal75.registration':[[23667,23720,'ba40b25e9da9b08d220ea07fa6dcea22dd578d250b5c990d9d4f75308b8fddbf'],[23731,23848,'01e20197f2b178282d2320aa53c46f510e3942c1c16dc970ee6fbaf10f3d1f49']]
 }
};

const ownRoutineFields=['routine_identity','definition','source_body','owner','raw_acl','language','volatility','security_definer','strict','parallel','leakproof','config_json','config_raw','config_dims','config_ndims','config_bounds','identity_arguments','result','cost','rows'];
const ownRoutineTypes={routine_identity:'text',definition:'text',source_body:'text',owner:'text',raw_acl:'text?',language:'text',volatility:'text',security_definer:'boolean',strict:'boolean',parallel:'text',leakproof:'boolean',config_json:'json?',config_raw:'text?',config_dims:'text?',config_ndims:'integer?',config_bounds:'json?',identity_arguments:'text',result:'text',cost:'number',rows:'number'};
const ownRoutineProjections=['p.oid::regprocedure::text','pg_get_functiondef(p.oid)','p.prosrc::text','p.proowner::regrole::text','p.proacl::text','l.lanname::text','p.provolatile::text','p.prosecdef','p.proisstrict','p.proparallel::text','p.proleakproof','to_jsonb(p.proconfig)','p.proconfig::text','array_dims(p.proconfig)','array_ndims(p.proconfig)','(SELECT jsonb_agg(jsonb_build_array(array_lower(p.proconfig,d),array_upper(p.proconfig,d)) ORDER BY d) FROM generate_series(1,array_ndims(p.proconfig)) d)','pg_get_function_identity_arguments(p.oid)','pg_get_function_result(p.oid)','p.procost','p.prorows'];

const directRuleFields={
 'worker:projected_domain:table':['name','kind','persistence','owner','row_security','forced_row_security','acl_text_or_empty'],
 'worker:projected_domain:column':['relation_name','position','name','type','not_null','default_text_or_empty','acl_text_or_empty'],
 'worker:projected_domain:constraint':['relation_name','name','definition','validated'],
 'worker:projected_domain:index':['relation_name','definition','valid','ready'],
 'worker:projected_domain:policy':['relation_name','name','command','permissive','roles','using','check'],
 'worker:projected_domain:foreign-key-trigger':['relation','name','referenced_relation','trigger_relation','constraint_relation','function','event_bits','enabled','deferrable','deferred','argument_count','arguments','columns_text','when_text_or_empty'],
 'worker:projected_domain:trigger':['relation_name','name','enabled','trigger_definition','definition','owner','acl'],
 'worker-edge:gateway_projected24:2':['name','owner','row_security','forced_row_security','acl_text_or_empty'],
 'worker-edge:gateway_projected24:3':['name','type_identity','not_null','identity','generated','default_text_or_empty'],
 'worker-edge:gateway_projected24:4':['name','constraint_type','validated','deferrable','deferred','definition_pretty'],
 'worker-edge:gateway_projected24:5':['name','valid','ready','unique','primary','definition'],
 'worker-edge:gateway_projected24:6':['name','identity_arguments','owner','security_definer','config_text_or_empty','acl','definition'],
 'worker-edge:gateway_projected24:7':['name','validated','definition_pretty'],
 'worker-edge:gateway_projected27:2':['name','superuser','inherit','create_role','create_db','login','replication','bypass_rls'],
 'worker-edge:gateway_projected27:3':['granted_role','member_role','admin_option'],
 'worker-edge:gateway_projected27:4':['name','owner','row_security','forced_row_security','acl_text_or_empty'],
 'worker-edge:gateway_projected27:5':['name','definition'],
 'worker-edge:gateway_projected27:6':['relation_name','name','type_identity','not_null','default_text_or_empty'],
 'worker-edge:gateway_projected27:7':['relation_name','name','constraint_type','validated','definition_pretty'],
 'worker-edge:gateway_projected27:8':['relation_name','name','type_identity','not_null','default_text_or_empty'],
 'worker-edge:gateway_projected27:9':['relation_name','name','constraint_type','validated','definition_pretty'],
 'worker-edge:gateway_projected27:10':['name','owner','valid','ready','unique','primary','definition'],
 'worker-edge:gateway_projected27:11':['relation_name','name','permissive','using','check'],
 'worker-edge:gateway_projected27:12':['relation_name','name','definition_pretty'],
 'worker-edge:gateway_projected27:13':['name','identity_arguments','owner','security_definer','config_text_or_empty','acl','definition'],
 'worker-edge:ordered_projected28:2':['name','superuser','inherit','create_role','create_db','login','replication','bypass_rls'],
 'worker-edge:ordered_projected28:3':['granted_role','member_role','admin_option'],
 'worker-edge:ordered_projected28:4':['name','owner','row_security','forced_row_security','acl_text_or_empty'],
 'worker-edge:ordered_projected28:5':['relation_name','name','type_identity','not_null','identity','generated','default_text_or_empty'],
 'worker-edge:ordered_projected28:6':['name','definition'],
 'worker-edge:ordered_projected28:7':['relation_name','name','constraint_type','validated','definition_pretty'],
 'worker-edge:ordered_projected28:8':['relation_name','name','permissive','using','check'],
 'worker-edge:ordered_projected28:9':['relation_name','name','definition_pretty'],
 'worker-edge:ordered_projected28:10':['name','identity_arguments','owner','security_definer','config_text_or_empty','acl','definition'],
 'worker-edge:runtime_projected40:2':['name','identity_arguments','owner','security_definer','config_text_or_empty','acl','definition'],
 'worker-edge:runtime_projected40:3':['name','owner','row_security','forced_row_security','acl_text_or_empty'],
 'worker-edge:runtime_projected40:4':['name','definition','validated'],
 'worker-edge:runtime_projected40:5':['relation','name','type','not_null'],
 'worker-edge:runtime_projected40:6':['namespace_name','table_name','name','roles_text','command','using','check'],
 'worker-edge:runtime_projected40:7':['name','definition'],
 'worker:projected72:schema':['name','owner','acl_text_or_empty'],
 'worker:projected72:table':['name','kind','persistence','owner','row_security','forced_row_security','acl_text_or_empty'],
 'worker:projected72:column':['relation_name','position','name','type','not_null','default_text_or_empty','acl_text_or_empty'],
 'worker:projected72:constraint':['relation_name','name','definition','validated'],
 'worker:projected72:index':['relation_name','definition','valid','ready'],
 'worker:projected72:policy':['relation_name','name','command','permissive','roles','using','check'],
 'worker:projected72:trigger':['relation','name','enabled','definition'],
 'worker:projected72:foreign-key-trigger':['relation','name','referenced_relation','trigger_relation','constraint_relation','function','event_bits','enabled','deferrable','deferred','argument_count','arguments','columns_text','when_text_or_empty'],
 'worker:projected72:function':['name','identity_arguments','owner','acl','definition'],
 'worker:projected72:precision-handoff':['owner','acl','definition'],
 'worker:projected72:bulk-handoff':['projected_identity','owner','acl','definition']
};

const targetPrefixes={
 'zasp_authorization80_worker.projected_domain()':'worker:projected_domain:',
 'zasp_authorization80_worker.gateway_projected24()':'worker-edge:gateway_projected24:',
 'zasp_authorization80_worker.gateway_projected27()':'worker-edge:gateway_projected27:',
 'zasp_authorization80_worker.ordered_projected28()':'worker-edge:ordered_projected28:',
 'zasp_authorization80_worker.runtime_projected40()':'worker-edge:runtime_projected40:',
 'zasp_authorization80_worker.projected72()':'worker:projected72:'
};
const refsForTarget=target=>Object.entries(directRuleFields).filter(([ruleId])=>ruleId.startsWith(targetPrefixes[target]??'\0')).flatMap(([ruleId,fields])=>fields.map(field=>({ruleId,field})));
const refs=(ruleId,fields)=>fields.map(field=>({ruleId,field}));

function selectedNode(contract,identity){
 if(!contract||!Array.isArray(contract.nodes)||!Array.isArray(contract.higherRegions)||!Array.isArray(contract.materializedObligations))throw Error('recursive capture source pin');
 const spec=sourceSpecs[identity],matches=contract.nodes.filter(node=>node.identity===identity);
 if(!spec||matches.length!==1)throw Error('recursive capture source pin '+identity);
 const node=matches[0];
 if(typeof node.source!=='string'||typeof node.definition!=='string'||node.sourceSHA256!==spec.sourceSHA256||sha(node.source)!==spec.sourceSHA256||node.definitionSHA256!==spec.definitionSHA256||sha(node.definition)!==spec.definitionSHA256)throw Error('recursive capture source pin '+identity);
 const actual=Object.fromEntries(frameFields.map(field=>[field,node[field]]));
 if(JSON.stringify(actual)!==JSON.stringify(spec.frame))throw Error('recursive capture source frame '+identity);
 return node;
}

function sourceSite(node,start=0,end=Buffer.byteLength(node.source)){
 const bytes=Buffer.from(node.source),text=bytes.subarray(start,end).toString('utf8');
 return {sourceIdentity:node.identity,sourceSHA256:node.sourceSHA256,definitionSHA256:node.definitionSHA256,siteSHA256:sha(text),start,end,frame:Object.fromEntries(frameFields.map(field=>[field,structuredClone(node[field])]))};
}

function checkedSite(node,start,end,expectedSHA256=null){
 const site=sourceSite(node,start,end);
 if(expectedSHA256&&site.siteSHA256!==expectedSHA256)throw Error('recursive capture source span '+node.identity+' '+start);
 return site;
}

function validateCatalog(catalog,nodes){
 if(!catalog||!Array.isArray(catalog.functions)||!Array.isArray(catalog.columns)||!Array.isArray(catalog.relations)||!Array.isArray(catalog.roles))throw Error('recursive capture catalog pin');
 for(const identity of [...richIdentities,'zasp_authorization80_worker.catalog_ready()','zasp_temporal72.roles_ready()','zasp_authorization80_temporal.projected72()','zasp_temporal76.catalog_ready()','zasp_temporal77.catalog_ready()','zasp_temporal78.catalog_ready()','zasp_authorization80_temporal.catalog_ready()']){
  const rows=catalog.functions.filter(row=>row.identity===identity),node=nodes.get(identity);
  if(rows.length!==1||sha(rows[0].definition)!==node.definitionSHA256||['owner','acl','config','language','security_definer','volatility','parallel','strict','leakproof','cost','rows','arguments','result'].some(field=>JSON.stringify(rows[0][field])!==JSON.stringify(node[field])))throw Error('recursive capture catalog pin '+identity);
 }
 const shapes={
  'zasp_temporal74.registration':[['singleton','boolean'],['checksum','text'],['fingerprint','text']],
  'zasp_temporal68.registration':[['singleton','boolean'],['checksum','text'],['fingerprint','text']],
  'zasp_temporal69.registration':[['singleton','boolean'],['checksum','text'],['fingerprint','text']],
  'zasp_temporal70.registration':[['singleton','boolean'],['checksum','text'],['fingerprint','text']],
  'zasp_temporal71.registration':[['singleton','boolean'],['checksum','text'],['fingerprint','text']],
  'zasp_temporal72.registration':[['singleton','boolean'],['checksum','text'],['fingerprint','text']],
  'zasp_temporal73.registration':[['singleton','boolean'],['checksum','text'],['fingerprint','text']],
  'zasp_temporal75.registration':[['singleton','boolean'],['checksum','text'],['fingerprint','text']],
  'zasp_temporal76.registration':[['singleton','boolean'],['checksum','text'],['fingerprint','text']],
  'zasp_temporal77.registration':[['singleton','boolean'],['checksum','text'],['fingerprint','text']],
  'zasp_temporal78.registration':[['singleton','boolean'],['checksum','text'],['fingerprint','text']],
  'zasp_authorization80_temporal.registration':[['singleton','boolean'],['checksum','text'],['fingerprint','text'],['profile_name','text']],
  'zasp_authorization79.registration':[['singleton','boolean'],['checksum','text'],['fingerprint','text']],
  'zasp_authorization80.registration':[['singleton','boolean'],['checksum','text'],['fingerprint','text']],
  'zasp_authorization80_worker.registration':[['singleton','boolean'],['checksum','text'],['fingerprint','text']],
  'public.zasp_schema_metadata':[['key','text'],['value','text'],['applied_at','timestamp with time zone']],
  'zasp_temporal72.principals':[['principal_name','text'],['authority_role','text']],
  'public.zasp_discovery_principal_bindings':[['principal_name','text'],['authority_role','text'],['registered_at','timestamp with time zone']],
  'public.zasp_discovery_execution_principals':[['principal_name','text'],['authority_role','text'],['registered_at','timestamp with time zone']]
 };
 for(const [relation,shape] of Object.entries(shapes)){
  if(catalog.relations.filter(row=>row.identity===relation).length!==1)throw Error('recursive capture catalog pin '+relation);
  const columns=catalog.columns.filter(row=>row.relation===relation).sort((a,b)=>a.position-b.position);
  if(columns.length!==shape.length||columns.some((row,index)=>row.position!==index+1||row.name!==shape[index][0]||row.type!==shape[index][1]||row.not_null!==true))throw Error('recursive capture catalog pin '+relation);
 }
 for(const name of ['zasp_temporal_executor','zasp_temporal_compensation','zasp_temporal_accounting']){
  const rows=catalog.roles.filter(row=>row.name===name);
  if(rows.length!==1||['login','superuser','create_db','create_role','replication','bypass_rls'].some(field=>typeof rows[0][field]!=='boolean'))throw Error('recursive capture catalog pin '+name);
 }
}

function callSite(node,text,last=false){
 const start=last?node.source.lastIndexOf(text):node.source.indexOf(text);
 if(start<0)throw Error('recursive capture source child '+node.identity+' '+text);
 return checkedSite(node,start,start+Buffer.byteLength(text));
}

function balancedCallEnd(source,start){
 const open=source.indexOf('(',start);if(open<0)throw Error('recursive capture balanced call');
 let depth=0,quoted=false;
 for(let index=open;index<source.length;index++){
  const char=source[index];
  if(char==="'"){
   if(quoted&&source[index+1]==="'"){index++;continue;}
   quoted=!quoted;continue;
  }
  if(quoted)continue;
  if(char==='(')depth++;
  if(char===')'&&--depth===0)return index+1;
 }
 throw Error('recursive capture unbalanced call');
}

function registrationSite(node,table){
 const countText=`(SELECT count(*)=1 FROM ${table})`,countStart=node.source.indexOf(countText);
 const existsStart=node.source.indexOf(`EXISTS(SELECT 1 FROM ${table}`,Math.max(0,countStart));
 if(existsStart<0)throw Error('recursive capture registration span '+node.identity+' '+table);
 return checkedSite(node,countStart>=0?countStart:existsStart,balancedCallEnd(node.source,existsStart));
}

function staticWorkerSpans(node){
 const start=node.source.indexOf('EXISTS(SELECT 1 FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang');
 const registration=node.source.indexOf('EXISTS(SELECT 1 FROM zasp_authorization80_worker.registration',start);
 const registrationEnd=node.source.indexOf(' AND zasp_authorization80_worker.catalog_ready()',registration);
 if(start<0||registration<0||registrationEnd<0)throw Error('recursive capture worker guard span '+node.identity);
 return {callable:checkedSite(node,start,registration-5),registration:checkedSite(node,registration,registrationEnd)};
}

function higherCatalogSite(node){
 const start=node.source.indexOf("EXISTS(SELECT 1 FROM pg_proc p WHERE p.oid='zasp_authorization80_worker.catalog_ready()'::regprocedure");
 const end=node.source.indexOf(' AND EXISTS(SELECT 1 FROM zasp_authorization80_worker.registration',start);
 if(start<0||end<0)throw Error('recursive capture higher catalog span '+node.identity);
 return checkedSite(node,start,end);
}

function retainedTarget(name){
 const targets={
  'zasp_temporal72.migration_helper_identity':'zasp_temporal72.migration_helper_identity(text,text,text)',
  'public.zasp_inventory_live_fingerprint':'public.zasp_inventory_live_fingerprint()',
  'zasp_authorization80_worker.projected74':'zasp_authorization80_worker.projected74()',
  'zasp_temporal67.scope_authority_ready':'zasp_temporal67.scope_authority_ready()',
  'zasp_authorization80.runtime_audit_ready':'zasp_authorization80.runtime_audit_ready()',
  'public.zasp_audit_export_source_catalog_role':'public.zasp_audit_export_source_catalog_role(oid,oid)',
  'public.zasp_audit_export_source_acl_ready':'public.zasp_audit_export_source_acl_ready()',
  'public.zasp_production_security_agent_existing_tests_global_fingerprint':'public.zasp_production_security_agent_existing_tests_global_fingerprin()',
  'public.zasp_compliance_jobs_catalog':'public.zasp_compliance_jobs_catalog()',
  'zasp_temporal72.roles_ready':'zasp_temporal72.roles_ready()'
 };
 const target=targets[name];if(!target)throw Error('recursive capture retained child '+name);return target;
}

function retainedChildren(target){
 if(target==='zasp_temporal72.migration_helper_identity(text,text,text)')return [
  ...refs('saved-input:zasp_temporal72.predecessor_functions',['signature','definition','owner_name','acl']),
  ...refs('wrapper:migration-helper:relations',['relation_identity','owner']),...refs('wrapper:migration-helper:routines',['routine_identity','owner','raw_acl']),
  ...refs('wrapper:migration-helper:routine-acl',['routine_identity','owner','grantor','grantee','privilege','grantable']),
  ...refs('wrapper:migration-helper:relation-resolution',['literal','cast','sourceSite','demandPath','resolvedIdentity']),
  ...refs('wrapper:migration-helper:routine-resolution',['literal','cast','sourceSite','demandPath','resolvedIdentity'])
 ];
 if(target==='zasp_temporal67.scope_authority_ready()')return [
  ...refs('wrapper:scope-authority:relation',['relation_identity','owner']),...refs('wrapper:scope-authority:routines',['routine_identity','owner','raw_acl']),
  ...refs('wrapper:scope-authority:routine-acl',['routine_identity','owner','grantor','grantee','privilege','grantable']),
  ...refs('wrapper:scope-authority:relation-resolution',['literal','cast','sourceSite','demandPath','resolvedIdentity']),
  ...refs('wrapper:scope-authority:routine-resolution',['literal','cast','sourceSite','demandPath','resolvedIdentity'])
 ];
 if(target==='zasp_authorization80.runtime_audit_ready()')return [
  ...refs('wrapper:runtime-profile',['singleton','name','audit_mode']),
  ...refs('wrapper:runtime-audit:registration-resolution',['literal','cast','sourceSite','demandPath','resolvedIdentity']),
  ...refs('wrapper:runtime-audit:catalog-resolution',['literal','cast','sourceSite','demandPath','resolvedIdentity'])
 ];
 if(target==='public.zasp_audit_export_source_catalog_role(oid,oid)'||target==='public.zasp_audit_export_source_acl_ready()')return [
  ...refs('wrapper:audit-source:relation',['relation_identity','owner','raw_acl']),...refs('wrapper:audit-source:columns',['relation_identity','number','name','raw_acl']),
  ...refs('wrapper:audit-source:relation-acl',['relation_identity','owner','acl_defaulted','grantor','grantee','privilege','grantable']),
  ...refs('wrapper:audit-source:column-acl',['relation_identity','number','name','owner','grantor','grantee','privilege','grantable']),
  ...refs('wrapper:audit-source:snapshot',['normalized_acl']),...refs('wrapper:audit-source-acl',['singleton','before_state','after_state','workflow_state'])
 ];
 if(target==='zasp_temporal72.roles_ready()')return [
  ...refs('wrapper:principals',['principal_name','authority_role']),
  ...refs('recursive:roles-ready:roles',['name','login','inherit','superuser','create_db','create_role','replication','bypass_rls']),
  ...refs('recursive:roles-ready:membership',['granted_role','member_role','admin_option']),
  ...refs('recursive:roles-ready:bindings',['source','principal_name','authority_role'])
 ];
 return [];
}

export function buildOrderedRecursiveCaptureInputs(sourceContract,catalog){
 const nodes=new Map();
 for(const identity of Object.keys(sourceSpecs))nodes.set(identity,selectedNode(sourceContract,identity));
 validateCatalog(catalog,nodes);
 const entries=[],rawRules=[],runtimeAlgebra=[],unresolved=[];
 const addRule=(rule,demandPath)=>{
  rawRules.push(rule);
  rule.fields.forEach((field,expressionOrdinal)=>entries.push({...rule.sourceSite,expressionOrdinal,field,sourceExpression:rule.projections[expressionOrdinal],selector:structuredClone(rule.selector),demandPath:[...demandPath],disposition:rule.sqlPhase==='witness'?'live-witness-only':'capture',evidence:{phase:rule.sqlPhase??'original',ruleId:rule.id,field}}));
 };

 for(const identity of richIdentities){
  const node=nodes.get(identity),spec=sourceSpecs[identity],site=sourceSite(node);
  addRule({id:`recursive:${spec.short}:routine`,kind:'routine',fields:[...ownRoutineFields],fieldTypes:{...ownRoutineTypes},projections:[...ownRoutineProjections],from:`FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang WHERE p.oid='${identity}'::regprocedure`,sourceSite:site,sourceMaxRows:1,refusalMaxRows:10000,canonicalClass:'pg_proc',handleExpression:"'pg_proc:'||p.oid::text||':0'",selector:{identity,cardinality:'exactly-one-canonical-routine',frame:'pg_catalog, public'}},[identity,'source-routine-input']);
 }

 const ready68=nodes.get('zasp_temporal68.ready(text,text)'),nativeSite=checkedSite(ready68,5113,5572,'b5d1fa21a6e6ff04d4e63768581d7aa5e214c9ce01385dc60cb240006ef70109');
 const roleNames=['zasp_temporal_executor','zasp_temporal_compensation','zasp_temporal_accounting'],roleList=roleNames.map(name=>`'${name}'`).join(','),roleRegList=roleNames.map(name=>`'${name}'::regrole`).join(',');
 addRule({id:'recursive:native-role-shape:roles',kind:'role',fields:['name','login','superuser','create_db','create_role','replication','bypass_rls'],fieldTypes:{name:'text',login:'boolean',superuser:'boolean',create_db:'boolean',create_role:'boolean',replication:'boolean',bypass_rls:'boolean'},projections:['r.rolname::text','r.rolcanlogin','r.rolsuper','r.rolcreatedb','r.rolcreaterole','r.rolreplication','r.rolbypassrls'],from:`FROM pg_roles r WHERE r.rolname IN(${roleList})`,sourceSite:nativeSite,sourceMaxRows:3,refusalMaxRows:10000,canonicalClass:'pg_authid',handleExpression:"'pg_authid:'||r.oid::text||':0'",selector:{roleNames}},['fixed-native-role-shape','roles']);
 addRule({id:'recursive:native-role-shape:membership',kind:'membership_bag',fields:['granted_role','member_role','admin_option'],fieldTypes:{granted_role:'text',member_role:'text',admin_option:'boolean'},projections:['granted.rolname::text','member.rolname::text','membership.admin_option'],from:`FROM pg_auth_members membership JOIN pg_roles granted ON granted.oid=membership.roleid JOIN pg_roles member ON member.oid=membership.member WHERE membership.roleid='zasp_temporal_accounting'::regrole OR membership.member IN(${roleRegList})`,sourceSite:nativeSite,sourceMaxRows:null,refusalMaxRows:10000,bag:true,selector:{grantedRole:'zasp_temporal_accounting',memberRoles:roleNames}},['fixed-native-role-shape','negative-membership-bag']);

 const predecessor=nodes.get('zasp_temporal68.predecessor_ready(text,text)'),metadataStart=predecessor.source.indexOf("UNION ALL SELECT concat_ws('|','metadata',key,CASE WHEN key IN("),metadataEnd=predecessor.source.indexOf('\n UNION ALL',metadataStart+1),metadataSite=checkedSite(predecessor,metadataStart,metadataEnd,'0a71679305fe3a28cffb98a5d581c5c22ef0c5b1d14fcf6512e6cbe0ac1c97f8'),metadataText=Buffer.from(predecessor.source).subarray(metadataStart,metadataEnd).toString('utf8'),metadataFrom=metadataText.slice(metadataText.lastIndexOf(' FROM public.zasp_schema_metadata')+1);
 addRule({id:'recursive:schema-metadata:normalization-input',kind:'saved_bag',fields:['key','value'],fieldTypes:{key:'text',value:'text'},projections:['key::text','value::text'],from:metadataFrom,sourceSite:metadataSite,sourceMaxRows:null,refusalMaxRows:10000,bag:true,sqlPhase:'witness',section:'witnesses',selector:{table:'public.zasp_schema_metadata',predicate:metadataFrom.slice(metadataFrom.indexOf(' WHERE ')+7)}},['metadata-owner-normalization','correlated-inputs']);

 const projectedDomain=nodes.get('zasp_authorization80_temporal.projected_domain()'),workerSpans=staticWorkerSpans(projectedDomain);
 const guardFields=['routine_identity','source_body','owner','raw_acl','language','security_definer','volatility','config_json','config_raw','config_dims','config_ndims','config_bounds'];
 const guardTypes={routine_identity:'text',source_body:'text',owner:'text',raw_acl:'text?',language:'text',security_definer:'boolean',volatility:'text',config_json:'json?',config_raw:'text?',config_dims:'text?',config_ndims:'integer?',config_bounds:'json?'};
 const guardProjections=['p.oid::regprocedure::text','p.prosrc::text','p.proowner::regrole::text','p.proacl::text','l.lanname::text','p.prosecdef','p.provolatile::text','to_jsonb(p.proconfig)','p.proconfig::text','array_dims(p.proconfig)','array_ndims(p.proconfig)','(SELECT jsonb_agg(jsonb_build_array(array_lower(p.proconfig,d),array_upper(p.proconfig,d)) ORDER BY d) FROM generate_series(1,array_ndims(p.proconfig)) d)'];
 addRule({id:'recursive:worker-catalog-ready:routine',kind:'routine',fields:guardFields,fieldTypes:guardTypes,projections:guardProjections,from:"FROM pg_proc p JOIN pg_language l ON l.oid=p.prolang WHERE p.oid='zasp_authorization80_worker.catalog_ready()'::regprocedure",sourceSite:workerSpans.callable,sourceMaxRows:1,refusalMaxRows:10000,canonicalClass:'pg_proc',handleExpression:"'pg_proc:'||p.oid::text||':0'",selector:{identity:'zasp_authorization80_worker.catalog_ready()',sourceBodySHA256:'28bc26660db8eae036fd2f36bc215fcf2e27c1aba6d2c7c42d5d6a58e73c5016'}},['worker-catalog-ready-guard','static-callable-inputs']);
 addRule({id:'recursive:worker-catalog-ready:definition',kind:'routine',fields:['definition'],fieldTypes:{definition:'text'},projections:['pg_get_functiondef(p.oid)'],from:"FROM pg_proc p WHERE p.oid='zasp_authorization80_worker.catalog_ready()'::regprocedure",sourceSite:higherCatalogSite(ready68),sourceMaxRows:1,refusalMaxRows:10000,canonicalClass:'pg_proc',handleExpression:"'pg_proc:'||p.oid::text||':0'",selector:{identity:'zasp_authorization80_worker.catalog_ready()',normalization:[['e12fb150ebaf718d39883a8e6e3b63caac90fb05409895e0fc832e717ab46960','<worker-checksum>'],['28bc26660db8eae036fd2f36bc215fcf2e27c1aba6d2c7c42d5d6a58e73c5016','<worker-catalog>']],normalizedSHA256:'3b46aa8607e042925c3cc56b66605244a0a6fe9ff2db41fcd339c8e6c7bebac8'}},['ready-predicate','worker-catalog-ready-normalized-definition']);
 addRule({id:'recursive:worker-catalog-ready:registration',kind:'live_guard_input_bag',fields:['checksum'],fieldTypes:{checksum:'text'},projections:['checksum::text'],from:"FROM zasp_authorization80_worker.registration WHERE checksum='e12fb150ebaf718d39883a8e6e3b63caac90fb05409895e0fc832e717ab46960'",sourceSite:workerSpans.registration,sourceMaxRows:null,refusalMaxRows:10000,bag:true,sqlPhase:'witness',section:'witnesses',selector:{table:'zasp_authorization80_worker.registration',checksum:'e12fb150ebaf718d39883a8e6e3b63caac90fb05409895e0fc832e717ab46960'}},['worker-catalog-ready-guard','registration-exists']);
 const literalSite=workerSpans.callable,literalSiteValue=literalSite.siteSHA256;
 addRule({id:'recursive:worker-catalog-ready:literal-resolution',kind:'resolution',fields:['literal','cast','sourceSite','demandPath','resolvedIdentity'],fieldTypes:{literal:'text',cast:'text',sourceSite:'text',demandPath:'text',resolvedIdentity:'text'},projections:['demanded.literal','demanded.cast_name',`'${literalSiteValue}'`,`'worker-catalog-ready-static-check'`,"CASE WHEN demanded.cast_name='regprocedure' THEN demanded.literal::regprocedure::text ELSE demanded.literal::regrole::text END"],from:"FROM (VALUES ('zasp_authorization80_worker.catalog_ready()','regprocedure'),('zasp_discovery_authority','regrole')) demanded(literal,cast_name)",sourceSite:literalSite,sourceMaxRows:2,refusalMaxRows:10000,bag:true,sqlPhase:'resolution',section:'resolutions',selector:{literals:[{literal:'zasp_authorization80_worker.catalog_ready()',cast:'regprocedure'},{literal:'zasp_discovery_authority',cast:'regrole'}]}},['worker-catalog-ready-guard','literal-resolution']);

 const temporal65=nodes.get('zasp_temporal65.fingerprint()');
 addRule({id:'recursive:temporal74:registration',kind:'live_guard_input_bag',fields:['checksum','fingerprint'],fieldTypes:{checksum:'text',fingerprint:'text'},projections:['checksum::text','fingerprint::text'],from:'FROM zasp_temporal74.registration',sourceSite:sourceSite(temporal65),sourceMaxRows:null,refusalMaxRows:10000,bag:true,sqlPhase:'witness',section:'witnesses',selector:{table:'zasp_temporal74.registration',predicate:null}},['conditional-wrapper','65-66-registration-count-and-match']);

 for(const family of ['76','77','78']){
  const identity=`zasp_temporal${family}.catalog_ready()`,node=nodes.get(identity),table=`zasp_temporal${family}.registration`;
  addRule({id:`recursive:temporal${family}:registration`,kind:'live_guard_input_bag',fields:['checksum','fingerprint'],fieldTypes:{checksum:'text',fingerprint:'text'},projections:['checksum::text','fingerprint::text'],from:`FROM ${table}`,sourceSite:sourceSite(node),sourceMaxRows:null,refusalMaxRows:10000,bag:true,sqlPhase:'witness',section:'witnesses',selector:{table,predicate:null}},[identity,'registration-count-checksum-fingerprint']);
 }
 const authorizationCatalog=nodes.get('zasp_authorization80_temporal.catalog_ready()');
 addRule({id:'recursive:authorization80-temporal:registration',kind:'live_guard_input_bag',fields:['checksum','fingerprint'],fieldTypes:{checksum:'text',fingerprint:'text'},projections:['checksum::text','fingerprint::text'],from:'FROM zasp_authorization80_temporal.registration',sourceSite:sourceSite(authorizationCatalog),sourceMaxRows:null,refusalMaxRows:10000,bag:true,sqlPhase:'witness',section:'witnesses',selector:{table:'zasp_authorization80_temporal.registration',predicate:null}},['zasp_authorization80_temporal.catalog_ready()','registration-count-checksum-fingerprint']);

 const rolesReady=nodes.get('zasp_temporal72.roles_ready()'),rolesReadySite=sourceSite(rolesReady);
 addRule({id:'recursive:roles-ready:roles',kind:'role',fields:['name','login','inherit','superuser','create_db','create_role','replication','bypass_rls'],fieldTypes:{name:'text',login:'boolean',inherit:'boolean',superuser:'boolean',create_db:'boolean',create_role:'boolean',replication:'boolean',bypass_rls:'boolean'},projections:['r.rolname::text','r.rolcanlogin','r.rolinherit','r.rolsuper','r.rolcreatedb','r.rolcreaterole','r.rolreplication','r.rolbypassrls'],from:'FROM pg_roles r WHERE r.rolname IN(SELECT principal_name FROM zasp_temporal72.principals UNION SELECT authority_role FROM zasp_temporal72.principals)',sourceSite:rolesReadySite,sourceMaxRows:null,refusalMaxRows:10000,bag:true,sqlPhase:'witness',section:'witnesses',selector:{selectedBy:'zasp_temporal72.principals.principal_name UNION authority_role'}},['zasp_temporal72.roles_ready()','selected-role-shape']);
 addRule({id:'recursive:roles-ready:membership',kind:'membership_bag',fields:['granted_role','member_role','admin_option'],fieldTypes:{granted_role:'text',member_role:'text',admin_option:'boolean'},projections:['granted.rolname::text','member.rolname::text','membership.admin_option'],from:'FROM pg_auth_members membership JOIN pg_roles granted ON granted.oid=membership.roleid JOIN pg_roles member ON member.oid=membership.member WHERE member.rolname IN(SELECT principal_name FROM zasp_temporal72.principals)',sourceSite:rolesReadySite,sourceMaxRows:null,refusalMaxRows:10000,bag:true,sqlPhase:'witness',section:'witnesses',selector:{memberSelectedBy:'zasp_temporal72.principals.principal_name'}},['zasp_temporal72.roles_ready()','all-selected-principal-memberships']);
 addRule({id:'recursive:roles-ready:bindings',kind:'saved_bag',fields:['source','principal_name','authority_role'],fieldTypes:{source:'text',principal_name:'text',authority_role:'text'},projections:['b.source::text','b.principal_name::text','b.authority_role::text'],from:"FROM (SELECT 'principal-bindings'::text source,principal_name,authority_role FROM public.zasp_discovery_principal_bindings UNION ALL SELECT 'execution-principals'::text source,principal_name,authority_role FROM public.zasp_discovery_execution_principals) b WHERE EXISTS(SELECT 1 FROM zasp_temporal72.principals p WHERE (p.principal_name,p.authority_role)=(b.principal_name,b.authority_role))",sourceSite:rolesReadySite,sourceMaxRows:null,refusalMaxRows:10000,bag:true,sqlPhase:'witness',section:'witnesses',selector:{tables:['public.zasp_discovery_principal_bindings','public.zasp_discovery_execution_principals'],selectedBy:'zasp_temporal72.principals pair'}},['zasp_temporal72.roles_ready()','binding-union-existence']);

 const ready78=nodes.get('zasp_temporal78.ready(text,text)');
 for(const family of ['68','69','70','71','72','73','75']){
  const table=`zasp_temporal${family}.registration`,node=family==='68'?ready68:ready78;
  const [start,end,pin]=readyRegistrationPins[node.identity][table].at(-1);
  addRule({id:`recursive:temporal${family}:registration`,kind:'live_guard_input_bag',fields:['checksum','fingerprint'],fieldTypes:{checksum:'text',fingerprint:'text'},projections:['checksum::text','fingerprint::text'],from:`FROM ${table}`,sourceSite:checkedSite(node,start,end,pin),sourceMaxRows:null,refusalMaxRows:10000,bag:true,sqlPhase:'witness',section:'witnesses',selector:{table,predicate:null}},[node.identity,`${table}-full-count-and-match`]);
 }
 for(const family of ['79','80']){
  const table=`zasp_authorization${family}.registration`;
  const [start,end,pin]=readyRegistrationPins[ready68.identity][table][0];
  addRule({id:`recursive:authorization${family}:registration`,kind:'live_guard_input_bag',fields:['checksum','fingerprint'],fieldTypes:{checksum:'text',fingerprint:'text'},projections:['checksum::text','fingerprint::text'],from:`FROM ${table}`,sourceSite:checkedSite(ready68,start,end,pin),sourceMaxRows:null,refusalMaxRows:10000,bag:true,sqlPhase:'witness',section:'witnesses',selector:{table,predicate:null}},[ready68.identity,`${table}-full-match`]);
 }

 const addReadyWitness=(node,site,children,kind)=>runtimeAlgebra.push({...site,ruleId:`recursive:${sourceSpecs[node.identity].short}:predicate:${site.start}`,disposition:'ready-predicate-live-witness-algebra',kind,children,sourceChildren:[],expression:Buffer.from(node.source).subarray(site.start,site.end).toString('utf8'),expectedFact:false});
 for(const [node,start,end] of [[ready68,131,692],[ready78,287,848]])addReadyWitness(node,checkedSite(node,start,end,'ea74f616b5fd356dc02efa99ddba46853ad8263ae5cd2a3de9e47b81ac0b558f'),[...refs('recursive:worker-catalog-ready:routine',guardFields),...refs('recursive:worker-catalog-ready:definition',['definition'])],'normalized-worker-catalog-definition');
 for(const node of [ready68,ready78])for(const [table,pins] of Object.entries(readyRegistrationPins[node.identity])){
  const family=table.split('.')[0].replace('zasp_',''),ruleId=table==='zasp_authorization80_temporal.registration'?'recursive:authorization80-temporal:registration':`recursive:${family}:registration`;
  for(const [start,end,pin] of pins)addReadyWitness(node,checkedSite(node,start,end,pin),refs(ruleId,['checksum','fingerprint']),'registration-cardinality-and-match');
 }

 for(const family of ['76','77','78']){
  const identity=`zasp_temporal${family}.catalog_ready()`,target=`zasp_temporal${family}.fingerprint()`,node=nodes.get(identity);
  runtimeAlgebra.push({...sourceSite(node),ruleId:`recursive:temporal${family}-catalog-ready:algebra`,disposition:'catalog-ready-source-algebra',children:refs(`recursive:temporal${family}:registration`,['checksum','fingerprint']),sourceChildren:[{sourceIdentity:target,sourceSite:callSite(node,target,true),required:'all-source-selected-raw-children',execution:'live-current-fingerprint-not-expected-fact'}],expression:node.source,expectedFact:false,cardinality:'unfiltered registration count must equal one; checksum and fingerprint must match before the live fingerprint comparison'});
 }
 const authorizationCalls=[
  ['zasp_authorization80_temporal.fingerprint()','zasp_authorization80_temporal.fingerprint()'],
  ['zasp_authorization79.ready(text)',"zasp_authorization79.ready('8b358e304b2eedaed7a4148f317f6d21d9c624ccc39105ca6199265ae661a987')"],
  ['zasp_authorization80.fingerprint()','zasp_authorization80.fingerprint()'],
  ['zasp_authorization80.runtime_audit_ready()','zasp_authorization80.runtime_audit_ready()'],
  ['zasp_authorization80_temporal.triggers_ready(boolean)','zasp_authorization80_temporal.triggers_ready(true)']
 ];
 runtimeAlgebra.push({...sourceSite(authorizationCatalog),ruleId:'recursive:authorization80-temporal-catalog-ready:algebra',disposition:'catalog-ready-source-algebra',children:[...refs('recursive:authorization80-temporal:registration',['checksum','fingerprint']),...refs('wrapper:runtime-profile',['singleton','name'])],sourceChildren:authorizationCalls.map(([sourceIdentity,text])=>({sourceIdentity,sourceSite:callSite(authorizationCatalog,text),required:'all-source-selected-raw-children',execution:'original live call not expected fact'})),expression:authorizationCatalog.source,expectedFact:false,cardinality:'preserve registration count/EXISTS, runtime-profile count plus bool_and, COALESCE false, left-to-right demand, NULL and error behavior'});
 runtimeAlgebra.push({...rolesReadySite,ruleId:'recursive:roles-ready:algebra',disposition:'live-witness-source-algebra',children:[...refs('wrapper:principals',['principal_name','authority_role']),...refs('recursive:roles-ready:roles',['name','login','inherit','superuser','create_db','create_role','replication','bypass_rls']),...refs('recursive:roles-ready:membership',['granted_role','member_role','admin_option']),...refs('recursive:roles-ready:bindings',['source','principal_name','authority_role'])],sourceChildren:[],expression:rolesReady.source,expectedFact:false,cardinality:'preserve principals count=4, missing-role LEFT JOIN behavior, every positive and negative membership edge, binding UNION ALL existence, NULL and error behavior'});

 for(const identity of richIdentities){
  const node=nodes.get(identity),spec=sourceSpecs[identity],obligation=sourceContract.materializedObligations.find(row=>row.identity===identity);
  if(!obligation||obligation.sourceSHA256!==node.sourceSHA256)throw Error('recursive capture materialized pin '+identity);
  const targetByCallId={},sourceChildren=obligation.retainedLiveCalls.map(call=>{
   const target=retainedTarget(call.name);targetByCallId[call.id]=target;
   if(!sourceContract.nodes.some(candidate=>candidate.identity===target))throw Error('recursive capture retained target '+target);
   return {sourceIdentity:target,sourceSite:checkedSite(node,call.start,call.end),edgeId:call.id,required:target==='zasp_authorization80_worker.projected74()'?'retained-opaque-P':'all-source-selected-raw-children',children:retainedChildren(target),execution:'live-current-result-not-expected-fact'};
  });
  const children=refs(`recursive:${spec.short}:routine`,ownRoutineFields);
  for(const span of obligation.structuralInvariantSpans){
   if(span.kind==='fixed-current-profile')children.push(...refs('wrapper:runtime-profile',['singleton','name']));
   if(span.kind==='fixed-native-role-shape-and-membership')children.push(...refs('recursive:native-role-shape:roles',['name','login','superuser','create_db','create_role','replication','bypass_rls']),...refs('recursive:native-role-shape:membership',['granted_role','member_role','admin_option']));
   runtimeAlgebra.push({...checkedSite(node,span.start,span.end,span.sha256),ruleId:`recursive:${spec.short}:structural:${span.start}`,kind:span.kind,disposition:'structural-inputs-under-live-expression',children:span.kind==='fixed-current-profile'?refs('wrapper:runtime-profile',['singleton','name']):[...refs('recursive:native-role-shape:roles',['name','login','superuser','create_db','create_role','replication','bypass_rls']),...refs('recursive:native-role-shape:membership',['granted_role','member_role','admin_option'])],expectedFact:false,cardinality:span.kind==='fixed-current-profile'?'count(*)=1 plus bool_and over the unfiltered bag; zero rows preserves SQL NULL':'three selected roles plus every matching membership tuple; missing regrole casts retain original errors'});
  }
  for(const span of obligation.inlineLiveSpans){
   const liveChildren=span.kind==='saved-export-migration-owner'?refs('saved-input:zasp_sa_export_prior.functions',['signature','owner_name']):refs('recursive:schema-metadata:normalization-input',['key','value']);
   runtimeAlgebra.push({...checkedSite(node,span.start,span.end,span.sha256),ruleId:`recursive:${spec.short}:live:${span.start}`,kind:span.kind,disposition:'live-witness-only',children:liveChildren,expectedFact:false,liveRelations:[...span.liveRelations],expression:span.text,cardinality:'original correlated EXISTS/member/login/binding semantics; result is never an expected field'});
  }
  runtimeAlgebra.push({...sourceSite(node),ruleId:`recursive:${spec.short}:algebra`,rawRuleId:`recursive:${spec.short}:routine`,disposition:'recursive-source-algebra',children,sourceChildren,targetByCallId,recipeSegments:structuredClone(obligation.recipeSegments),expectedFact:false});
  const region=sourceContract.higherRegions.find(row=>row.identity===identity);
  if(region){
   if(region.sourceSHA256!==node.sourceSHA256||sha(region.prefix)!==region.prefixSHA256||sha(region.originalExpression)!==region.originalExpressionSHA256||sha(region.suffix)!==region.suffixSHA256)throw Error('recursive capture higher region pin '+identity);
   runtimeAlgebra.at(-1).higherRegion={prefix:region.prefix,prefixSHA256:region.prefixSHA256,originalExpression:region.originalExpression,originalExpressionSHA256:region.originalExpressionSHA256,suffix:region.suffix,suffixSHA256:region.suffixSHA256,tailObligation:region.tailObligation};
  }
 }

 runtimeAlgebra.push({...checkedSite(predecessor,118841,119679),ruleId:'recursive:predecessor68:conditional63-64-tail',disposition:'live-witness-only',kind:'conditional63-64-tail',children:refs('wrapper:retired-authorities',['schema_name','original_fingerprint','retired_fingerprint']),expectedFact:false,cardinality:'preserve zero, one, both, duplicates and orphans in the fixed saved bag',controlFlow:'namespace presence IS DISTINCT FROM FOUND; absent row CONTINUE; fixed original fingerprints; dynamic fingerprint execution and effective EXECUTE refusal remain live'});

 const addConditional=(ruleId,identity,targets)=>{
  const node=nodes.get(identity),guard=targets[0],selected=targets[1],guardText=guard;
  const sourceChildren=[
   {sourceIdentity:guard,sourceSite:callSite(node,guardText,true),required:'live-guard-with-all-source-selected-raw-children',execution:'live-current-result-not-expected-fact'},
   {sourceIdentity:selected,sourceSite:callSite(node,selected,true),required:selected==='zasp_authorization80_worker.projected74()'?'retained-opaque-P':'all-source-selected-raw-children',execution:'selected-only-under-original-guard'}
  ];
  const children=refsForTarget(selected);
  if(guard==='zasp_authorization80_worker.catalog_ready()')children.push(...refs('recursive:worker-catalog-ready:routine',guardFields),...refs('recursive:worker-catalog-ready:registration',['checksum']),...refs('recursive:worker-catalog-ready:literal-resolution',['literal','cast','sourceSite','demandPath','resolvedIdentity']));
  if(guard==='zasp_temporal72.fingerprint()')children.push(...refs('schedule:guard-registration',['checksum','fingerprint']));
  if(identity==='zasp_temporal65.fingerprint()'||identity==='zasp_temporal66.fingerprint()')children.push(...refs('recursive:temporal74:registration',['checksum','fingerprint']));
  if(selected==='zasp_temporal77.base67_fingerprint()')children.push(...refs('recursive:base67:routine',ownRoutineFields));
  const algebra={...sourceSite(node),ruleId,disposition:'conditional-source-algebra',children,sourceChildren,liveGuard:{sourceIdentity:guard,expectedFact:false,execution:'original live call with original NULL/error/demand ordering'},selectedChild:{sourceIdentity:selected,demand:'only when original guard is true'},nullElse:/ELSE\s+''\s+END/.test(node.source)?"''":'NULL',expression:node.source,expectedFact:false};
  if(guard==='zasp_authorization80_worker.catalog_ready()'&&node.source.includes('EXISTS(SELECT 1 FROM pg_proc'))algebra.guardStructuralSites=staticWorkerSpans(node);
  if(identity==='zasp_temporal65.fingerprint()'||identity==='zasp_temporal66.fingerprint()')algebra.cardinality='unfiltered temporal74 registration count must equal one; checksum/fingerprint match and live temporal74 fingerprint equality precede selected child';
  runtimeAlgebra.push(algebra);
 };

 addConditional('recursive:projected-domain:algebra','zasp_authorization80_temporal.projected_domain()',['zasp_authorization80_worker.catalog_ready()','zasp_authorization80_worker.projected_domain()']);
 addConditional('recursive:temporal-projected72:algebra','zasp_authorization80_temporal.projected72()',['zasp_authorization80_worker.catalog_ready()','zasp_authorization80_worker.projected72()']);
 for(const [identity,targets] of Object.entries(publicConditionals))addConditional(`recursive:${sourceSpecs[identity].short}:algebra`,identity,targets);
 for(const [family,spec] of Object.entries(conditionalSpecs))addConditional(`recursive:conditional:${family}`,spec.identity,spec.targets);
 for(const [identity,targets] of Object.entries(additionalConditionals))addConditional(`recursive:${sourceSpecs[identity].short}:algebra`,identity,targets);

 return {entries,rawRules,runtimeAlgebra,unresolved};
}
