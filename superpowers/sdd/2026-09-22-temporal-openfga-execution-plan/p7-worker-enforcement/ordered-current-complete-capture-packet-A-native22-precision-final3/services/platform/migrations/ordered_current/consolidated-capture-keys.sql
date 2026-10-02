SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected_domain:table:keys','identity',c.oid::regclass::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_class c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker:projected_domain:table:demand' AND split_part(d.handle,':',1)='pg_class'
) AS capture_keys_0001
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected_domain:foreign-key-trigger:keys','identity',jsonb_build_array(c.tgrelid::regclass::text,c.tgname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_trigger c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker:projected_domain:foreign-key-trigger:demand' AND split_part(d.handle,':',1)='pg_trigger'
) AS capture_keys_0002
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected62:table:keys','identity',c.oid::regclass::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_class c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker:projected62:table:demand' AND split_part(d.handle,':',1)='pg_class'
) AS capture_keys_0003
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected68:table:keys','identity',c.oid::regclass::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_class c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker:projected68:table:demand' AND split_part(d.handle,':',1)='pg_class'
) AS capture_keys_0004
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected68:foreign-key-trigger:keys','identity',jsonb_build_array(c.tgrelid::regclass::text,c.tgname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_trigger c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker:projected68:foreign-key-trigger:demand' AND split_part(d.handle,':',1)='pg_trigger'
) AS capture_keys_0005
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected69:table:keys','identity',c.oid::regclass::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_class c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker:projected69:table:demand' AND split_part(d.handle,':',1)='pg_class'
) AS capture_keys_0006
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected69:foreign-key-trigger:keys','identity',jsonb_build_array(c.tgrelid::regclass::text,c.tgname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_trigger c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker:projected69:foreign-key-trigger:demand' AND split_part(d.handle,':',1)='pg_trigger'
) AS capture_keys_0007
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected72:table:keys','identity',c.oid::regclass::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_class c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker:projected72:table:demand' AND split_part(d.handle,':',1)='pg_class'
) AS capture_keys_0008
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected72:foreign-key-trigger:keys','identity',jsonb_build_array(c.tgrelid::regclass::text,c.tgname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_trigger c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker:projected72:foreign-key-trigger:demand' AND split_part(d.handle,':',1)='pg_trigger'
) AS capture_keys_0009
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected78:table:keys','identity',c.oid::regclass::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_class c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker:projected78:table:demand' AND split_part(d.handle,':',1)='pg_class'
) AS capture_keys_0010
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected78:foreign-key-trigger:keys','identity',jsonb_build_array(c.tgrelid::regclass::text,c.tgname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_trigger c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker:projected78:foreign-key-trigger:demand' AND split_part(d.handle,':',1)='pg_trigger'
) AS capture_keys_0011
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:gateway_projected24:2:keys','identity',c.oid::regclass::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_class c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker-edge:gateway_projected24:2:demand' AND split_part(d.handle,':',1)='pg_class'
) AS capture_keys_0012
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:gateway_projected24:3:keys','identity',jsonb_build_array(c.attrelid::regclass::text,c.attnum,c.attname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_attribute c ON c.attrelid=split_part(d.handle,':',2)::oid AND c.attnum=split_part(d.handle,':',3)::integer WHERE d."ruleId"='worker-edge:gateway_projected24:3:demand' AND split_part(d.handle,':',1)='pg_attribute'
) AS capture_keys_0013
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:gateway_projected24:4:keys','identity',jsonb_build_array(c.connamespace::regnamespace::text,CASE WHEN c.conrelid<>0 THEN c.conrelid::regclass::text ELSE NULL END,CASE WHEN c.contypid<>0 THEN c.contypid::regtype::text ELSE NULL END,c.conname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_constraint c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker-edge:gateway_projected24:4:demand' AND split_part(d.handle,':',1)='pg_constraint'
) AS capture_keys_0014
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:gateway_projected24:5:keys','identity',c.oid::regclass::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_class c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker-edge:gateway_projected24:5:demand' AND split_part(d.handle,':',1)='pg_class'
) AS capture_keys_0015
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:gateway_projected24:7:keys','identity',jsonb_build_array(c.connamespace::regnamespace::text,CASE WHEN c.conrelid<>0 THEN c.conrelid::regclass::text ELSE NULL END,CASE WHEN c.contypid<>0 THEN c.contypid::regtype::text ELSE NULL END,c.conname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_constraint c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker-edge:gateway_projected24:7:demand' AND split_part(d.handle,':',1)='pg_constraint'
) AS capture_keys_0016
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:gateway_projected27:2:keys','identity',c.rolname::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_roles c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker-edge:gateway_projected27:2:demand' AND split_part(d.handle,':',1)='pg_authid'
) AS capture_keys_0017
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:gateway_projected27:4:keys','identity',c.oid::regclass::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_class c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker-edge:gateway_projected27:4:demand' AND split_part(d.handle,':',1)='pg_class'
) AS capture_keys_0018
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:gateway_projected27:5:keys','identity',c.oid::regclass::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_class c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker-edge:gateway_projected27:5:demand' AND split_part(d.handle,':',1)='pg_class'
) AS capture_keys_0019
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:gateway_projected27:6:keys','identity',jsonb_build_array(c.attrelid::regclass::text,c.attnum,c.attname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_attribute c ON c.attrelid=split_part(d.handle,':',2)::oid AND c.attnum=split_part(d.handle,':',3)::integer WHERE d."ruleId"='worker-edge:gateway_projected27:6:demand' AND split_part(d.handle,':',1)='pg_attribute'
) AS capture_keys_0020
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:gateway_projected27:7:keys','identity',jsonb_build_array(c.connamespace::regnamespace::text,CASE WHEN c.conrelid<>0 THEN c.conrelid::regclass::text ELSE NULL END,CASE WHEN c.contypid<>0 THEN c.contypid::regtype::text ELSE NULL END,c.conname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_constraint c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker-edge:gateway_projected27:7:demand' AND split_part(d.handle,':',1)='pg_constraint'
) AS capture_keys_0021
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:gateway_projected27:8:keys','identity',jsonb_build_array(c.attrelid::regclass::text,c.attnum,c.attname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_attribute c ON c.attrelid=split_part(d.handle,':',2)::oid AND c.attnum=split_part(d.handle,':',3)::integer WHERE d."ruleId"='worker-edge:gateway_projected27:8:demand' AND split_part(d.handle,':',1)='pg_attribute'
) AS capture_keys_0022
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:gateway_projected27:9:keys','identity',jsonb_build_array(c.connamespace::regnamespace::text,CASE WHEN c.conrelid<>0 THEN c.conrelid::regclass::text ELSE NULL END,CASE WHEN c.contypid<>0 THEN c.contypid::regtype::text ELSE NULL END,c.conname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_constraint c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker-edge:gateway_projected27:9:demand' AND split_part(d.handle,':',1)='pg_constraint'
) AS capture_keys_0023
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:gateway_projected27:10:keys','identity',c.oid::regclass::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_class c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker-edge:gateway_projected27:10:demand' AND split_part(d.handle,':',1)='pg_class'
) AS capture_keys_0024
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:gateway_projected27:11:keys','identity',jsonb_build_array(c.polrelid::regclass::text,c.polname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_policy c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker-edge:gateway_projected27:11:demand' AND split_part(d.handle,':',1)='pg_policy'
) AS capture_keys_0025
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:gateway_projected27:12:keys','identity',jsonb_build_array(c.tgrelid::regclass::text,c.tgname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_trigger c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker-edge:gateway_projected27:12:demand' AND split_part(d.handle,':',1)='pg_trigger'
) AS capture_keys_0026
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:ordered_projected28:2:keys','identity',c.rolname::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_roles c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker-edge:ordered_projected28:2:demand' AND split_part(d.handle,':',1)='pg_authid'
) AS capture_keys_0027
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:ordered_projected28:4:keys','identity',c.oid::regclass::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_class c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker-edge:ordered_projected28:4:demand' AND split_part(d.handle,':',1)='pg_class'
) AS capture_keys_0028
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:ordered_projected28:5:keys','identity',jsonb_build_array(c.attrelid::regclass::text,c.attnum,c.attname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_attribute c ON c.attrelid=split_part(d.handle,':',2)::oid AND c.attnum=split_part(d.handle,':',3)::integer WHERE d."ruleId"='worker-edge:ordered_projected28:5:demand' AND split_part(d.handle,':',1)='pg_attribute'
) AS capture_keys_0029
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:ordered_projected28:6:keys','identity',c.oid::regclass::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_class c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker-edge:ordered_projected28:6:demand' AND split_part(d.handle,':',1)='pg_class'
) AS capture_keys_0030
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:ordered_projected28:7:keys','identity',jsonb_build_array(c.connamespace::regnamespace::text,CASE WHEN c.conrelid<>0 THEN c.conrelid::regclass::text ELSE NULL END,CASE WHEN c.contypid<>0 THEN c.contypid::regtype::text ELSE NULL END,c.conname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_constraint c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker-edge:ordered_projected28:7:demand' AND split_part(d.handle,':',1)='pg_constraint'
) AS capture_keys_0031
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:ordered_projected28:8:keys','identity',jsonb_build_array(c.polrelid::regclass::text,c.polname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_policy c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker-edge:ordered_projected28:8:demand' AND split_part(d.handle,':',1)='pg_policy'
) AS capture_keys_0032
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:ordered_projected28:9:keys','identity',jsonb_build_array(c.tgrelid::regclass::text,c.tgname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_trigger c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker-edge:ordered_projected28:9:demand' AND split_part(d.handle,':',1)='pg_trigger'
) AS capture_keys_0033
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:runtime_projected40:3:keys','identity',c.oid::regclass::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_class c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker-edge:runtime_projected40:3:demand' AND split_part(d.handle,':',1)='pg_class'
) AS capture_keys_0034
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:runtime_projected40:4:keys','identity',jsonb_build_array(c.connamespace::regnamespace::text,CASE WHEN c.conrelid<>0 THEN c.conrelid::regclass::text ELSE NULL END,CASE WHEN c.contypid<>0 THEN c.contypid::regtype::text ELSE NULL END,c.conname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_constraint c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker-edge:runtime_projected40:4:demand' AND split_part(d.handle,':',1)='pg_constraint'
) AS capture_keys_0035
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:runtime_projected40:5:keys','identity',jsonb_build_array(c.attrelid::regclass::text,c.attnum,c.attname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_attribute c ON c.attrelid=split_part(d.handle,':',2)::oid AND c.attnum=split_part(d.handle,':',3)::integer WHERE d."ruleId"='worker-edge:runtime_projected40:5:demand' AND split_part(d.handle,':',1)='pg_attribute'
) AS capture_keys_0036
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:runtime_projected40:6:keys','identity',jsonb_build_array(c.polrelid::regclass::text,c.polname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_policy c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker-edge:runtime_projected40:6:demand' AND split_part(d.handle,':',1)='pg_policy'
) AS capture_keys_0037
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:runtime_projected40:7:keys','identity',c.oid::regclass::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_class c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker-edge:runtime_projected40:7:demand' AND split_part(d.handle,':',1)='pg_class'
) AS capture_keys_0038
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:runtime_projected50_binding:3:keys','identity',c.oid::regprocedure::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_proc c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker-edge:runtime_projected50_binding:3:demand' AND split_part(d.handle,':',1)='pg_proc'
) AS capture_keys_0039
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:runtime_projected50_binding:4:keys','identity',jsonb_build_array(c.tgrelid::regclass::text,c.tgname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_trigger c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker-edge:runtime_projected50_binding:4:demand' AND split_part(d.handle,':',1)='pg_trigger'
) AS capture_keys_0040
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:runtime_projected50_binding:5:keys','identity',c.oid::regprocedure::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_proc c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker-edge:runtime_projected50_binding:5:demand' AND split_part(d.handle,':',1)='pg_proc'
) AS capture_keys_0041
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:runtime_projected50_binding:6:keys','identity',jsonb_build_array(c.attrelid::regclass::text,c.attnum,c.attname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_attribute c ON c.attrelid=split_part(d.handle,':',2)::oid AND c.attnum=split_part(d.handle,':',3)::integer WHERE d."ruleId"='worker-edge:runtime_projected50_binding:6:demand' AND split_part(d.handle,':',1)='pg_attribute'
) AS capture_keys_0042
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:runtime_projected50_binding:7:keys','identity',c.oid::regprocedure::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_proc c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker-edge:runtime_projected50_binding:7:demand' AND split_part(d.handle,':',1)='pg_proc'
) AS capture_keys_0043
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:runtime_projected50_binding:8:keys','identity',c.oid::regprocedure::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_proc c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker-edge:runtime_projected50_binding:8:demand' AND split_part(d.handle,':',1)='pg_proc'
) AS capture_keys_0044
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:runtime_projected50_search:4:keys','identity',c.oid::regclass::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_class c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker-edge:runtime_projected50_search:4:demand' AND split_part(d.handle,':',1)='pg_class'
) AS capture_keys_0045
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:runtime_projected50_search:5:keys','identity',jsonb_build_array(c.connamespace::regnamespace::text,CASE WHEN c.conrelid<>0 THEN c.conrelid::regclass::text ELSE NULL END,CASE WHEN c.contypid<>0 THEN c.contypid::regtype::text ELSE NULL END,c.conname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_constraint c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker-edge:runtime_projected50_search:5:demand' AND split_part(d.handle,':',1)='pg_constraint'
) AS capture_keys_0046
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:runtime_projected50_search:6:keys','identity',jsonb_build_array(c.attrelid::regclass::text,c.attnum,c.attname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_attribute c ON c.attrelid=split_part(d.handle,':',2)::oid AND c.attnum=split_part(d.handle,':',3)::integer WHERE d."ruleId"='worker-edge:runtime_projected50_search:6:demand' AND split_part(d.handle,':',1)='pg_attribute'
) AS capture_keys_0047
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:runtime_projected50_search:7:keys','identity',jsonb_build_array(c.polrelid::regclass::text,c.polname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_policy c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker-edge:runtime_projected50_search:7:demand' AND split_part(d.handle,':',1)='pg_policy'
) AS capture_keys_0048
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:runtime_projected50_search:8:keys','identity',c.oid::regclass::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_class c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker-edge:runtime_projected50_search:8:demand' AND split_part(d.handle,':',1)='pg_class'
) AS capture_keys_0049
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:runtime_projected50_search:9:keys','identity',jsonb_build_array(c.tgrelid::regclass::text,c.tgname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_trigger c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker-edge:runtime_projected50_search:9:demand' AND split_part(d.handle,':',1)='pg_trigger'
) AS capture_keys_0050
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected_domain:column:keys','identity',jsonb_build_array(c.attrelid::regclass::text,c.attnum,c.attname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_attribute c ON c.attrelid=split_part(d.handle,':',2)::oid AND c.attnum=split_part(d.handle,':',3)::integer WHERE d."ruleId"='worker:projected_domain:column:demand' AND split_part(d.handle,':',1)='pg_attribute'
) AS capture_keys_0051
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected_domain:constraint:keys','identity',jsonb_build_array(c.connamespace::regnamespace::text,CASE WHEN c.conrelid<>0 THEN c.conrelid::regclass::text ELSE NULL END,CASE WHEN c.contypid<>0 THEN c.contypid::regtype::text ELSE NULL END,c.conname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_constraint c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker:projected_domain:constraint:demand' AND split_part(d.handle,':',1)='pg_constraint'
) AS capture_keys_0052
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected_domain:index:keys','identity',c.oid::regclass::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_class c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker:projected_domain:index:demand' AND split_part(d.handle,':',1)='pg_class'
) AS capture_keys_0053
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected_domain:policy:keys','identity',jsonb_build_array(c.polrelid::regclass::text,c.polname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_policy c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker:projected_domain:policy:demand' AND split_part(d.handle,':',1)='pg_policy'
) AS capture_keys_0054
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected_temporal_profile:schema:keys','identity',c.nspname::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_namespace c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker:projected_temporal_profile:schema:demand' AND split_part(d.handle,':',1)='pg_namespace'
) AS capture_keys_0055
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected_temporal_profile:table:keys','identity',c.oid::regclass::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_class c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker:projected_temporal_profile:table:demand' AND split_part(d.handle,':',1)='pg_class'
) AS capture_keys_0056
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected_temporal_profile:column:keys','identity',jsonb_build_array(c.attrelid::regclass::text,c.attnum,c.attname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_attribute c ON c.attrelid=split_part(d.handle,':',2)::oid AND c.attnum=split_part(d.handle,':',3)::integer WHERE d."ruleId"='worker:projected_temporal_profile:column:demand' AND split_part(d.handle,':',1)='pg_attribute'
) AS capture_keys_0057
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected_temporal_profile:constraint:keys','identity',jsonb_build_array(c.connamespace::regnamespace::text,CASE WHEN c.conrelid<>0 THEN c.conrelid::regclass::text ELSE NULL END,CASE WHEN c.contypid<>0 THEN c.contypid::regtype::text ELSE NULL END,c.conname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_constraint c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker:projected_temporal_profile:constraint:demand' AND split_part(d.handle,':',1)='pg_constraint'
) AS capture_keys_0058
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected_temporal_profile:policy:keys','identity',jsonb_build_array(c.polrelid::regclass::text,c.polname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_policy c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker:projected_temporal_profile:policy:demand' AND split_part(d.handle,':',1)='pg_policy'
) AS capture_keys_0059
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected_temporal_profile:trigger:keys','identity',jsonb_build_array(c.tgrelid::regclass::text,c.tgname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_trigger c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker:projected_temporal_profile:trigger:demand' AND split_part(d.handle,':',1)='pg_trigger'
) AS capture_keys_0060
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected62:schema:keys','identity',c.nspname::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_namespace c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker:projected62:schema:demand' AND split_part(d.handle,':',1)='pg_namespace'
) AS capture_keys_0061
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected62:column:keys','identity',jsonb_build_array(c.attrelid::regclass::text,c.attnum,c.attname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_attribute c ON c.attrelid=split_part(d.handle,':',2)::oid AND c.attnum=split_part(d.handle,':',3)::integer WHERE d."ruleId"='worker:projected62:column:demand' AND split_part(d.handle,':',1)='pg_attribute'
) AS capture_keys_0062
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected62:constraint:keys','identity',jsonb_build_array(c.connamespace::regnamespace::text,CASE WHEN c.conrelid<>0 THEN c.conrelid::regclass::text ELSE NULL END,CASE WHEN c.contypid<>0 THEN c.contypid::regtype::text ELSE NULL END,c.conname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_constraint c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker:projected62:constraint:demand' AND split_part(d.handle,':',1)='pg_constraint'
) AS capture_keys_0063
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected62:policy:keys','identity',jsonb_build_array(c.polrelid::regclass::text,c.polname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_policy c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker:projected62:policy:demand' AND split_part(d.handle,':',1)='pg_policy'
) AS capture_keys_0064
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected62:index:keys','identity',c.oid::regclass::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_class c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker:projected62:index:demand' AND split_part(d.handle,':',1)='pg_class'
) AS capture_keys_0065
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected62:trigger:keys','identity',jsonb_build_array(c.tgrelid::regclass::text,c.tgname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_trigger c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker:projected62:trigger:demand' AND split_part(d.handle,':',1)='pg_trigger'
) AS capture_keys_0066
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected68:schema:keys','identity',c.nspname::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_namespace c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker:projected68:schema:demand' AND split_part(d.handle,':',1)='pg_namespace'
) AS capture_keys_0067
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected68:column:keys','identity',jsonb_build_array(c.attrelid::regclass::text,c.attnum,c.attname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_attribute c ON c.attrelid=split_part(d.handle,':',2)::oid AND c.attnum=split_part(d.handle,':',3)::integer WHERE d."ruleId"='worker:projected68:column:demand' AND split_part(d.handle,':',1)='pg_attribute'
) AS capture_keys_0068
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected68:constraint:keys','identity',jsonb_build_array(c.connamespace::regnamespace::text,CASE WHEN c.conrelid<>0 THEN c.conrelid::regclass::text ELSE NULL END,CASE WHEN c.contypid<>0 THEN c.contypid::regtype::text ELSE NULL END,c.conname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_constraint c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker:projected68:constraint:demand' AND split_part(d.handle,':',1)='pg_constraint'
) AS capture_keys_0069
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected68:index:keys','identity',c.oid::regclass::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_class c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker:projected68:index:demand' AND split_part(d.handle,':',1)='pg_class'
) AS capture_keys_0070
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected68:policy:keys','identity',jsonb_build_array(c.polrelid::regclass::text,c.polname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_policy c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker:projected68:policy:demand' AND split_part(d.handle,':',1)='pg_policy'
) AS capture_keys_0071
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected68:trigger:keys','identity',jsonb_build_array(c.tgrelid::regclass::text,c.tgname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_trigger c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker:projected68:trigger:demand' AND split_part(d.handle,':',1)='pg_trigger'
) AS capture_keys_0072
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected69:schema:keys','identity',c.nspname::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_namespace c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker:projected69:schema:demand' AND split_part(d.handle,':',1)='pg_namespace'
) AS capture_keys_0073
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected69:column:keys','identity',jsonb_build_array(c.attrelid::regclass::text,c.attnum,c.attname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_attribute c ON c.attrelid=split_part(d.handle,':',2)::oid AND c.attnum=split_part(d.handle,':',3)::integer WHERE d."ruleId"='worker:projected69:column:demand' AND split_part(d.handle,':',1)='pg_attribute'
) AS capture_keys_0074
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected69:constraint:keys','identity',jsonb_build_array(c.connamespace::regnamespace::text,CASE WHEN c.conrelid<>0 THEN c.conrelid::regclass::text ELSE NULL END,CASE WHEN c.contypid<>0 THEN c.contypid::regtype::text ELSE NULL END,c.conname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_constraint c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker:projected69:constraint:demand' AND split_part(d.handle,':',1)='pg_constraint'
) AS capture_keys_0075
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected69:index:keys','identity',c.oid::regclass::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_class c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker:projected69:index:demand' AND split_part(d.handle,':',1)='pg_class'
) AS capture_keys_0076
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected69:policy:keys','identity',jsonb_build_array(c.polrelid::regclass::text,c.polname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_policy c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker:projected69:policy:demand' AND split_part(d.handle,':',1)='pg_policy'
) AS capture_keys_0077
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected69:trigger:keys','identity',jsonb_build_array(c.tgrelid::regclass::text,c.tgname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_trigger c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker:projected69:trigger:demand' AND split_part(d.handle,':',1)='pg_trigger'
) AS capture_keys_0078
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected72:schema:keys','identity',c.nspname::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_namespace c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker:projected72:schema:demand' AND split_part(d.handle,':',1)='pg_namespace'
) AS capture_keys_0079
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected72:column:keys','identity',jsonb_build_array(c.attrelid::regclass::text,c.attnum,c.attname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_attribute c ON c.attrelid=split_part(d.handle,':',2)::oid AND c.attnum=split_part(d.handle,':',3)::integer WHERE d."ruleId"='worker:projected72:column:demand' AND split_part(d.handle,':',1)='pg_attribute'
) AS capture_keys_0080
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected72:constraint:keys','identity',jsonb_build_array(c.connamespace::regnamespace::text,CASE WHEN c.conrelid<>0 THEN c.conrelid::regclass::text ELSE NULL END,CASE WHEN c.contypid<>0 THEN c.contypid::regtype::text ELSE NULL END,c.conname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_constraint c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker:projected72:constraint:demand' AND split_part(d.handle,':',1)='pg_constraint'
) AS capture_keys_0081
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected72:index:keys','identity',c.oid::regclass::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_class c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker:projected72:index:demand' AND split_part(d.handle,':',1)='pg_class'
) AS capture_keys_0082
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected72:policy:keys','identity',jsonb_build_array(c.polrelid::regclass::text,c.polname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_policy c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker:projected72:policy:demand' AND split_part(d.handle,':',1)='pg_policy'
) AS capture_keys_0083
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected72:trigger:keys','identity',jsonb_build_array(c.tgrelid::regclass::text,c.tgname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_trigger c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker:projected72:trigger:demand' AND split_part(d.handle,':',1)='pg_trigger'
) AS capture_keys_0084
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected78:schema:keys','identity',c.nspname::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_namespace c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker:projected78:schema:demand' AND split_part(d.handle,':',1)='pg_namespace'
) AS capture_keys_0085
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected78:column:keys','identity',jsonb_build_array(c.attrelid::regclass::text,c.attnum,c.attname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_attribute c ON c.attrelid=split_part(d.handle,':',2)::oid AND c.attnum=split_part(d.handle,':',3)::integer WHERE d."ruleId"='worker:projected78:column:demand' AND split_part(d.handle,':',1)='pg_attribute'
) AS capture_keys_0086
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected78:constraint:keys','identity',jsonb_build_array(c.connamespace::regnamespace::text,CASE WHEN c.conrelid<>0 THEN c.conrelid::regclass::text ELSE NULL END,CASE WHEN c.contypid<>0 THEN c.contypid::regtype::text ELSE NULL END,c.conname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_constraint c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker:projected78:constraint:demand' AND split_part(d.handle,':',1)='pg_constraint'
) AS capture_keys_0087
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected78:index:keys','identity',c.oid::regclass::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_class c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker:projected78:index:demand' AND split_part(d.handle,':',1)='pg_class'
) AS capture_keys_0088
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected78:policy:keys','identity',jsonb_build_array(c.polrelid::regclass::text,c.polname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_policy c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker:projected78:policy:demand' AND split_part(d.handle,':',1)='pg_policy'
) AS capture_keys_0089
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected78:trigger:keys','identity',jsonb_build_array(c.tgrelid::regclass::text,c.tgname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_trigger c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker:projected78:trigger:demand' AND split_part(d.handle,':',1)='pg_trigger'
) AS capture_keys_0090
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected78:finding-ownership-trigger:keys','identity',jsonb_build_array(c.tgrelid::regclass::text,c.tgname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_trigger c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker:projected78:finding-ownership-trigger:demand' AND split_part(d.handle,':',1)='pg_trigger'
) AS capture_keys_0091
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected78:finding-decision-trigger:keys','identity',jsonb_build_array(c.tgrelid::regclass::text,c.tgname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_trigger c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker:projected78:finding-decision-trigger:demand' AND split_part(d.handle,':',1)='pg_trigger'
) AS capture_keys_0092
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected79:schema:keys','identity',c.nspname::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_namespace c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker:projected79:schema:demand' AND split_part(d.handle,':',1)='pg_namespace'
) AS capture_keys_0093
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected79:relation:keys','identity',c.oid::regclass::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_class c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker:projected79:relation:demand' AND split_part(d.handle,':',1)='pg_class'
) AS capture_keys_0094
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected79:column:keys','identity',jsonb_build_array(c.attrelid::regclass::text,c.attnum,c.attname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_attribute c ON c.attrelid=split_part(d.handle,':',2)::oid AND c.attnum=split_part(d.handle,':',3)::integer WHERE d."ruleId"='worker:projected79:column:demand' AND split_part(d.handle,':',1)='pg_attribute'
) AS capture_keys_0095
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected79:constraint:keys','identity',jsonb_build_array(c.connamespace::regnamespace::text,CASE WHEN c.conrelid<>0 THEN c.conrelid::regclass::text ELSE NULL END,CASE WHEN c.contypid<>0 THEN c.contypid::regtype::text ELSE NULL END,c.conname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_constraint c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker:projected79:constraint:demand' AND split_part(d.handle,':',1)='pg_constraint'
) AS capture_keys_0096
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected79:policy:keys','identity',jsonb_build_array(c.polrelid::regclass::text,c.polname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_policy c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker:projected79:policy:demand' AND split_part(d.handle,':',1)='pg_policy'
) AS capture_keys_0097
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected79:trigger:keys','identity',jsonb_build_array(c.tgrelid::regclass::text,c.tgname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_trigger c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker:projected79:trigger:demand' AND split_part(d.handle,':',1)='pg_trigger'
) AS capture_keys_0098
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:70.fingerprint:schema:keys','identity',c.nspname::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_namespace c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='temporal:70.fingerprint:schema:demand' AND split_part(d.handle,':',1)='pg_namespace'
) AS capture_keys_0099
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:70.fingerprint:table:keys','identity',c.oid::regclass::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_class c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='temporal:70.fingerprint:table:demand' AND split_part(d.handle,':',1)='pg_class'
) AS capture_keys_0100
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:70.fingerprint:column:keys','identity',jsonb_build_array(c.attrelid::regclass::text,c.attnum,c.attname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_attribute c ON c.attrelid=split_part(d.handle,':',2)::oid AND c.attnum=split_part(d.handle,':',3)::integer WHERE d."ruleId"='temporal:70.fingerprint:column:demand' AND split_part(d.handle,':',1)='pg_attribute'
) AS capture_keys_0101
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:70.fingerprint:constraint:keys','identity',jsonb_build_array(c.connamespace::regnamespace::text,CASE WHEN c.conrelid<>0 THEN c.conrelid::regclass::text ELSE NULL END,CASE WHEN c.contypid<>0 THEN c.contypid::regtype::text ELSE NULL END,c.conname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_constraint c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='temporal:70.fingerprint:constraint:demand' AND split_part(d.handle,':',1)='pg_constraint'
) AS capture_keys_0102
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:70.fingerprint:index:keys','identity',c.oid::regclass::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_class c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='temporal:70.fingerprint:index:demand' AND split_part(d.handle,':',1)='pg_class'
) AS capture_keys_0103
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:70.fingerprint:policy:keys','identity',jsonb_build_array(c.polrelid::regclass::text,c.polname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_policy c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='temporal:70.fingerprint:policy:demand' AND split_part(d.handle,':',1)='pg_policy'
) AS capture_keys_0104
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:70.fingerprint:trigger:keys','identity',jsonb_build_array(c.tgrelid::regclass::text,c.tgname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_trigger c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='temporal:70.fingerprint:trigger:demand' AND split_part(d.handle,':',1)='pg_trigger'
) AS capture_keys_0105
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:70.fingerprint:foreign-key-trigger:keys','identity',jsonb_build_array(c.tgrelid::regclass::text,c.tgname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_trigger c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='temporal:70.fingerprint:foreign-key-trigger:demand' AND split_part(d.handle,':',1)='pg_trigger'
) AS capture_keys_0106
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:71.fingerprint:schema:keys','identity',c.nspname::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_namespace c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='temporal:71.fingerprint:schema:demand' AND split_part(d.handle,':',1)='pg_namespace'
) AS capture_keys_0107
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:71.fingerprint:table:keys','identity',c.oid::regclass::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_class c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='temporal:71.fingerprint:table:demand' AND split_part(d.handle,':',1)='pg_class'
) AS capture_keys_0108
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:71.fingerprint:column:keys','identity',jsonb_build_array(c.attrelid::regclass::text,c.attnum,c.attname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_attribute c ON c.attrelid=split_part(d.handle,':',2)::oid AND c.attnum=split_part(d.handle,':',3)::integer WHERE d."ruleId"='temporal:71.fingerprint:column:demand' AND split_part(d.handle,':',1)='pg_attribute'
) AS capture_keys_0109
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:71.fingerprint:constraint:keys','identity',jsonb_build_array(c.connamespace::regnamespace::text,CASE WHEN c.conrelid<>0 THEN c.conrelid::regclass::text ELSE NULL END,CASE WHEN c.contypid<>0 THEN c.contypid::regtype::text ELSE NULL END,c.conname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_constraint c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='temporal:71.fingerprint:constraint:demand' AND split_part(d.handle,':',1)='pg_constraint'
) AS capture_keys_0110
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:71.fingerprint:index:keys','identity',c.oid::regclass::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_class c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='temporal:71.fingerprint:index:demand' AND split_part(d.handle,':',1)='pg_class'
) AS capture_keys_0111
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:71.fingerprint:policy:keys','identity',jsonb_build_array(c.polrelid::regclass::text,c.polname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_policy c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='temporal:71.fingerprint:policy:demand' AND split_part(d.handle,':',1)='pg_policy'
) AS capture_keys_0112
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:71.fingerprint:trigger:keys','identity',jsonb_build_array(c.tgrelid::regclass::text,c.tgname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_trigger c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='temporal:71.fingerprint:trigger:demand' AND split_part(d.handle,':',1)='pg_trigger'
) AS capture_keys_0113
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:71.fingerprint:foreign-key-trigger:keys','identity',jsonb_build_array(c.tgrelid::regclass::text,c.tgname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_trigger c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='temporal:71.fingerprint:foreign-key-trigger:demand' AND split_part(d.handle,':',1)='pg_trigger'
) AS capture_keys_0114
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:72.retained_execution_fingerprint:column:keys','identity',jsonb_build_array(c.attrelid::regclass::text,c.attnum,c.attname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_attribute c ON c.attrelid=split_part(d.handle,':',2)::oid AND c.attnum=split_part(d.handle,':',3)::integer WHERE d."ruleId"='temporal:72.retained_execution_fingerprint:column:demand' AND split_part(d.handle,':',1)='pg_attribute'
) AS capture_keys_0115
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:72.retained_execution_fingerprint:constraint:keys','identity',jsonb_build_array(c.connamespace::regnamespace::text,CASE WHEN c.conrelid<>0 THEN c.conrelid::regclass::text ELSE NULL END,CASE WHEN c.contypid<>0 THEN c.contypid::regtype::text ELSE NULL END,c.conname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_constraint c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='temporal:72.retained_execution_fingerprint:constraint:demand' AND split_part(d.handle,':',1)='pg_constraint'
) AS capture_keys_0116
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:72.retained_execution_fingerprint:index:keys','identity',c.oid::regclass::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_class c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='temporal:72.retained_execution_fingerprint:index:demand' AND split_part(d.handle,':',1)='pg_class'
) AS capture_keys_0117
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:72.retained_precision_fingerprint:schema:keys','identity',c.nspname::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_namespace c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='temporal:72.retained_precision_fingerprint:schema:demand' AND split_part(d.handle,':',1)='pg_namespace'
) AS capture_keys_0118
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:72.retained_precision_fingerprint:constraint:keys','identity',jsonb_build_array(c.connamespace::regnamespace::text,CASE WHEN c.conrelid<>0 THEN c.conrelid::regclass::text ELSE NULL END,CASE WHEN c.contypid<>0 THEN c.contypid::regtype::text ELSE NULL END,c.conname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_constraint c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='temporal:72.retained_precision_fingerprint:constraint:demand' AND split_part(d.handle,':',1)='pg_constraint'
) AS capture_keys_0119
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:72.retained_precision_fingerprint:trigger:keys','identity',jsonb_build_array(c.tgrelid::regclass::text,c.tgname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_trigger c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='temporal:72.retained_precision_fingerprint:trigger:demand' AND split_part(d.handle,':',1)='pg_trigger'
) AS capture_keys_0120
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:74.outbox65_fingerprint:schema:keys','identity',c.nspname::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_namespace c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='temporal:74.outbox65_fingerprint:schema:demand' AND split_part(d.handle,':',1)='pg_namespace'
) AS capture_keys_0121
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:74.outbox65_fingerprint:table:keys','identity',c.oid::regclass::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_class c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='temporal:74.outbox65_fingerprint:table:demand' AND split_part(d.handle,':',1)='pg_class'
) AS capture_keys_0122
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:74.outbox65_fingerprint:column:keys','identity',jsonb_build_array(c.attrelid::regclass::text,c.attnum,c.attname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_attribute c ON c.attrelid=split_part(d.handle,':',2)::oid AND c.attnum=split_part(d.handle,':',3)::integer WHERE d."ruleId"='temporal:74.outbox65_fingerprint:column:demand' AND split_part(d.handle,':',1)='pg_attribute'
) AS capture_keys_0123
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:74.outbox65_fingerprint:constraint:keys','identity',jsonb_build_array(c.connamespace::regnamespace::text,CASE WHEN c.conrelid<>0 THEN c.conrelid::regclass::text ELSE NULL END,CASE WHEN c.contypid<>0 THEN c.contypid::regtype::text ELSE NULL END,c.conname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_constraint c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='temporal:74.outbox65_fingerprint:constraint:demand' AND split_part(d.handle,':',1)='pg_constraint'
) AS capture_keys_0124
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:74.outbox65_fingerprint:policy:keys','identity',jsonb_build_array(c.polrelid::regclass::text,c.polname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_policy c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='temporal:74.outbox65_fingerprint:policy:demand' AND split_part(d.handle,':',1)='pg_policy'
) AS capture_keys_0125
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:74.outbox65_fingerprint:index:keys','identity',c.oid::regclass::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_class c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='temporal:74.outbox65_fingerprint:index:demand' AND split_part(d.handle,':',1)='pg_class'
) AS capture_keys_0126
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:74.outbox65_fingerprint:trigger:keys','identity',jsonb_build_array(c.tgrelid::regclass::text,c.tgname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_trigger c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='temporal:74.outbox65_fingerprint:trigger:demand' AND split_part(d.handle,':',1)='pg_trigger'
) AS capture_keys_0127
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:74.owner66_fingerprint:schema:keys','identity',c.nspname::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_namespace c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='temporal:74.owner66_fingerprint:schema:demand' AND split_part(d.handle,':',1)='pg_namespace'
) AS capture_keys_0128
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:74.owner66_fingerprint:table:keys','identity',c.oid::regclass::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_class c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='temporal:74.owner66_fingerprint:table:demand' AND split_part(d.handle,':',1)='pg_class'
) AS capture_keys_0129
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:74.owner66_fingerprint:column:keys','identity',jsonb_build_array(c.attrelid::regclass::text,c.attnum,c.attname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_attribute c ON c.attrelid=split_part(d.handle,':',2)::oid AND c.attnum=split_part(d.handle,':',3)::integer WHERE d."ruleId"='temporal:74.owner66_fingerprint:column:demand' AND split_part(d.handle,':',1)='pg_attribute'
) AS capture_keys_0130
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:74.owner66_fingerprint:constraint:keys','identity',jsonb_build_array(c.connamespace::regnamespace::text,CASE WHEN c.conrelid<>0 THEN c.conrelid::regclass::text ELSE NULL END,CASE WHEN c.contypid<>0 THEN c.contypid::regtype::text ELSE NULL END,c.conname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_constraint c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='temporal:74.owner66_fingerprint:constraint:demand' AND split_part(d.handle,':',1)='pg_constraint'
) AS capture_keys_0131
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:74.owner66_fingerprint:index:keys','identity',c.oid::regclass::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_class c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='temporal:74.owner66_fingerprint:index:demand' AND split_part(d.handle,':',1)='pg_class'
) AS capture_keys_0132
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:74.owner66_fingerprint:policy:keys','identity',jsonb_build_array(c.polrelid::regclass::text,c.polname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_policy c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='temporal:74.owner66_fingerprint:policy:demand' AND split_part(d.handle,':',1)='pg_policy'
) AS capture_keys_0133
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:74.owner66_fingerprint:trigger:keys','identity',jsonb_build_array(c.tgrelid::regclass::text,c.tgname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_trigger c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='temporal:74.owner66_fingerprint:trigger:demand' AND split_part(d.handle,':',1)='pg_trigger'
) AS capture_keys_0134
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:75.fingerprint:schema:keys','identity',c.nspname::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_namespace c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='temporal:75.fingerprint:schema:demand' AND split_part(d.handle,':',1)='pg_namespace'
) AS capture_keys_0135
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:75.fingerprint:table:keys','identity',c.oid::regclass::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_class c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='temporal:75.fingerprint:table:demand' AND split_part(d.handle,':',1)='pg_class'
) AS capture_keys_0136
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:75.fingerprint:column:keys','identity',jsonb_build_array(c.attrelid::regclass::text,c.attnum,c.attname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_attribute c ON c.attrelid=split_part(d.handle,':',2)::oid AND c.attnum=split_part(d.handle,':',3)::integer WHERE d."ruleId"='temporal:75.fingerprint:column:demand' AND split_part(d.handle,':',1)='pg_attribute'
) AS capture_keys_0137
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:75.fingerprint:constraint:keys','identity',jsonb_build_array(c.connamespace::regnamespace::text,CASE WHEN c.conrelid<>0 THEN c.conrelid::regclass::text ELSE NULL END,CASE WHEN c.contypid<>0 THEN c.contypid::regtype::text ELSE NULL END,c.conname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_constraint c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='temporal:75.fingerprint:constraint:demand' AND split_part(d.handle,':',1)='pg_constraint'
) AS capture_keys_0138
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:75.fingerprint:index:keys','identity',c.oid::regclass::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_class c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='temporal:75.fingerprint:index:demand' AND split_part(d.handle,':',1)='pg_class'
) AS capture_keys_0139
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:75.fingerprint:policy:keys','identity',jsonb_build_array(c.polrelid::regclass::text,c.polname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_policy c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='temporal:75.fingerprint:policy:demand' AND split_part(d.handle,':',1)='pg_policy'
) AS capture_keys_0140
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:75.fingerprint:trigger:keys','identity',jsonb_build_array(c.tgrelid::regclass::text,c.tgname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_trigger c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='temporal:75.fingerprint:trigger:demand' AND split_part(d.handle,':',1)='pg_trigger'
) AS capture_keys_0141
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:75.fingerprint:foreign-key-trigger:keys','identity',jsonb_build_array(c.tgrelid::regclass::text,c.tgname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_trigger c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='temporal:75.fingerprint:foreign-key-trigger:demand' AND split_part(d.handle,':',1)='pg_trigger'
) AS capture_keys_0142
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:75.fingerprint:owner-trigger:keys','identity',jsonb_build_array(c.tgrelid::regclass::text,c.tgname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_trigger c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='temporal:75.fingerprint:owner-trigger:demand' AND split_part(d.handle,':',1)='pg_trigger'
) AS capture_keys_0143
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:75.fingerprint:owner-policy:keys','identity',jsonb_build_array(c.polrelid::regclass::text,c.polname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_policy c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='temporal:75.fingerprint:owner-policy:demand' AND split_part(d.handle,':',1)='pg_policy'
) AS capture_keys_0144
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:77.domain67_fingerprint:schema:keys','identity',c.nspname::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_namespace c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='temporal:77.domain67_fingerprint:schema:demand' AND split_part(d.handle,':',1)='pg_namespace'
) AS capture_keys_0145
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:77.domain67_fingerprint:table:keys','identity',c.oid::regclass::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_class c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='temporal:77.domain67_fingerprint:table:demand' AND split_part(d.handle,':',1)='pg_class'
) AS capture_keys_0146
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:77.domain67_fingerprint:column:keys','identity',jsonb_build_array(c.attrelid::regclass::text,c.attnum,c.attname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_attribute c ON c.attrelid=split_part(d.handle,':',2)::oid AND c.attnum=split_part(d.handle,':',3)::integer WHERE d."ruleId"='temporal:77.domain67_fingerprint:column:demand' AND split_part(d.handle,':',1)='pg_attribute'
) AS capture_keys_0147
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:77.domain67_fingerprint:constraint:keys','identity',jsonb_build_array(c.connamespace::regnamespace::text,CASE WHEN c.conrelid<>0 THEN c.conrelid::regclass::text ELSE NULL END,CASE WHEN c.contypid<>0 THEN c.contypid::regtype::text ELSE NULL END,c.conname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_constraint c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='temporal:77.domain67_fingerprint:constraint:demand' AND split_part(d.handle,':',1)='pg_constraint'
) AS capture_keys_0148
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:77.domain67_fingerprint:index:keys','identity',c.oid::regclass::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_class c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='temporal:77.domain67_fingerprint:index:demand' AND split_part(d.handle,':',1)='pg_class'
) AS capture_keys_0149
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:77.domain67_fingerprint:policy:keys','identity',jsonb_build_array(c.polrelid::regclass::text,c.polname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_policy c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='temporal:77.domain67_fingerprint:policy:demand' AND split_part(d.handle,':',1)='pg_policy'
) AS capture_keys_0150
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:77.domain67_fingerprint:trigger:keys','identity',jsonb_build_array(c.tgrelid::regclass::text,c.tgname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_trigger c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='temporal:77.domain67_fingerprint:trigger:demand' AND split_part(d.handle,':',1)='pg_trigger'
) AS capture_keys_0151
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:78.predecessor73_fingerprint:schema:keys','identity',c.nspname::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_namespace c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='temporal:78.predecessor73_fingerprint:schema:demand' AND split_part(d.handle,':',1)='pg_namespace'
) AS capture_keys_0152
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:78.predecessor73_fingerprint:table:keys','identity',c.oid::regclass::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_class c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='temporal:78.predecessor73_fingerprint:table:demand' AND split_part(d.handle,':',1)='pg_class'
) AS capture_keys_0153
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:78.predecessor73_fingerprint:column:keys','identity',jsonb_build_array(c.attrelid::regclass::text,c.attnum,c.attname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_attribute c ON c.attrelid=split_part(d.handle,':',2)::oid AND c.attnum=split_part(d.handle,':',3)::integer WHERE d."ruleId"='temporal:78.predecessor73_fingerprint:column:demand' AND split_part(d.handle,':',1)='pg_attribute'
) AS capture_keys_0154
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:78.predecessor73_fingerprint:constraint:keys','identity',jsonb_build_array(c.connamespace::regnamespace::text,CASE WHEN c.conrelid<>0 THEN c.conrelid::regclass::text ELSE NULL END,CASE WHEN c.contypid<>0 THEN c.contypid::regtype::text ELSE NULL END,c.conname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_constraint c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='temporal:78.predecessor73_fingerprint:constraint:demand' AND split_part(d.handle,':',1)='pg_constraint'
) AS capture_keys_0155
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:78.predecessor73_fingerprint:index:keys','identity',c.oid::regclass::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_class c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='temporal:78.predecessor73_fingerprint:index:demand' AND split_part(d.handle,':',1)='pg_class'
) AS capture_keys_0156
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:78.predecessor73_fingerprint:policy:keys','identity',jsonb_build_array(c.polrelid::regclass::text,c.polname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_policy c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='temporal:78.predecessor73_fingerprint:policy:demand' AND split_part(d.handle,':',1)='pg_policy'
) AS capture_keys_0157
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:78.predecessor73_fingerprint:trigger:keys','identity',jsonb_build_array(c.tgrelid::regclass::text,c.tgname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_trigger c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='temporal:78.predecessor73_fingerprint:trigger:demand' AND split_part(d.handle,':',1)='pg_trigger'
) AS capture_keys_0158
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:78.predecessor73_fingerprint:foreign-key-trigger:keys','identity',jsonb_build_array(c.tgrelid::regclass::text,c.tgname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_trigger c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='temporal:78.predecessor73_fingerprint:foreign-key-trigger:demand' AND split_part(d.handle,':',1)='pg_trigger'
) AS capture_keys_0159
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:78.predecessor73_fingerprint:capacity-trigger:keys','identity',jsonb_build_array(c.tgrelid::regclass::text,c.tgname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_trigger c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='temporal:78.predecessor73_fingerprint:capacity-trigger:demand' AND split_part(d.handle,':',1)='pg_trigger'
) AS capture_keys_0160
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:78.predecessor76_fingerprint:schema:keys','identity',c.nspname::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_namespace c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='temporal:78.predecessor76_fingerprint:schema:demand' AND split_part(d.handle,':',1)='pg_namespace'
) AS capture_keys_0161
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:78.predecessor76_fingerprint:table:keys','identity',c.oid::regclass::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_class c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='temporal:78.predecessor76_fingerprint:table:demand' AND split_part(d.handle,':',1)='pg_class'
) AS capture_keys_0162
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:78.predecessor76_fingerprint:column:keys','identity',jsonb_build_array(c.attrelid::regclass::text,c.attnum,c.attname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_attribute c ON c.attrelid=split_part(d.handle,':',2)::oid AND c.attnum=split_part(d.handle,':',3)::integer WHERE d."ruleId"='temporal:78.predecessor76_fingerprint:column:demand' AND split_part(d.handle,':',1)='pg_attribute'
) AS capture_keys_0163
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:78.predecessor76_fingerprint:constraint:keys','identity',jsonb_build_array(c.connamespace::regnamespace::text,CASE WHEN c.conrelid<>0 THEN c.conrelid::regclass::text ELSE NULL END,CASE WHEN c.contypid<>0 THEN c.contypid::regtype::text ELSE NULL END,c.conname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_constraint c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='temporal:78.predecessor76_fingerprint:constraint:demand' AND split_part(d.handle,':',1)='pg_constraint'
) AS capture_keys_0164
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:78.predecessor76_fingerprint:index:keys','identity',c.oid::regclass::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_class c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='temporal:78.predecessor76_fingerprint:index:demand' AND split_part(d.handle,':',1)='pg_class'
) AS capture_keys_0165
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:78.predecessor76_fingerprint:policy:keys','identity',jsonb_build_array(c.polrelid::regclass::text,c.polname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_policy c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='temporal:78.predecessor76_fingerprint:policy:demand' AND split_part(d.handle,':',1)='pg_policy'
) AS capture_keys_0166
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:78.predecessor76_fingerprint:trigger:keys','identity',jsonb_build_array(c.tgrelid::regclass::text,c.tgname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_trigger c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='temporal:78.predecessor76_fingerprint:trigger:demand' AND split_part(d.handle,':',1)='pg_trigger'
) AS capture_keys_0167
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:78.predecessor76_fingerprint:foreign-key-trigger:keys','identity',jsonb_build_array(c.tgrelid::regclass::text,c.tgname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_trigger c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='temporal:78.predecessor76_fingerprint:foreign-key-trigger:demand' AND split_part(d.handle,':',1)='pg_trigger'
) AS capture_keys_0168
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:78.predecessor76_fingerprint:human-trigger:keys','identity',jsonb_build_array(c.tgrelid::regclass::text,c.tgname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_trigger c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='temporal:78.predecessor76_fingerprint:human-trigger:demand' AND split_part(d.handle,':',1)='pg_trigger'
) AS capture_keys_0169
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:78.predecessor76_fingerprint:owner-policy:keys','identity',jsonb_build_array(c.polrelid::regclass::text,c.polname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_policy c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='temporal:78.predecessor76_fingerprint:owner-policy:demand' AND split_part(d.handle,':',1)='pg_policy'
) AS capture_keys_0170
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:78.predecessor76_fingerprint:executor-constraint:keys','identity',jsonb_build_array(c.connamespace::regnamespace::text,CASE WHEN c.conrelid<>0 THEN c.conrelid::regclass::text ELSE NULL END,CASE WHEN c.contypid<>0 THEN c.contypid::regtype::text ELSE NULL END,c.conname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_constraint c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='temporal:78.predecessor76_fingerprint:executor-constraint:demand' AND split_part(d.handle,':',1)='pg_constraint'
) AS capture_keys_0171
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:78.predecessor77_fingerprint:schema:keys','identity',c.nspname::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_namespace c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='temporal:78.predecessor77_fingerprint:schema:demand' AND split_part(d.handle,':',1)='pg_namespace'
) AS capture_keys_0172
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:78.predecessor77_fingerprint:table:keys','identity',c.oid::regclass::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_class c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='temporal:78.predecessor77_fingerprint:table:demand' AND split_part(d.handle,':',1)='pg_class'
) AS capture_keys_0173
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:78.predecessor77_fingerprint:column:keys','identity',jsonb_build_array(c.attrelid::regclass::text,c.attnum,c.attname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_attribute c ON c.attrelid=split_part(d.handle,':',2)::oid AND c.attnum=split_part(d.handle,':',3)::integer WHERE d."ruleId"='temporal:78.predecessor77_fingerprint:column:demand' AND split_part(d.handle,':',1)='pg_attribute'
) AS capture_keys_0174
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:78.predecessor77_fingerprint:constraint:keys','identity',jsonb_build_array(c.connamespace::regnamespace::text,CASE WHEN c.conrelid<>0 THEN c.conrelid::regclass::text ELSE NULL END,CASE WHEN c.contypid<>0 THEN c.contypid::regtype::text ELSE NULL END,c.conname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_constraint c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='temporal:78.predecessor77_fingerprint:constraint:demand' AND split_part(d.handle,':',1)='pg_constraint'
) AS capture_keys_0175
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:78.predecessor77_fingerprint:index:keys','identity',c.oid::regclass::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_class c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='temporal:78.predecessor77_fingerprint:index:demand' AND split_part(d.handle,':',1)='pg_class'
) AS capture_keys_0176
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:78.predecessor77_fingerprint:policy:keys','identity',jsonb_build_array(c.polrelid::regclass::text,c.polname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_policy c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='temporal:78.predecessor77_fingerprint:policy:demand' AND split_part(d.handle,':',1)='pg_policy'
) AS capture_keys_0177
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:78.predecessor77_fingerprint:trigger:keys','identity',jsonb_build_array(c.tgrelid::regclass::text,c.tgname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_trigger c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='temporal:78.predecessor77_fingerprint:trigger:demand' AND split_part(d.handle,':',1)='pg_trigger'
) AS capture_keys_0178
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:78.predecessor77_fingerprint:foreign-key-trigger:keys','identity',jsonb_build_array(c.tgrelid::regclass::text,c.tgname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_trigger c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='temporal:78.predecessor77_fingerprint:foreign-key-trigger:demand' AND split_part(d.handle,':',1)='pg_trigger'
) AS capture_keys_0179
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:78.predecessor77_fingerprint:definition-guard:keys','identity',jsonb_build_array(c.tgrelid::regclass::text,c.tgname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_trigger c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='temporal:78.predecessor77_fingerprint:definition-guard:demand' AND split_part(d.handle,':',1)='pg_trigger'
) AS capture_keys_0180
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:78.predecessor77_fingerprint:source-capture:keys','identity',jsonb_build_array(c.tgrelid::regclass::text,c.tgname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_trigger c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='temporal:78.predecessor77_fingerprint:source-capture:demand' AND split_part(d.handle,':',1)='pg_trigger'
) AS capture_keys_0181
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:78.predecessor77_fingerprint:occurrence-guard:keys','identity',jsonb_build_array(c.tgrelid::regclass::text,c.tgname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_trigger c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='temporal:78.predecessor77_fingerprint:occurrence-guard:demand' AND split_part(d.handle,':',1)='pg_trigger'
) AS capture_keys_0182
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:attack_lab_execution:role:keys','identity',c.rolname::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_roles c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='public:attack_lab_execution:role:demand' AND split_part(d.handle,':',1)='pg_authid'
) AS capture_keys_0183
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:attack_lab_execution:table:keys','identity',c.oid::regclass::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_class c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='public:attack_lab_execution:table:demand' AND split_part(d.handle,':',1)='pg_class'
) AS capture_keys_0184
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:attack_lab_execution:index:keys','identity',c.oid::regclass::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_class c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='public:attack_lab_execution:index:demand' AND split_part(d.handle,':',1)='pg_class'
) AS capture_keys_0185
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:attack_lab_execution:column:keys','identity',jsonb_build_array(c.attrelid::regclass::text,c.attnum,c.attname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_attribute c ON c.attrelid=split_part(d.handle,':',2)::oid AND c.attnum=split_part(d.handle,':',3)::integer WHERE d."ruleId"='public:attack_lab_execution:column:demand' AND split_part(d.handle,':',1)='pg_attribute'
) AS capture_keys_0186
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:attack_lab_execution:constraint:keys','identity',jsonb_build_array(c.connamespace::regnamespace::text,CASE WHEN c.conrelid<>0 THEN c.conrelid::regclass::text ELSE NULL END,CASE WHEN c.contypid<>0 THEN c.contypid::regtype::text ELSE NULL END,c.conname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_constraint c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='public:attack_lab_execution:constraint:demand' AND split_part(d.handle,':',1)='pg_constraint'
) AS capture_keys_0187
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:attack_lab_execution:policy:keys','identity',jsonb_build_array(c.polrelid::regclass::text,c.polname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_policy c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='public:attack_lab_execution:policy:demand' AND split_part(d.handle,':',1)='pg_policy'
) AS capture_keys_0188
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:attack_lab_execution:function:keys','identity',c.oid::regprocedure::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_proc c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='public:attack_lab_execution:function:demand' AND split_part(d.handle,':',1)='pg_proc'
) AS capture_keys_0189
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:discovery_schedule_replay:schema:keys','identity',c.nspname::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_namespace c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='public:discovery_schedule_replay:schema:demand' AND split_part(d.handle,':',1)='pg_namespace'
) AS capture_keys_0190
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:discovery_schedule_replay:table:keys','identity',c.oid::regclass::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_class c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='public:discovery_schedule_replay:table:demand' AND split_part(d.handle,':',1)='pg_class'
) AS capture_keys_0191
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:discovery_schedule_replay:column:keys','identity',jsonb_build_array(c.attrelid::regclass::text,c.attnum,c.attname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_attribute c ON c.attrelid=split_part(d.handle,':',2)::oid AND c.attnum=split_part(d.handle,':',3)::integer WHERE d."ruleId"='public:discovery_schedule_replay:column:demand' AND split_part(d.handle,':',1)='pg_attribute'
) AS capture_keys_0192
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:discovery_schedule_replay:constraint:keys','identity',jsonb_build_array(c.connamespace::regnamespace::text,CASE WHEN c.conrelid<>0 THEN c.conrelid::regclass::text ELSE NULL END,CASE WHEN c.contypid<>0 THEN c.contypid::regtype::text ELSE NULL END,c.conname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_constraint c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='public:discovery_schedule_replay:constraint:demand' AND split_part(d.handle,':',1)='pg_constraint'
) AS capture_keys_0193
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:discovery_schedule_replay:index:keys','identity',c.oid::regclass::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_class c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='public:discovery_schedule_replay:index:demand' AND split_part(d.handle,':',1)='pg_class'
) AS capture_keys_0194
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:inventory:column:keys','identity',jsonb_build_array(c.attrelid::regclass::text,c.attnum,c.attname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_attribute c ON c.attrelid=split_part(d.handle,':',2)::oid AND c.attnum=split_part(d.handle,':',3)::integer WHERE d."ruleId"='public:inventory:column:demand' AND split_part(d.handle,':',1)='pg_attribute'
) AS capture_keys_0195
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:inventory:constraint:keys','identity',jsonb_build_array(c.connamespace::regnamespace::text,CASE WHEN c.conrelid<>0 THEN c.conrelid::regclass::text ELSE NULL END,CASE WHEN c.contypid<>0 THEN c.contypid::regtype::text ELSE NULL END,c.conname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_constraint c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='public:inventory:constraint:demand' AND split_part(d.handle,':',1)='pg_constraint'
) AS capture_keys_0196
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:inventory:index:keys','identity',c.oid::regclass::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_class c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='public:inventory:index:demand' AND split_part(d.handle,':',1)='pg_class'
) AS capture_keys_0197
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:inventory:trigger:keys','identity',jsonb_build_array(c.tgrelid::regclass::text,c.tgname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_trigger c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='public:inventory:trigger:demand' AND split_part(d.handle,':',1)='pg_trigger'
) AS capture_keys_0198
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:red_team_execution:role:keys','identity',c.rolname::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_roles c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='public:red_team_execution:role:demand' AND split_part(d.handle,':',1)='pg_authid'
) AS capture_keys_0199
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:red_team_execution:table:keys','identity',c.oid::regclass::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_class c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='public:red_team_execution:table:demand' AND split_part(d.handle,':',1)='pg_class'
) AS capture_keys_0200
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:red_team_execution:column:keys','identity',jsonb_build_array(c.attrelid::regclass::text,c.attnum,c.attname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_attribute c ON c.attrelid=split_part(d.handle,':',2)::oid AND c.attnum=split_part(d.handle,':',3)::integer WHERE d."ruleId"='public:red_team_execution:column:demand' AND split_part(d.handle,':',1)='pg_attribute'
) AS capture_keys_0201
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:red_team_execution:constraint:keys','identity',jsonb_build_array(c.connamespace::regnamespace::text,CASE WHEN c.conrelid<>0 THEN c.conrelid::regclass::text ELSE NULL END,CASE WHEN c.contypid<>0 THEN c.contypid::regtype::text ELSE NULL END,c.conname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_constraint c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='public:red_team_execution:constraint:demand' AND split_part(d.handle,':',1)='pg_constraint'
) AS capture_keys_0202
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:red_team_execution:policy:keys','identity',jsonb_build_array(c.polrelid::regclass::text,c.polname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_policy c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='public:red_team_execution:policy:demand' AND split_part(d.handle,':',1)='pg_policy'
) AS capture_keys_0203
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:red_team_execution:function:keys','identity',c.oid::regprocedure::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_proc c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='public:red_team_execution:function:demand' AND split_part(d.handle,':',1)='pg_proc'
) AS capture_keys_0204
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:sa_attack_lab:schema:keys','identity',c.nspname::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_namespace c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='public:sa_attack_lab:schema:demand' AND split_part(d.handle,':',1)='pg_namespace'
) AS capture_keys_0205
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:sa_attack_lab:table:keys','identity',c.oid::regclass::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_class c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='public:sa_attack_lab:table:demand' AND split_part(d.handle,':',1)='pg_class'
) AS capture_keys_0206
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:sa_attack_lab:column:keys','identity',jsonb_build_array(c.attrelid::regclass::text,c.attnum,c.attname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_attribute c ON c.attrelid=split_part(d.handle,':',2)::oid AND c.attnum=split_part(d.handle,':',3)::integer WHERE d."ruleId"='public:sa_attack_lab:column:demand' AND split_part(d.handle,':',1)='pg_attribute'
) AS capture_keys_0207
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:sa_attack_lab:constraint:keys','identity',jsonb_build_array(c.connamespace::regnamespace::text,CASE WHEN c.conrelid<>0 THEN c.conrelid::regclass::text ELSE NULL END,CASE WHEN c.contypid<>0 THEN c.contypid::regtype::text ELSE NULL END,c.conname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_constraint c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='public:sa_attack_lab:constraint:demand' AND split_part(d.handle,':',1)='pg_constraint'
) AS capture_keys_0208
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:sa_attack_lab:policy:keys','identity',jsonb_build_array(c.polrelid::regclass::text,c.polname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_policy c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='public:sa_attack_lab:policy:demand' AND split_part(d.handle,':',1)='pg_policy'
) AS capture_keys_0209
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:sa_export:schema:keys','identity',c.nspname::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_namespace c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='public:sa_export:schema:demand' AND split_part(d.handle,':',1)='pg_namespace'
) AS capture_keys_0210
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:sa_export:table:keys','identity',c.oid::regclass::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_class c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='public:sa_export:table:demand' AND split_part(d.handle,':',1)='pg_class'
) AS capture_keys_0211
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:sa_export:column:keys','identity',jsonb_build_array(c.attrelid::regclass::text,c.attnum,c.attname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_attribute c ON c.attrelid=split_part(d.handle,':',2)::oid AND c.attnum=split_part(d.handle,':',3)::integer WHERE d."ruleId"='public:sa_export:column:demand' AND split_part(d.handle,':',1)='pg_attribute'
) AS capture_keys_0212
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:sa_export:constraint:keys','identity',jsonb_build_array(c.connamespace::regnamespace::text,CASE WHEN c.conrelid<>0 THEN c.conrelid::regclass::text ELSE NULL END,CASE WHEN c.contypid<>0 THEN c.contypid::regtype::text ELSE NULL END,c.conname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_constraint c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='public:sa_export:constraint:demand' AND split_part(d.handle,':',1)='pg_constraint'
) AS capture_keys_0213
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:sa_export:policy:keys','identity',jsonb_build_array(c.polrelid::regclass::text,c.polname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_policy c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='public:sa_export:policy:demand' AND split_part(d.handle,':',1)='pg_policy'
) AS capture_keys_0214
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:sa_export:index:keys','identity',c.oid::regclass::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_class c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='public:sa_export:index:demand' AND split_part(d.handle,':',1)='pg_class'
) AS capture_keys_0215
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:sa_export:trigger:keys','identity',jsonb_build_array(c.tgrelid::regclass::text,c.tgname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_trigger c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='public:sa_export:trigger:demand' AND split_part(d.handle,':',1)='pg_trigger'
) AS capture_keys_0216
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:sa_multistep:table:keys','identity',c.oid::regclass::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_class c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='public:sa_multistep:table:demand' AND split_part(d.handle,':',1)='pg_class'
) AS capture_keys_0217
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:sa_multistep:column:keys','identity',jsonb_build_array(c.attrelid::regclass::text,c.attnum,c.attname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_attribute c ON c.attrelid=split_part(d.handle,':',2)::oid AND c.attnum=split_part(d.handle,':',3)::integer WHERE d."ruleId"='public:sa_multistep:column:demand' AND split_part(d.handle,':',1)='pg_attribute'
) AS capture_keys_0218
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:sa_multistep:constraint:keys','identity',jsonb_build_array(c.connamespace::regnamespace::text,CASE WHEN c.conrelid<>0 THEN c.conrelid::regclass::text ELSE NULL END,CASE WHEN c.contypid<>0 THEN c.contypid::regtype::text ELSE NULL END,c.conname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_constraint c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='public:sa_multistep:constraint:demand' AND split_part(d.handle,':',1)='pg_constraint'
) AS capture_keys_0219
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:sa_multistep:policy:keys','identity',jsonb_build_array(c.polrelid::regclass::text,c.polname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_policy c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='public:sa_multistep:policy:demand' AND split_part(d.handle,':',1)='pg_policy'
) AS capture_keys_0220
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:sa_multistep:index:keys','identity',c.oid::regclass::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_class c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='public:sa_multistep:index:demand' AND split_part(d.handle,':',1)='pg_class'
) AS capture_keys_0221
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:sa_multistep:trigger:keys','identity',jsonb_build_array(c.tgrelid::regclass::text,c.tgname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_trigger c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='public:sa_multistep:trigger:demand' AND split_part(d.handle,':',1)='pg_trigger'
) AS capture_keys_0222
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:sa_multistep:foreign-key-trigger:keys','identity',jsonb_build_array(c.tgrelid::regclass::text,c.tgname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_trigger c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='public:sa_multistep:foreign-key-trigger:demand' AND split_part(d.handle,':',1)='pg_trigger'
) AS capture_keys_0223
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:sa_webhook:schema:keys','identity',c.nspname::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_namespace c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='public:sa_webhook:schema:demand' AND split_part(d.handle,':',1)='pg_namespace'
) AS capture_keys_0224
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:sa_webhook:table:keys','identity',c.oid::regclass::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_class c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='public:sa_webhook:table:demand' AND split_part(d.handle,':',1)='pg_class'
) AS capture_keys_0225
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:sa_webhook:column:keys','identity',jsonb_build_array(c.attrelid::regclass::text,c.attnum,c.attname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_attribute c ON c.attrelid=split_part(d.handle,':',2)::oid AND c.attnum=split_part(d.handle,':',3)::integer WHERE d."ruleId"='public:sa_webhook:column:demand' AND split_part(d.handle,':',1)='pg_attribute'
) AS capture_keys_0226
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:sa_webhook:constraint:keys','identity',jsonb_build_array(c.connamespace::regnamespace::text,CASE WHEN c.conrelid<>0 THEN c.conrelid::regclass::text ELSE NULL END,CASE WHEN c.contypid<>0 THEN c.contypid::regtype::text ELSE NULL END,c.conname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_constraint c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='public:sa_webhook:constraint:demand' AND split_part(d.handle,':',1)='pg_constraint'
) AS capture_keys_0227
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:sa_webhook:policy:keys','identity',jsonb_build_array(c.polrelid::regclass::text,c.polname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_policy c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='public:sa_webhook:policy:demand' AND split_part(d.handle,':',1)='pg_policy'
) AS capture_keys_0228
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:sa_webhook:index:keys','identity',c.oid::regclass::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_class c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='public:sa_webhook:index:demand' AND split_part(d.handle,':',1)='pg_class'
) AS capture_keys_0229
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:sa_webhook:trigger:keys','identity',jsonb_build_array(c.tgrelid::regclass::text,c.tgname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_trigger c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='public:sa_webhook:trigger:demand' AND split_part(d.handle,':',1)='pg_trigger'
) AS capture_keys_0230
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:sa_webhook:role:keys','identity',c.rolname::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_roles c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='public:sa_webhook:role:demand' AND split_part(d.handle,':',1)='pg_authid'
) AS capture_keys_0231
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:security_agent_connector_revocation:table:keys','identity',c.oid::regclass::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_class c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='public:security_agent_connector_revocation:table:demand' AND split_part(d.handle,':',1)='pg_class'
) AS capture_keys_0232
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:security_agent_connector_revocation:column:keys','identity',jsonb_build_array(c.attrelid::regclass::text,c.attnum,c.attname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_attribute c ON c.attrelid=split_part(d.handle,':',2)::oid AND c.attnum=split_part(d.handle,':',3)::integer WHERE d."ruleId"='public:security_agent_connector_revocation:column:demand' AND split_part(d.handle,':',1)='pg_attribute'
) AS capture_keys_0233
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:security_agent_connector_revocation:table_constraint:keys','identity',jsonb_build_array(c.connamespace::regnamespace::text,CASE WHEN c.conrelid<>0 THEN c.conrelid::regclass::text ELSE NULL END,CASE WHEN c.contypid<>0 THEN c.contypid::regtype::text ELSE NULL END,c.conname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_constraint c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='public:security_agent_connector_revocation:table_constraint:demand' AND split_part(d.handle,':',1)='pg_constraint'
) AS capture_keys_0234
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:security_agent_connector_revocation:index:keys','identity',c.oid::regclass::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_class c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='public:security_agent_connector_revocation:index:demand' AND split_part(d.handle,':',1)='pg_class'
) AS capture_keys_0235
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:security_agent_connector_revocation:policy:keys','identity',jsonb_build_array(c.polrelid::regclass::text,c.polname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_policy c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='public:security_agent_connector_revocation:policy:demand' AND split_part(d.handle,':',1)='pg_policy'
) AS capture_keys_0236
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:security_agent_connector_revocation:function:keys','identity',c.oid::regprocedure::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_proc c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='public:security_agent_connector_revocation:function:demand' AND split_part(d.handle,':',1)='pg_proc'
) AS capture_keys_0237
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:security_agent_connector_revocation:constraint:keys','identity',jsonb_build_array(c.connamespace::regnamespace::text,CASE WHEN c.conrelid<>0 THEN c.conrelid::regclass::text ELSE NULL END,CASE WHEN c.contypid<>0 THEN c.contypid::regtype::text ELSE NULL END,c.conname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_constraint c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='public:security_agent_connector_revocation:constraint:demand' AND split_part(d.handle,':',1)='pg_constraint'
) AS capture_keys_0238
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','product:approval_notification:table:keys','identity',c.oid::regclass::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_class c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='product:approval_notification:table:demand' AND split_part(d.handle,':',1)='pg_class'
) AS capture_keys_0239
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','product:approval_notification:column:keys','identity',jsonb_build_array(c.attrelid::regclass::text,c.attnum,c.attname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_attribute c ON c.attrelid=split_part(d.handle,':',2)::oid AND c.attnum=split_part(d.handle,':',3)::integer WHERE d."ruleId"='product:approval_notification:column:demand' AND split_part(d.handle,':',1)='pg_attribute'
) AS capture_keys_0240
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','product:approval_notification:constraint:keys','identity',jsonb_build_array(c.connamespace::regnamespace::text,CASE WHEN c.conrelid<>0 THEN c.conrelid::regclass::text ELSE NULL END,CASE WHEN c.contypid<>0 THEN c.contypid::regtype::text ELSE NULL END,c.conname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_constraint c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='product:approval_notification:constraint:demand' AND split_part(d.handle,':',1)='pg_constraint'
) AS capture_keys_0241
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','product:approval_notification:index:keys','identity',c.oid::regclass::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_class c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='product:approval_notification:index:demand' AND split_part(d.handle,':',1)='pg_class'
) AS capture_keys_0242
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','product:approval_notification:policy:keys','identity',jsonb_build_array(c.polrelid::regclass::text,c.polname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_policy c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='product:approval_notification:policy:demand' AND split_part(d.handle,':',1)='pg_policy'
) AS capture_keys_0243
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','product:approval_notification:function:keys','identity',c.oid::regprocedure::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_proc c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='product:approval_notification:function:demand' AND split_part(d.handle,':',1)='pg_proc'
) AS capture_keys_0244
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','product:approval_notification:trigger:keys','identity',jsonb_build_array(c.tgrelid::regclass::text,c.tgname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_trigger c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='product:approval_notification:trigger:demand' AND split_part(d.handle,':',1)='pg_trigger'
) AS capture_keys_0245
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','product:home_attention:function:keys','identity',c.oid::regprocedure::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_proc c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='product:home_attention:function:demand' AND split_part(d.handle,':',1)='pg_proc'
) AS capture_keys_0246
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','product:integration_setup:function:keys','identity',c.oid::regprocedure::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_proc c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='product:integration_setup:function:demand' AND split_part(d.handle,':',1)='pg_proc'
) AS capture_keys_0247
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','product:integration_webhook:function:keys','identity',c.oid::regprocedure::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_proc c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='product:integration_webhook:function:demand' AND split_part(d.handle,':',1)='pg_proc'
) AS capture_keys_0248
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','product:integration_webhook:table:keys','identity',c.oid::regclass::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_class c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='product:integration_webhook:table:demand' AND split_part(d.handle,':',1)='pg_class'
) AS capture_keys_0249
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','product:integration_webhook:column:keys','identity',jsonb_build_array(c.attrelid::regclass::text,c.attnum,c.attname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_attribute c ON c.attrelid=split_part(d.handle,':',2)::oid AND c.attnum=split_part(d.handle,':',3)::integer WHERE d."ruleId"='product:integration_webhook:column:demand' AND split_part(d.handle,':',1)='pg_attribute'
) AS capture_keys_0250
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','product:integration_webhook:constraint:keys','identity',jsonb_build_array(c.connamespace::regnamespace::text,CASE WHEN c.conrelid<>0 THEN c.conrelid::regclass::text ELSE NULL END,CASE WHEN c.contypid<>0 THEN c.contypid::regtype::text ELSE NULL END,c.conname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_constraint c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='product:integration_webhook:constraint:demand' AND split_part(d.handle,':',1)='pg_constraint'
) AS capture_keys_0251
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','product:integration_webhook:index:keys','identity',c.oid::regclass::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_class c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='product:integration_webhook:index:demand' AND split_part(d.handle,':',1)='pg_class'
) AS capture_keys_0252
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','product:integration_webhook:policy:keys','identity',jsonb_build_array(c.polrelid::regclass::text,c.polname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_policy c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='product:integration_webhook:policy:demand' AND split_part(d.handle,':',1)='pg_policy'
) AS capture_keys_0253
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','product:reconciliation_lane_plan:function:keys','identity',c.oid::regprocedure::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_proc c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='product:reconciliation_lane_plan:function:demand' AND split_part(d.handle,':',1)='pg_proc'
) AS capture_keys_0254
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','product:red_team_artifacts:function:keys','identity',c.oid::regprocedure::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_proc c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='product:red_team_artifacts:function:demand' AND split_part(d.handle,':',1)='pg_proc'
) AS capture_keys_0255
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','product:red_team_artifacts:constraint:keys','identity',jsonb_build_array(c.connamespace::regnamespace::text,CASE WHEN c.conrelid<>0 THEN c.conrelid::regclass::text ELSE NULL END,CASE WHEN c.contypid<>0 THEN c.contypid::regtype::text ELSE NULL END,c.conname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_constraint c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='product:red_team_artifacts:constraint:demand' AND split_part(d.handle,':',1)='pg_constraint'
) AS capture_keys_0256
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','product:red_team_artifacts:column:keys','identity',jsonb_build_array(c.attrelid::regclass::text,c.attnum,c.attname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_attribute c ON c.attrelid=split_part(d.handle,':',2)::oid AND c.attnum=split_part(d.handle,':',3)::integer WHERE d."ruleId"='product:red_team_artifacts:column:demand' AND split_part(d.handle,':',1)='pg_attribute'
) AS capture_keys_0257
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','product:red_team_invocation:function:keys','identity',c.oid::regprocedure::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_proc c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='product:red_team_invocation:function:demand' AND split_part(d.handle,':',1)='pg_proc'
) AS capture_keys_0258
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','product:red_team_safety:function:keys','identity',c.oid::regprocedure::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_proc c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='product:red_team_safety:function:demand' AND split_part(d.handle,':',1)='pg_proc'
) AS capture_keys_0259
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','product:workflow_compatibility:function:keys','identity',c.oid::regprocedure::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_proc c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='product:workflow_compatibility:function:demand' AND split_part(d.handle,':',1)='pg_proc'
) AS capture_keys_0260
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','runtime:acceptance:function:keys','identity',c.oid::regprocedure::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_proc c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='runtime:acceptance:function:demand' AND split_part(d.handle,':',1)='pg_proc'
) AS capture_keys_0261
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','runtime:candidate_authority:function:keys','identity',c.oid::regprocedure::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_proc c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='runtime:candidate_authority:function:demand' AND split_part(d.handle,':',1)='pg_proc'
) AS capture_keys_0262
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','runtime:candidate_authority:table:keys','identity',c.oid::regclass::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_class c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='runtime:candidate_authority:table:demand' AND split_part(d.handle,':',1)='pg_class'
) AS capture_keys_0263
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','runtime:candidate_authority:column:keys','identity',jsonb_build_array(c.attrelid::regclass::text,c.attnum,c.attname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_attribute c ON c.attrelid=split_part(d.handle,':',2)::oid AND c.attnum=split_part(d.handle,':',3)::integer WHERE d."ruleId"='runtime:candidate_authority:column:demand' AND split_part(d.handle,':',1)='pg_attribute'
) AS capture_keys_0264
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','runtime:candidate_authority:constraint:keys','identity',jsonb_build_array(c.connamespace::regnamespace::text,CASE WHEN c.conrelid<>0 THEN c.conrelid::regclass::text ELSE NULL END,CASE WHEN c.contypid<>0 THEN c.contypid::regtype::text ELSE NULL END,c.conname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_constraint c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='runtime:candidate_authority:constraint:demand' AND split_part(d.handle,':',1)='pg_constraint'
) AS capture_keys_0265
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','runtime:candidate_authority:index:keys','identity',c.oid::regclass::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_class c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='runtime:candidate_authority:index:demand' AND split_part(d.handle,':',1)='pg_class'
) AS capture_keys_0266
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','runtime:candidate_authority:policy:keys','identity',jsonb_build_array(c.polrelid::regclass::text,c.polname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_policy c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='runtime:candidate_authority:policy:demand' AND split_part(d.handle,':',1)='pg_policy'
) AS capture_keys_0267
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','runtime:candidate_authority:trigger:keys','identity',jsonb_build_array(c.tgrelid::regclass::text,c.tgname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_trigger c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='runtime:candidate_authority:trigger:demand' AND split_part(d.handle,':',1)='pg_trigger'
) AS capture_keys_0268
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','runtime:correlation_routing:function:keys','identity',c.oid::regprocedure::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_proc c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='runtime:correlation_routing:function:demand' AND split_part(d.handle,':',1)='pg_proc'
) AS capture_keys_0269
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','runtime:correlation_routing:trigger:keys','identity',jsonb_build_array(c.tgrelid::regclass::text,c.tgname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_trigger c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='runtime:correlation_routing:trigger:demand' AND split_part(d.handle,':',1)='pg_trigger'
) AS capture_keys_0270
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','runtime:enrollment_pairing:function:keys','identity',c.oid::regprocedure::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_proc c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='runtime:enrollment_pairing:function:demand' AND split_part(d.handle,':',1)='pg_proc'
) AS capture_keys_0271
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','runtime:enrollment_pairing:table:keys','identity',c.oid::regclass::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_class c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='runtime:enrollment_pairing:table:demand' AND split_part(d.handle,':',1)='pg_class'
) AS capture_keys_0272
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','runtime:enrollment_pairing:column:keys','identity',jsonb_build_array(c.attrelid::regclass::text,c.attnum,c.attname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_attribute c ON c.attrelid=split_part(d.handle,':',2)::oid AND c.attnum=split_part(d.handle,':',3)::integer WHERE d."ruleId"='runtime:enrollment_pairing:column:demand' AND split_part(d.handle,':',1)='pg_attribute'
) AS capture_keys_0273
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','runtime:enrollment_pairing:constraint:keys','identity',jsonb_build_array(c.connamespace::regnamespace::text,CASE WHEN c.conrelid<>0 THEN c.conrelid::regclass::text ELSE NULL END,CASE WHEN c.contypid<>0 THEN c.contypid::regtype::text ELSE NULL END,c.conname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_constraint c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='runtime:enrollment_pairing:constraint:demand' AND split_part(d.handle,':',1)='pg_constraint'
) AS capture_keys_0274
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','runtime:enrollment_pairing:policy:keys','identity',jsonb_build_array(c.polrelid::regclass::text,c.polname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_policy c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='runtime:enrollment_pairing:policy:demand' AND split_part(d.handle,':',1)='pg_policy'
) AS capture_keys_0275
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','runtime:enrollment_pairing:trigger:keys','identity',jsonb_build_array(c.tgrelid::regclass::text,c.tgname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_trigger c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='runtime:enrollment_pairing:trigger:demand' AND split_part(d.handle,':',1)='pg_trigger'
) AS capture_keys_0276
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','runtime:queue_replay:function:keys','identity',c.oid::regprocedure::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_proc c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='runtime:queue_replay:function:demand' AND split_part(d.handle,':',1)='pg_proc'
) AS capture_keys_0277
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','runtime:session_evidence:function:keys','identity',c.oid::regprocedure::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_proc c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='runtime:session_evidence:function:demand' AND split_part(d.handle,':',1)='pg_proc'
) AS capture_keys_0278
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','runtime:session_query:function:keys','identity',c.oid::regprocedure::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_proc c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='runtime:session_query:function:demand' AND split_part(d.handle,':',1)='pg_proc'
) AS capture_keys_0279
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','runtime:session_reads:function:keys','identity',c.oid::regprocedure::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_proc c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='runtime:session_reads:function:demand' AND split_part(d.handle,':',1)='pg_proc'
) AS capture_keys_0280
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','runtime:session_reads:table:keys','identity',c.oid::regclass::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_class c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='runtime:session_reads:table:demand' AND split_part(d.handle,':',1)='pg_class'
) AS capture_keys_0281
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','runtime:session_reads:constraint:keys','identity',jsonb_build_array(c.connamespace::regnamespace::text,CASE WHEN c.conrelid<>0 THEN c.conrelid::regclass::text ELSE NULL END,CASE WHEN c.contypid<>0 THEN c.contypid::regtype::text ELSE NULL END,c.conname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_constraint c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='runtime:session_reads:constraint:demand' AND split_part(d.handle,':',1)='pg_constraint'
) AS capture_keys_0282
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','runtime:session_reads:column:keys','identity',jsonb_build_array(c.attrelid::regclass::text,c.attnum,c.attname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_attribute c ON c.attrelid=split_part(d.handle,':',2)::oid AND c.attnum=split_part(d.handle,':',3)::integer WHERE d."ruleId"='runtime:session_reads:column:demand' AND split_part(d.handle,':',1)='pg_attribute'
) AS capture_keys_0283
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','runtime:session_reads:policy:keys','identity',jsonb_build_array(c.polrelid::regclass::text,c.polname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_policy c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='runtime:session_reads:policy:demand' AND split_part(d.handle,':',1)='pg_policy'
) AS capture_keys_0284
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','runtime:session_reads:index:keys','identity',c.oid::regclass::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_class c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='runtime:session_reads:index:demand' AND split_part(d.handle,':',1)='pg_class'
) AS capture_keys_0285
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','runtime:session_reads:trigger:keys','identity',jsonb_build_array(c.tgrelid::regclass::text,c.tgname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_trigger c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='runtime:session_reads:trigger:demand' AND split_part(d.handle,':',1)='pg_trigger'
) AS capture_keys_0286
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','runtime:session_search:function:keys','identity',c.oid::regprocedure::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_proc c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='runtime:session_search:function:demand' AND split_part(d.handle,':',1)='pg_proc'
) AS capture_keys_0287
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','runtime:session_search:table:keys','identity',c.oid::regclass::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_class c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='runtime:session_search:table:demand' AND split_part(d.handle,':',1)='pg_class'
) AS capture_keys_0288
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','runtime:session_search:constraint:keys','identity',jsonb_build_array(c.connamespace::regnamespace::text,CASE WHEN c.conrelid<>0 THEN c.conrelid::regclass::text ELSE NULL END,CASE WHEN c.contypid<>0 THEN c.contypid::regtype::text ELSE NULL END,c.conname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_constraint c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='runtime:session_search:constraint:demand' AND split_part(d.handle,':',1)='pg_constraint'
) AS capture_keys_0289
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','runtime:session_search:column:keys','identity',jsonb_build_array(c.attrelid::regclass::text,c.attnum,c.attname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_attribute c ON c.attrelid=split_part(d.handle,':',2)::oid AND c.attnum=split_part(d.handle,':',3)::integer WHERE d."ruleId"='runtime:session_search:column:demand' AND split_part(d.handle,':',1)='pg_attribute'
) AS capture_keys_0290
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','runtime:session_search:policy:keys','identity',jsonb_build_array(c.polrelid::regclass::text,c.polname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_policy c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='runtime:session_search:policy:demand' AND split_part(d.handle,':',1)='pg_policy'
) AS capture_keys_0291
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','runtime:session_search:index:keys','identity',c.oid::regclass::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_class c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='runtime:session_search:index:demand' AND split_part(d.handle,':',1)='pg_class'
) AS capture_keys_0292
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','runtime:session_search:trigger:keys','identity',jsonb_build_array(c.tgrelid::regclass::text,c.tgname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_trigger c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='runtime:session_search:trigger:demand' AND split_part(d.handle,':',1)='pg_trigger'
) AS capture_keys_0293
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected_domain:trigger:keys','identity',jsonb_build_array(c.tgrelid::regclass::text,c.tgname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_trigger c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker:projected_domain:trigger:demand' AND split_part(d.handle,':',1)='pg_trigger'
) AS capture_keys_0294
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected_temporal_profile:function:keys','identity',c.oid::regprocedure::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_proc c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker:projected_temporal_profile:function:demand' AND split_part(d.handle,':',1)='pg_proc'
) AS capture_keys_0295
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected62:function:keys','identity',c.oid::regprocedure::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_proc c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker:projected62:function:demand' AND split_part(d.handle,':',1)='pg_proc'
) AS capture_keys_0296
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected68:function:keys','identity',c.oid::regprocedure::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_proc c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker:projected68:function:demand' AND split_part(d.handle,':',1)='pg_proc'
) AS capture_keys_0297
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected69:function:keys','identity',c.oid::regprocedure::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_proc c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker:projected69:function:demand' AND split_part(d.handle,':',1)='pg_proc'
) AS capture_keys_0298
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected72:function:keys','identity',c.oid::regprocedure::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_proc c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker:projected72:function:demand' AND split_part(d.handle,':',1)='pg_proc'
) AS capture_keys_0299
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected72:precision-handoff:keys','identity',c.oid::regprocedure::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_proc c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker:projected72:precision-handoff:demand' AND split_part(d.handle,':',1)='pg_proc'
) AS capture_keys_0300
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected72:bulk-handoff:keys','identity',c.oid::regprocedure::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_proc c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker:projected72:bulk-handoff:demand' AND split_part(d.handle,':',1)='pg_proc'
) AS capture_keys_0301
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected78:function:keys','identity',c.oid::regprocedure::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_proc c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker:projected78:function:demand' AND split_part(d.handle,':',1)='pg_proc'
) AS capture_keys_0302
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected78:effective-predecessor:keys','identity',c.oid::regprocedure::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_proc c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker:projected78:effective-predecessor:demand' AND split_part(d.handle,':',1)='pg_proc'
) AS capture_keys_0303
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected79:function:keys','identity',c.oid::regprocedure::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_proc c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker:projected79:function:demand' AND split_part(d.handle,':',1)='pg_proc'
) AS capture_keys_0304
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker:projected79:view:keys','identity',c.oid::regclass::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_class c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker:projected79:view:demand' AND split_part(d.handle,':',1)='pg_class'
) AS capture_keys_0305
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:gateway_projected24:6:keys','identity',c.oid::regprocedure::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_proc c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker-edge:gateway_projected24:6:demand' AND split_part(d.handle,':',1)='pg_proc'
) AS capture_keys_0306
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:gateway_projected27:13:keys','identity',c.oid::regprocedure::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_proc c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker-edge:gateway_projected27:13:demand' AND split_part(d.handle,':',1)='pg_proc'
) AS capture_keys_0307
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:ordered_projected28:10:keys','identity',c.oid::regprocedure::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_proc c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker-edge:ordered_projected28:10:demand' AND split_part(d.handle,':',1)='pg_proc'
) AS capture_keys_0308
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:runtime_projected40:2:keys','identity',c.oid::regprocedure::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_proc c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker-edge:runtime_projected40:2:demand' AND split_part(d.handle,':',1)='pg_proc'
) AS capture_keys_0309
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:runtime_projected50_search:1:keys','identity',c.oid::regprocedure::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_proc c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker-edge:runtime_projected50_search:1:demand' AND split_part(d.handle,':',1)='pg_proc'
) AS capture_keys_0310
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:runtime_projected50_search:2:keys','identity',c.oid::regprocedure::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_proc c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker-edge:runtime_projected50_search:2:demand' AND split_part(d.handle,':',1)='pg_proc'
) AS capture_keys_0311
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-edge:runtime_projected50_search:3:keys','identity',c.oid::regprocedure::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_proc c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker-edge:runtime_projected50_search:3:demand' AND split_part(d.handle,':',1)='pg_proc'
) AS capture_keys_0312
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:70.fingerprint:function:keys','identity',c.oid::regprocedure::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_proc c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='temporal:70.fingerprint:function:demand' AND split_part(d.handle,':',1)='pg_proc'
) AS capture_keys_0313
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:71.fingerprint:function:keys','identity',c.oid::regprocedure::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_proc c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='temporal:71.fingerprint:function:demand' AND split_part(d.handle,':',1)='pg_proc'
) AS capture_keys_0314
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:74.outbox65_fingerprint:function:keys','identity',c.oid::regprocedure::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_proc c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='temporal:74.outbox65_fingerprint:function:demand' AND split_part(d.handle,':',1)='pg_proc'
) AS capture_keys_0315
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:74.owner66_fingerprint:function:keys','identity',c.oid::regprocedure::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_proc c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='temporal:74.owner66_fingerprint:function:demand' AND split_part(d.handle,':',1)='pg_proc'
) AS capture_keys_0316
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:75.fingerprint:function:keys','identity',c.oid::regprocedure::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_proc c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='temporal:75.fingerprint:function:demand' AND split_part(d.handle,':',1)='pg_proc'
) AS capture_keys_0317
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:77.domain67_fingerprint:function:keys','identity',c.oid::regprocedure::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_proc c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='temporal:77.domain67_fingerprint:function:demand' AND split_part(d.handle,':',1)='pg_proc'
) AS capture_keys_0318
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:78.predecessor73_fingerprint:function:keys','identity',c.oid::regprocedure::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_proc c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='temporal:78.predecessor73_fingerprint:function:demand' AND split_part(d.handle,':',1)='pg_proc'
) AS capture_keys_0319
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:78.predecessor76_fingerprint:function:keys','identity',c.oid::regprocedure::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_proc c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='temporal:78.predecessor76_fingerprint:function:demand' AND split_part(d.handle,':',1)='pg_proc'
) AS capture_keys_0320
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:78.predecessor76_fingerprint:executor-function:keys','identity',c.oid::regprocedure::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_proc c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='temporal:78.predecessor76_fingerprint:executor-function:demand' AND split_part(d.handle,':',1)='pg_proc'
) AS capture_keys_0321
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:sa_attack_lab:function:keys','identity',c.oid::regprocedure::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_proc c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='public:sa_attack_lab:function:demand' AND split_part(d.handle,':',1)='pg_proc'
) AS capture_keys_0322
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:sa_export:function:keys','identity',c.oid::regprocedure::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_proc c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='public:sa_export:function:demand' AND split_part(d.handle,':',1)='pg_proc'
) AS capture_keys_0323
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:sa_multistep:function:keys','identity',c.oid::regprocedure::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_proc c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='public:sa_multistep:function:demand' AND split_part(d.handle,':',1)='pg_proc'
) AS capture_keys_0324
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:sa_webhook:function:keys','identity',c.oid::regprocedure::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_proc c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='public:sa_webhook:function:demand' AND split_part(d.handle,':',1)='pg_proc'
) AS capture_keys_0325
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:78.predecessor77_fingerprint:function:keys','identity',c.oid::regprocedure::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_proc c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='temporal:78.predecessor77_fingerprint:function:demand' AND split_part(d.handle,':',1)='pg_proc'
) AS capture_keys_0326
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:78.predecessor77_fingerprint:effective-policy-boundary:keys','identity',c.oid::regprocedure::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_proc c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='temporal:78.predecessor77_fingerprint:effective-policy-boundary:demand' AND split_part(d.handle,':',1)='pg_proc'
) AS capture_keys_0327
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:discovery_schedule_replay:function:keys','identity',c.oid::regprocedure::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_proc c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='public:discovery_schedule_replay:function:demand' AND split_part(d.handle,':',1)='pg_proc'
) AS capture_keys_0328
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','ready78:saved-current:routines:keys','identity',c.oid::regprocedure::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_proc c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='ready78:saved-current:routines:demand' AND split_part(d.handle,':',1)='pg_proc'
) AS capture_keys_0329
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-catalog:line:4:keys','identity',c.nspname::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_namespace c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker-catalog:line:4:demand' AND split_part(d.handle,':',1)='pg_namespace'
) AS capture_keys_0330
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-catalog:line:5:keys','identity',c.oid::regprocedure::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_proc c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker-catalog:line:5:demand' AND split_part(d.handle,':',1)='pg_proc'
) AS capture_keys_0331
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-catalog:line:6:keys','identity',c.oid::regclass::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_class c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker-catalog:line:6:demand' AND split_part(d.handle,':',1)='pg_class'
) AS capture_keys_0332
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-catalog:line:7:keys','identity',jsonb_build_array(c.attrelid::regclass::text,c.attnum,c.attname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_attribute c ON c.attrelid=split_part(d.handle,':',2)::oid AND c.attnum=split_part(d.handle,':',3)::integer WHERE d."ruleId"='worker-catalog:line:7:demand' AND split_part(d.handle,':',1)='pg_attribute'
) AS capture_keys_0333
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-catalog:line:8:keys','identity',jsonb_build_array(c.connamespace::regnamespace::text,CASE WHEN c.conrelid<>0 THEN c.conrelid::regclass::text ELSE NULL END,CASE WHEN c.contypid<>0 THEN c.contypid::regtype::text ELSE NULL END,c.conname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_constraint c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker-catalog:line:8:demand' AND split_part(d.handle,':',1)='pg_constraint'
) AS capture_keys_0334
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-catalog:line:9:keys','identity',jsonb_build_array(c.polrelid::regclass::text,c.polname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_policy c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker-catalog:line:9:demand' AND split_part(d.handle,':',1)='pg_policy'
) AS capture_keys_0335
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-catalog:line:10:keys','identity',jsonb_build_array(c.tgrelid::regclass::text,c.tgname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_trigger c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker-catalog:line:10:demand' AND split_part(d.handle,':',1)='pg_trigger'
) AS capture_keys_0336
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-catalog:line:15:keys','identity',c.nspname::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_namespace c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker-catalog:line:15:demand' AND split_part(d.handle,':',1)='pg_namespace'
) AS capture_keys_0337
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-catalog:line:16:keys','identity',c.oid::regprocedure::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_proc c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker-catalog:line:16:demand' AND split_part(d.handle,':',1)='pg_proc'
) AS capture_keys_0338
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-catalog:line:17:keys','identity',c.oid::regclass::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_class c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker-catalog:line:17:demand' AND split_part(d.handle,':',1)='pg_class'
) AS capture_keys_0339
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-catalog:line:18:keys','identity',jsonb_build_array(c.attrelid::regclass::text,c.attnum,c.attname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_attribute c ON c.attrelid=split_part(d.handle,':',2)::oid AND c.attnum=split_part(d.handle,':',3)::integer WHERE d."ruleId"='worker-catalog:line:18:demand' AND split_part(d.handle,':',1)='pg_attribute'
) AS capture_keys_0340
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-catalog:line:19:keys','identity',jsonb_build_array(c.connamespace::regnamespace::text,CASE WHEN c.conrelid<>0 THEN c.conrelid::regclass::text ELSE NULL END,CASE WHEN c.contypid<>0 THEN c.contypid::regtype::text ELSE NULL END,c.conname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_constraint c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker-catalog:line:19:demand' AND split_part(d.handle,':',1)='pg_constraint'
) AS capture_keys_0341
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-catalog:line:20:keys','identity',c.oid::regclass::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_class c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker-catalog:line:20:demand' AND split_part(d.handle,':',1)='pg_class'
) AS capture_keys_0342
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-catalog:line:21:keys','identity',jsonb_build_array(c.polrelid::regclass::text,c.polname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_policy c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker-catalog:line:21:demand' AND split_part(d.handle,':',1)='pg_policy'
) AS capture_keys_0343
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-catalog:line:22:keys','identity',jsonb_build_array(c.tgrelid::regclass::text,c.tgname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_trigger c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker-catalog:line:22:demand' AND split_part(d.handle,':',1)='pg_trigger'
) AS capture_keys_0344
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-catalog:line:23:keys','identity',jsonb_build_array(c.tgrelid::regclass::text,c.tgname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_trigger c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker-catalog:line:23:demand' AND split_part(d.handle,':',1)='pg_trigger'
) AS capture_keys_0345
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-catalog:line:24:keys','identity',c.oid::regclass::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_class c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker-catalog:line:24:demand' AND split_part(d.handle,':',1)='pg_class'
) AS capture_keys_0346
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-catalog:line:25:keys','identity',jsonb_build_array(c.attrelid::regclass::text,c.attnum,c.attname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_attribute c ON c.attrelid=split_part(d.handle,':',2)::oid AND c.attnum=split_part(d.handle,':',3)::integer WHERE d."ruleId"='worker-catalog:line:25:demand' AND split_part(d.handle,':',1)='pg_attribute'
) AS capture_keys_0347
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-catalog:line:26:keys','identity',jsonb_build_array(c.polrelid::regclass::text,c.polname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_policy c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker-catalog:line:26:demand' AND split_part(d.handle,':',1)='pg_policy'
) AS capture_keys_0348
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-catalog:line:32:keys','identity',jsonb_build_array(c.tgrelid::regclass::text,c.tgname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_trigger c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker-catalog:line:32:demand' AND split_part(d.handle,':',1)='pg_trigger'
) AS capture_keys_0349
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-catalog:line:33:keys','identity',jsonb_build_array(c.tgrelid::regclass::text,c.tgname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_trigger c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker-catalog:line:33:demand' AND split_part(d.handle,':',1)='pg_trigger'
) AS capture_keys_0350
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-catalog:line:34:keys','identity',c.oid::regclass::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_class c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker-catalog:line:34:demand' AND split_part(d.handle,':',1)='pg_class'
) AS capture_keys_0351
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-catalog:line:35:keys','identity',c.oid::regclass::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_class c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker-catalog:line:35:demand' AND split_part(d.handle,':',1)='pg_class'
) AS capture_keys_0352
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-catalog:line:36:keys','identity',jsonb_build_array(c.tgrelid::regclass::text,c.tgname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_trigger c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker-catalog:line:36:demand' AND split_part(d.handle,':',1)='pg_trigger'
) AS capture_keys_0353
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-catalog:line:37:keys','identity',jsonb_build_array(c.tgrelid::regclass::text,c.tgname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_trigger c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker-catalog:line:37:demand' AND split_part(d.handle,':',1)='pg_trigger'
) AS capture_keys_0354
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-catalog:line:38:keys','identity',jsonb_build_array(c.tgrelid::regclass::text,c.tgname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_trigger c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker-catalog:line:38:demand' AND split_part(d.handle,':',1)='pg_trigger'
) AS capture_keys_0355
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-catalog:line:39:keys','identity',jsonb_build_array(c.tgrelid::regclass::text,c.tgname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_trigger c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker-catalog:line:39:demand' AND split_part(d.handle,':',1)='pg_trigger'
) AS capture_keys_0356
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-catalog:line:40:keys','identity',jsonb_build_array(c.tgrelid::regclass::text,c.tgname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_trigger c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker-catalog:line:40:demand' AND split_part(d.handle,':',1)='pg_trigger'
) AS capture_keys_0357
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','worker-catalog:line:41:keys','identity',jsonb_build_array(c.tgrelid::regclass::text,c.tgname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_trigger c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='worker-catalog:line:41:demand' AND split_part(d.handle,':',1)='pg_trigger'
) AS capture_keys_0358
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','authorization80:schema:keys','identity',c.nspname::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_namespace c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='authorization80:schema:demand' AND split_part(d.handle,':',1)='pg_namespace'
) AS capture_keys_0359
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','authorization80:runtime-profile-trigger:keys','identity',jsonb_build_array(c.tgrelid::regclass::text,c.tgname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_trigger c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='authorization80:runtime-profile-trigger:demand' AND split_part(d.handle,':',1)='pg_trigger'
) AS capture_keys_0360
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','authorization80:runtime-profile-column:keys','identity',jsonb_build_array(c.attrelid::regclass::text,c.attnum,c.attname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_attribute c ON c.attrelid=split_part(d.handle,':',2)::oid AND c.attnum=split_part(d.handle,':',3)::integer WHERE d."ruleId"='authorization80:runtime-profile-column:demand' AND split_part(d.handle,':',1)='pg_attribute'
) AS capture_keys_0361
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','authorization80:runtime-profile-column:types:keys','identity',c.oid::regtype::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_type c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='authorization80:runtime-profile-column:types:demand' AND split_part(d.handle,':',1)='pg_type'
) AS capture_keys_0362
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','authorization80:function:keys','identity',c.oid::regprocedure::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_proc c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='authorization80:function:demand' AND split_part(d.handle,':',1)='pg_proc'
) AS capture_keys_0363
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','authorization80:home-source-function:keys','identity',c.oid::regprocedure::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_proc c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='authorization80:home-source-function:demand' AND split_part(d.handle,':',1)='pg_proc'
) AS capture_keys_0364
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','authorization80:relation:keys','identity',c.oid::regclass::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_class c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='authorization80:relation:demand' AND split_part(d.handle,':',1)='pg_class'
) AS capture_keys_0365
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','authorization80:constraint:keys','identity',jsonb_build_array(c.connamespace::regnamespace::text,CASE WHEN c.conrelid<>0 THEN c.conrelid::regclass::text ELSE NULL END,CASE WHEN c.contypid<>0 THEN c.contypid::regtype::text ELSE NULL END,c.conname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_constraint c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='authorization80:constraint:demand' AND split_part(d.handle,':',1)='pg_constraint'
) AS capture_keys_0366
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','authorization80:policy:keys','identity',jsonb_build_array(c.polrelid::regclass::text,c.polname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_policy c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='authorization80:policy:demand' AND split_part(d.handle,':',1)='pg_policy'
) AS capture_keys_0367
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','authorization80:risk-relation:keys','identity',c.oid::regclass::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_class c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='authorization80:risk-relation:demand' AND split_part(d.handle,':',1)='pg_class'
) AS capture_keys_0368
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','authorization80:risk-policy:keys','identity',jsonb_build_array(c.polrelid::regclass::text,c.polname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_policy c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='authorization80:risk-policy:demand' AND split_part(d.handle,':',1)='pg_policy'
) AS capture_keys_0369
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','authorization80:data-controls-relation:keys','identity',c.oid::regclass::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_class c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='authorization80:data-controls-relation:demand' AND split_part(d.handle,':',1)='pg_class'
) AS capture_keys_0370
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','authorization80:data-controls-policy:keys','identity',jsonb_build_array(c.polrelid::regclass::text,c.polname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_policy c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='authorization80:data-controls-policy:demand' AND split_part(d.handle,':',1)='pg_policy'
) AS capture_keys_0371
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','authorization80:data-controls-column:keys','identity',jsonb_build_array(c.attrelid::regclass::text,c.attnum,c.attname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_attribute c ON c.attrelid=split_part(d.handle,':',2)::oid AND c.attnum=split_part(d.handle,':',3)::integer WHERE d."ruleId"='authorization80:data-controls-column:demand' AND split_part(d.handle,':',1)='pg_attribute'
) AS capture_keys_0372
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','authorization80:data-controls-column:types:keys','identity',c.oid::regtype::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_type c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='authorization80:data-controls-column:types:demand' AND split_part(d.handle,':',1)='pg_type'
) AS capture_keys_0373
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','authorization80:data-controls-constraint:keys','identity',jsonb_build_array(c.connamespace::regnamespace::text,CASE WHEN c.conrelid<>0 THEN c.conrelid::regclass::text ELSE NULL END,CASE WHEN c.contypid<>0 THEN c.contypid::regtype::text ELSE NULL END,c.conname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_constraint c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='authorization80:data-controls-constraint:demand' AND split_part(d.handle,':',1)='pg_constraint'
) AS capture_keys_0374
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','authorization80:hierarchy-relation:keys','identity',c.oid::regclass::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_class c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='authorization80:hierarchy-relation:demand' AND split_part(d.handle,':',1)='pg_class'
) AS capture_keys_0375
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','authorization80:hierarchy-trigger:keys','identity',jsonb_build_array(c.tgrelid::regclass::text,c.tgname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_trigger c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='authorization80:hierarchy-trigger:demand' AND split_part(d.handle,':',1)='pg_trigger'
) AS capture_keys_0376
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','authorization80:hierarchy-column:keys','identity',jsonb_build_array(c.attrelid::regclass::text,c.attnum,c.attname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_attribute c ON c.attrelid=split_part(d.handle,':',2)::oid AND c.attnum=split_part(d.handle,':',3)::integer WHERE d."ruleId"='authorization80:hierarchy-column:demand' AND split_part(d.handle,':',1)='pg_attribute'
) AS capture_keys_0377
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','authorization80:hierarchy-column:types:keys','identity',c.oid::regtype::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_type c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='authorization80:hierarchy-column:types:demand' AND split_part(d.handle,':',1)='pg_type'
) AS capture_keys_0378
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','authorization80:hierarchy-constraint:keys','identity',jsonb_build_array(c.connamespace::regnamespace::text,CASE WHEN c.conrelid<>0 THEN c.conrelid::regclass::text ELSE NULL END,CASE WHEN c.contypid<>0 THEN c.contypid::regtype::text ELSE NULL END,c.conname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_constraint c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='authorization80:hierarchy-constraint:demand' AND split_part(d.handle,':',1)='pg_constraint'
) AS capture_keys_0379
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','authorization80:hierarchy-policy:keys','identity',jsonb_build_array(c.polrelid::regclass::text,c.polname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_policy c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='authorization80:hierarchy-policy:demand' AND split_part(d.handle,':',1)='pg_policy'
) AS capture_keys_0380
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','authorization-temporal:triggers-ready:triggers:keys','identity',jsonb_build_array(c.tgrelid::regclass::text,c.tgname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_trigger c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='authorization-temporal:triggers-ready:triggers:demand' AND split_part(d.handle,':',1)='pg_trigger'
) AS capture_keys_0381
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','authorization-temporal:triggers-ready:routine:keys','identity',c.oid::regprocedure::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_proc c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='authorization-temporal:triggers-ready:routine:demand' AND split_part(d.handle,':',1)='pg_proc'
) AS capture_keys_0382
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:72.retained_execution_fingerprint:table:keys','identity',c.oid::regclass::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_class c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='temporal:72.retained_execution_fingerprint:table:demand' AND split_part(d.handle,':',1)='pg_class'
) AS capture_keys_0383
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:72.retained_execution_fingerprint:function:keys','identity',c.oid::regprocedure::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_proc c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='temporal:72.retained_execution_fingerprint:function:demand' AND split_part(d.handle,':',1)='pg_proc'
) AS capture_keys_0384
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:72.retained_execution_fingerprint:policy:keys','identity',jsonb_build_array(c.polrelid::regclass::text,c.polname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_policy c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='temporal:72.retained_execution_fingerprint:policy:demand' AND split_part(d.handle,':',1)='pg_policy'
) AS capture_keys_0385
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:72.retained_execution_fingerprint:trigger:keys','identity',jsonb_build_array(c.tgrelid::regclass::text,c.tgname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_trigger c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='temporal:72.retained_execution_fingerprint:trigger:demand' AND split_part(d.handle,':',1)='pg_trigger'
) AS capture_keys_0386
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:72.retained_execution_fingerprint:role:keys','identity',c.rolname::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_roles c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='temporal:72.retained_execution_fingerprint:role:demand' AND split_part(d.handle,':',1)='pg_authid'
) AS capture_keys_0387
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:inventory:table:keys','identity',c.oid::regclass::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_class c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='public:inventory:table:demand' AND split_part(d.handle,':',1)='pg_class'
) AS capture_keys_0388
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:inventory:policy:keys','identity',jsonb_build_array(c.polrelid::regclass::text,c.polname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_policy c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='public:inventory:policy:demand' AND split_part(d.handle,':',1)='pg_policy'
) AS capture_keys_0389
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:inventory:function:keys','identity',c.oid::regprocedure::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_proc c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='public:inventory:function:demand' AND split_part(d.handle,':',1)='pg_proc'
) AS capture_keys_0390
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:inventory:function:core-owner:keys','identity',c.oid::regclass::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_class c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='public:inventory:function:core-owner:demand' AND split_part(d.handle,':',1)='pg_class'
) AS capture_keys_0391
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:inventory:role:keys','identity',c.rolname::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_roles c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='public:inventory:role:demand' AND split_part(d.handle,':',1)='pg_authid'
) AS capture_keys_0392
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','special:global-control:role:keys','identity',c.rolname::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_roles c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='special:global-control:role:demand' AND split_part(d.handle,':',1)='pg_authid'
) AS capture_keys_0393
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','special:global-control:owned-function:keys','identity',c.oid::regprocedure::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_proc c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='special:global-control:owned-function:demand' AND split_part(d.handle,':',1)='pg_proc'
) AS capture_keys_0394
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','special:global-control:owned-relation:keys','identity',c.oid::regclass::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_class c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='special:global-control:owned-relation:demand' AND split_part(d.handle,':',1)='pg_class'
) AS capture_keys_0395
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','special:global-control:owned-schema:keys','identity',c.nspname::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_namespace c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='special:global-control:owned-schema:demand' AND split_part(d.handle,':',1)='pg_namespace'
) AS capture_keys_0396
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','special:global-control:owned-database:keys','identity',c.datname::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_database c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='special:global-control:owned-database:demand' AND split_part(d.handle,':',1)='pg_database'
) AS capture_keys_0397
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','special:global-control:default-acl:keys','identity',jsonb_build_array(c.defaclrole::regrole::text,CASE WHEN c.defaclnamespace=0 THEN NULL ELSE c.defaclnamespace::regnamespace::text END,c.defaclobjtype)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_default_acl c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='special:global-control:default-acl:demand' AND split_part(d.handle,':',1)='pg_default_acl'
) AS capture_keys_0398
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','special:global-control:table:keys','identity',c.oid::regclass::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_class c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='special:global-control:table:demand' AND split_part(d.handle,':',1)='pg_class'
) AS capture_keys_0399
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','special:global-control:column:keys','identity',jsonb_build_array(c.attrelid::regclass::text,c.attnum,c.attname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_attribute c ON c.attrelid=split_part(d.handle,':',2)::oid AND c.attnum=split_part(d.handle,':',3)::integer WHERE d."ruleId"='special:global-control:column:demand' AND split_part(d.handle,':',1)='pg_attribute'
) AS capture_keys_0400
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','special:global-control:constraint:keys','identity',jsonb_build_array(c.connamespace::regnamespace::text,CASE WHEN c.conrelid<>0 THEN c.conrelid::regclass::text ELSE NULL END,CASE WHEN c.contypid<>0 THEN c.contypid::regtype::text ELSE NULL END,c.conname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_constraint c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='special:global-control:constraint:demand' AND split_part(d.handle,':',1)='pg_constraint'
) AS capture_keys_0401
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','special:global-control:index:keys','identity',c.oid::regclass::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_class c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='special:global-control:index:demand' AND split_part(d.handle,':',1)='pg_class'
) AS capture_keys_0402
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','special:global-control:policy:keys','identity',jsonb_build_array(c.polrelid::regclass::text,c.polname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_policy c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='special:global-control:policy:demand' AND split_part(d.handle,':',1)='pg_policy'
) AS capture_keys_0403
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','special:global-control:trigger:keys','identity',jsonb_build_array(c.tgrelid::regclass::text,c.tgname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_trigger c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='special:global-control:trigger:demand' AND split_part(d.handle,':',1)='pg_trigger'
) AS capture_keys_0404
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','special:compliance-jobs:relation:keys','identity',c.oid::regclass::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_class c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='special:compliance-jobs:relation:demand' AND split_part(d.handle,':',1)='pg_class'
) AS capture_keys_0405
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','special:compliance-jobs:column:keys','identity',jsonb_build_array(c.attrelid::regclass::text,c.attnum,c.attname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_attribute c ON c.attrelid=split_part(d.handle,':',2)::oid AND c.attnum=split_part(d.handle,':',3)::integer WHERE d."ruleId"='special:compliance-jobs:column:demand' AND split_part(d.handle,':',1)='pg_attribute'
) AS capture_keys_0406
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','special:compliance-jobs:constraint:keys','identity',jsonb_build_array(c.connamespace::regnamespace::text,CASE WHEN c.conrelid<>0 THEN c.conrelid::regclass::text ELSE NULL END,CASE WHEN c.contypid<>0 THEN c.contypid::regtype::text ELSE NULL END,c.conname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_constraint c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='special:compliance-jobs:constraint:demand' AND split_part(d.handle,':',1)='pg_constraint'
) AS capture_keys_0407
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','special:compliance-jobs:index:keys','identity',c.oid::regclass::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_class c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='special:compliance-jobs:index:demand' AND split_part(d.handle,':',1)='pg_class'
) AS capture_keys_0408
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','special:compliance-jobs:policy:keys','identity',jsonb_build_array(c.polrelid::regclass::text,c.polname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_policy c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='special:compliance-jobs:policy:demand' AND split_part(d.handle,':',1)='pg_policy'
) AS capture_keys_0409
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','special:compliance-jobs:trigger:keys','identity',jsonb_build_array(c.tgrelid::regclass::text,c.tgname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_trigger c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='special:compliance-jobs:trigger:demand' AND split_part(d.handle,':',1)='pg_trigger'
) AS capture_keys_0410
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','special:compliance-jobs:role:keys','identity',c.rolname::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_roles c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='special:compliance-jobs:role:demand' AND split_part(d.handle,':',1)='pg_authid'
) AS capture_keys_0411
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','wrapper:scope-authority:relation:keys','identity',c.oid::regclass::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_class c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='wrapper:scope-authority:relation:demand' AND split_part(d.handle,':',1)='pg_class'
) AS capture_keys_0412
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','wrapper:scope-authority:routines:keys','identity',c.oid::regprocedure::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_proc c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='wrapper:scope-authority:routines:demand' AND split_part(d.handle,':',1)='pg_proc'
) AS capture_keys_0413
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','wrapper:migration-helper:relations:keys','identity',c.oid::regclass::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_class c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='wrapper:migration-helper:relations:demand' AND split_part(d.handle,':',1)='pg_class'
) AS capture_keys_0414
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','wrapper:migration-helper:routines:keys','identity',c.oid::regprocedure::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_proc c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='wrapper:migration-helper:routines:demand' AND split_part(d.handle,':',1)='pg_proc'
) AS capture_keys_0415
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','wrapper:audit-source:relation:keys','identity',c.oid::regclass::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_class c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='wrapper:audit-source:relation:demand' AND split_part(d.handle,':',1)='pg_class'
) AS capture_keys_0416
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','wrapper:audit-source:columns:keys','identity',jsonb_build_array(c.attrelid::regclass::text,c.attnum,c.attname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_attribute c ON c.attrelid=split_part(d.handle,':',2)::oid AND c.attnum=split_part(d.handle,':',3)::integer WHERE d."ruleId"='wrapper:audit-source:columns:demand' AND split_part(d.handle,':',1)='pg_attribute'
) AS capture_keys_0417
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','wrapper:audit-source:ready-relation:keys','identity',c.oid::regclass::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_class c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='wrapper:audit-source:ready-relation:demand' AND split_part(d.handle,':',1)='pg_class'
) AS capture_keys_0418
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','wrapper:audit-workflow:relation:keys','identity',c.oid::regclass::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_class c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='wrapper:audit-workflow:relation:demand' AND split_part(d.handle,':',1)='pg_class'
) AS capture_keys_0419
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','wrapper:audit-workflow:columns:keys','identity',jsonb_build_array(c.attrelid::regclass::text,c.attnum,c.attname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_attribute c ON c.attrelid=split_part(d.handle,':',2)::oid AND c.attnum=split_part(d.handle,':',3)::integer WHERE d."ruleId"='wrapper:audit-workflow:columns:demand' AND split_part(d.handle,':',1)='pg_attribute'
) AS capture_keys_0420
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','recursive:predecessor68:routine:keys','identity',c.oid::regprocedure::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_proc c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='recursive:predecessor68:routine:demand' AND split_part(d.handle,':',1)='pg_proc'
) AS capture_keys_0421
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','recursive:ready68:routine:keys','identity',c.oid::regprocedure::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_proc c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='recursive:ready68:routine:demand' AND split_part(d.handle,':',1)='pg_proc'
) AS capture_keys_0422
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','recursive:ready78:routine:keys','identity',c.oid::regprocedure::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_proc c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='recursive:ready78:routine:demand' AND split_part(d.handle,':',1)='pg_proc'
) AS capture_keys_0423
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','recursive:base67:routine:keys','identity',c.oid::regprocedure::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_proc c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='recursive:base67:routine:demand' AND split_part(d.handle,':',1)='pg_proc'
) AS capture_keys_0424
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','recursive:native-role-shape:roles:keys','identity',c.rolname::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_roles c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='recursive:native-role-shape:roles:demand' AND split_part(d.handle,':',1)='pg_authid'
) AS capture_keys_0425
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','recursive:worker-catalog-ready:routine:keys','identity',c.oid::regprocedure::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_proc c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='recursive:worker-catalog-ready:routine:demand' AND split_part(d.handle,':',1)='pg_proc'
) AS capture_keys_0426
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','recursive:worker-catalog-ready:definition:keys','identity',c.oid::regprocedure::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_proc c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='recursive:worker-catalog-ready:definition:demand' AND split_part(d.handle,':',1)='pg_proc'
) AS capture_keys_0427
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','prior:compliance:schema:keys','identity',c.nspname::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_namespace c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='prior:compliance:schema:demand' AND split_part(d.handle,':',1)='pg_namespace'
) AS capture_keys_0428
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','prior:compliance:function:keys','identity',c.oid::regprocedure::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_proc c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='prior:compliance:function:demand' AND split_part(d.handle,':',1)='pg_proc'
) AS capture_keys_0429
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','prior:existing:schema:keys','identity',c.nspname::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_namespace c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='prior:existing:schema:demand' AND split_part(d.handle,':',1)='pg_namespace'
) AS capture_keys_0430
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','prior:existing:function:keys','identity',c.oid::regprocedure::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_proc c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='prior:existing:function:demand' AND split_part(d.handle,':',1)='pg_proc'
) AS capture_keys_0431
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','prior:run-context:schema:keys','identity',c.nspname::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_namespace c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='prior:run-context:schema:demand' AND split_part(d.handle,':',1)='pg_namespace'
) AS capture_keys_0432
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','prior:run-context:function:keys','identity',c.oid::regprocedure::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_proc c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='prior:run-context:function:demand' AND split_part(d.handle,':',1)='pg_proc'
) AS capture_keys_0433
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','prior:budget:schema:keys','identity',c.nspname::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_namespace c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='prior:budget:schema:demand' AND split_part(d.handle,':',1)='pg_namespace'
) AS capture_keys_0434
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','prior:budget:function:keys','identity',c.oid::regprocedure::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_proc c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='prior:budget:function:demand' AND split_part(d.handle,':',1)='pg_proc'
) AS capture_keys_0435
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','prior:audit:schema:keys','identity',c.nspname::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_namespace c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='prior:audit:schema:demand' AND split_part(d.handle,':',1)='pg_namespace'
) AS capture_keys_0436
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','prior:audit:function:keys','identity',c.oid::regprocedure::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_proc c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='prior:audit:function:demand' AND split_part(d.handle,':',1)='pg_proc'
) AS capture_keys_0437
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','prior:existing:table:keys','identity',c.oid::regclass::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_class c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='prior:existing:table:demand' AND split_part(d.handle,':',1)='pg_class'
) AS capture_keys_0438
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','prior:existing:column:keys','identity',jsonb_build_array(c.attrelid::regclass::text,c.attnum,c.attname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_attribute c ON c.attrelid=split_part(d.handle,':',2)::oid AND c.attnum=split_part(d.handle,':',3)::integer WHERE d."ruleId"='prior:existing:column:demand' AND split_part(d.handle,':',1)='pg_attribute'
) AS capture_keys_0439
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','prior:existing:constraint:keys','identity',jsonb_build_array(c.connamespace::regnamespace::text,CASE WHEN c.conrelid<>0 THEN c.conrelid::regclass::text ELSE NULL END,CASE WHEN c.contypid<>0 THEN c.contypid::regtype::text ELSE NULL END,c.conname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_constraint c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='prior:existing:constraint:demand' AND split_part(d.handle,':',1)='pg_constraint'
) AS capture_keys_0440
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','prior:existing:index:keys','identity',c.oid::regclass::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_class c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='prior:existing:index:demand' AND split_part(d.handle,':',1)='pg_class'
) AS capture_keys_0441
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','prior:existing:policy:keys','identity',jsonb_build_array(c.polrelid::regclass::text,c.polname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_policy c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='prior:existing:policy:demand' AND split_part(d.handle,':',1)='pg_policy'
) AS capture_keys_0442
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','prior:existing:trigger:keys','identity',jsonb_build_array(c.tgrelid::regclass::text,c.tgname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_trigger c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='prior:existing:trigger:demand' AND split_part(d.handle,':',1)='pg_trigger'
) AS capture_keys_0443
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','prior:budget:table:keys','identity',c.oid::regclass::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_class c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='prior:budget:table:demand' AND split_part(d.handle,':',1)='pg_class'
) AS capture_keys_0444
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','prior:budget:column:keys','identity',jsonb_build_array(c.attrelid::regclass::text,c.attnum,c.attname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_attribute c ON c.attrelid=split_part(d.handle,':',2)::oid AND c.attnum=split_part(d.handle,':',3)::integer WHERE d."ruleId"='prior:budget:column:demand' AND split_part(d.handle,':',1)='pg_attribute'
) AS capture_keys_0445
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','prior:budget:constraint:keys','identity',jsonb_build_array(c.connamespace::regnamespace::text,CASE WHEN c.conrelid<>0 THEN c.conrelid::regclass::text ELSE NULL END,CASE WHEN c.contypid<>0 THEN c.contypid::regtype::text ELSE NULL END,c.conname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_constraint c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='prior:budget:constraint:demand' AND split_part(d.handle,':',1)='pg_constraint'
) AS capture_keys_0446
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','prior:budget:index:keys','identity',c.oid::regclass::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_class c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='prior:budget:index:demand' AND split_part(d.handle,':',1)='pg_class'
) AS capture_keys_0447
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','prior:budget:policy:keys','identity',jsonb_build_array(c.polrelid::regclass::text,c.polname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_policy c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='prior:budget:policy:demand' AND split_part(d.handle,':',1)='pg_policy'
) AS capture_keys_0448
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','prior:budget:trigger:keys','identity',jsonb_build_array(c.tgrelid::regclass::text,c.tgname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_trigger c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='prior:budget:trigger:demand' AND split_part(d.handle,':',1)='pg_trigger'
) AS capture_keys_0449
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','prior:audit:table:keys','identity',c.oid::regclass::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_class c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='prior:audit:table:demand' AND split_part(d.handle,':',1)='pg_class'
) AS capture_keys_0450
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','prior:audit:column:keys','identity',jsonb_build_array(c.attrelid::regclass::text,c.attnum,c.attname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_attribute c ON c.attrelid=split_part(d.handle,':',2)::oid AND c.attnum=split_part(d.handle,':',3)::integer WHERE d."ruleId"='prior:audit:column:demand' AND split_part(d.handle,':',1)='pg_attribute'
) AS capture_keys_0451
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','prior:audit:constraint:keys','identity',jsonb_build_array(c.connamespace::regnamespace::text,CASE WHEN c.conrelid<>0 THEN c.conrelid::regclass::text ELSE NULL END,CASE WHEN c.contypid<>0 THEN c.contypid::regtype::text ELSE NULL END,c.conname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_constraint c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='prior:audit:constraint:demand' AND split_part(d.handle,':',1)='pg_constraint'
) AS capture_keys_0452
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','prior:audit:index:keys','identity',c.oid::regclass::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_class c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='prior:audit:index:demand' AND split_part(d.handle,':',1)='pg_class'
) AS capture_keys_0453
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','prior:audit:policy:keys','identity',jsonb_build_array(c.polrelid::regclass::text,c.polname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_policy c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='prior:audit:policy:demand' AND split_part(d.handle,':',1)='pg_policy'
) AS capture_keys_0454
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','prior:audit:trigger:keys','identity',jsonb_build_array(c.tgrelid::regclass::text,c.tgname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_trigger c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='prior:audit:trigger:demand' AND split_part(d.handle,':',1)='pg_trigger'
) AS capture_keys_0455
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','prior:run-context:activity-index:keys','identity',c.oid::regclass::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_class c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='prior:run-context:activity-index:demand' AND split_part(d.handle,':',1)='pg_class'
) AS capture_keys_0456
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','prior:audit:export-role:keys','identity',c.rolname::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_roles c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='prior:audit:export-role:demand' AND split_part(d.handle,':',1)='pg_authid'
) AS capture_keys_0457
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','prior:audit:view:keys','identity',c.oid::regclass::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_class c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='prior:audit:view:demand' AND split_part(d.handle,':',1)='pg_class'
) AS capture_keys_0458
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','prior:compliance:normalization-relation:keys','identity',c.oid::regclass::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_class c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='prior:compliance:normalization-relation:demand' AND split_part(d.handle,':',1)='pg_class'
) AS capture_keys_0459
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','prior:run-context:normalization-relation:keys','identity',c.oid::regclass::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_class c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='prior:run-context:normalization-relation:demand' AND split_part(d.handle,':',1)='pg_class'
) AS capture_keys_0460
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','prior:audit:source-shape:keys','identity',c.oid::regclass::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_class c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='prior:audit:source-shape:demand' AND split_part(d.handle,':',1)='pg_class'
) AS capture_keys_0461
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','prior:audit:red-team-relation:keys','identity',c.oid::regclass::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_class c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='prior:audit:red-team-relation:demand' AND split_part(d.handle,':',1)='pg_class'
) AS capture_keys_0462
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','prior:audit:source-columns-shape:keys','identity',jsonb_build_array(c.attrelid::regclass::text,c.attnum,c.attname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_attribute c ON c.attrelid=split_part(d.handle,':',2)::oid AND c.attnum=split_part(d.handle,':',3)::integer WHERE d."ruleId"='prior:audit:source-columns-shape:demand' AND split_part(d.handle,':',1)='pg_attribute'
) AS capture_keys_0463
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','prior:audit:red-team-columns:keys','identity',jsonb_build_array(c.attrelid::regclass::text,c.attnum,c.attname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_attribute c ON c.attrelid=split_part(d.handle,':',2)::oid AND c.attnum=split_part(d.handle,':',3)::integer WHERE d."ruleId"='prior:audit:red-team-columns:demand' AND split_part(d.handle,':',1)='pg_attribute'
) AS capture_keys_0464
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','materialized:sa-multistep-prior:legacy-approval-fence:keys','identity',c.oid::regprocedure::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_proc c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='materialized:sa-multistep-prior:legacy-approval-fence:demand' AND split_part(d.handle,':',1)='pg_proc'
) AS capture_keys_0465
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','materialized:sa-multistep-prior:legacy-action-fence:keys','identity',c.oid::regprocedure::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_proc c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='materialized:sa-multistep-prior:legacy-action-fence:demand' AND split_part(d.handle,':',1)='pg_proc'
) AS capture_keys_0466
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','materialized:sa-multistep-prior:schema:keys','identity',c.nspname::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_namespace c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='materialized:sa-multistep-prior:schema:demand' AND split_part(d.handle,':',1)='pg_namespace'
) AS capture_keys_0467
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','materialized:sa-multistep-prior:function:keys','identity',c.oid::regprocedure::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_proc c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='materialized:sa-multistep-prior:function:demand' AND split_part(d.handle,':',1)='pg_proc'
) AS capture_keys_0468
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','materialized:sa-multistep-prior:table:keys','identity',c.oid::regclass::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_class c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='materialized:sa-multistep-prior:table:demand' AND split_part(d.handle,':',1)='pg_class'
) AS capture_keys_0469
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','materialized:sa-multistep-prior:column:keys','identity',jsonb_build_array(c.attrelid::regclass::text,c.attnum,c.attname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_attribute c ON c.attrelid=split_part(d.handle,':',2)::oid AND c.attnum=split_part(d.handle,':',3)::integer WHERE d."ruleId"='materialized:sa-multistep-prior:column:demand' AND split_part(d.handle,':',1)='pg_attribute'
) AS capture_keys_0470
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','materialized:sa-multistep-prior:constraint:keys','identity',jsonb_build_array(c.connamespace::regnamespace::text,CASE WHEN c.conrelid<>0 THEN c.conrelid::regclass::text ELSE NULL END,CASE WHEN c.contypid<>0 THEN c.contypid::regtype::text ELSE NULL END,c.conname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_constraint c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='materialized:sa-multistep-prior:constraint:demand' AND split_part(d.handle,':',1)='pg_constraint'
) AS capture_keys_0471
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','materialized:sa-multistep-prior:index:keys','identity',c.oid::regclass::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_class c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='materialized:sa-multistep-prior:index:demand' AND split_part(d.handle,':',1)='pg_class'
) AS capture_keys_0472
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','materialized:sa-multistep-prior:trigger:keys','identity',jsonb_build_array(c.tgrelid::regclass::text,c.tgname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_trigger c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='materialized:sa-multistep-prior:trigger:demand' AND split_part(d.handle,':',1)='pg_trigger'
) AS capture_keys_0473
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','materialized:sa-multistep-prior:foreign-key-trigger:keys','identity',jsonb_build_array(c.tgrelid::regclass::text,c.tgname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_trigger c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='materialized:sa-multistep-prior:foreign-key-trigger:demand' AND split_part(d.handle,':',1)='pg_trigger'
) AS capture_keys_0474
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','materialized:sa-multistep-prior:policy:keys','identity',jsonb_build_array(c.polrelid::regclass::text,c.polname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_policy c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='materialized:sa-multistep-prior:policy:demand' AND split_part(d.handle,':',1)='pg_policy'
) AS capture_keys_0475
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','materialized:ordered-writer-definition:routine:keys','identity',c.oid::regprocedure::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_proc c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='materialized:ordered-writer-definition:routine:demand' AND split_part(d.handle,':',1)='pg_proc'
) AS capture_keys_0476
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','materialized:ordered-writer-normalized-identity:routine:keys','identity',c.oid::regprocedure::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_proc c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='materialized:ordered-writer-normalized-identity:routine:demand' AND split_part(d.handle,':',1)='pg_proc'
) AS capture_keys_0477
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','temporal:72.retained_precision_fingerprint:function:keys','identity',c.oid::regprocedure::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_proc c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='temporal:72.retained_precision_fingerprint:function:demand' AND split_part(d.handle,':',1)='pg_proc'
) AS capture_keys_0478
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:sa_attack_lab:saved-table:relation:keys','identity',c.oid::regclass::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_class c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='public:sa_attack_lab:saved-table:relation:demand' AND split_part(d.handle,':',1)='pg_class'
) AS capture_keys_0479
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:sa_attack_lab:saved-table:column:keys','identity',jsonb_build_array(c.attrelid::regclass::text,c.attnum,c.attname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_attribute c ON c.attrelid=split_part(d.handle,':',2)::oid AND c.attnum=split_part(d.handle,':',3)::integer WHERE d."ruleId"='public:sa_attack_lab:saved-table:column:demand' AND split_part(d.handle,':',1)='pg_attribute'
) AS capture_keys_0480
UNION ALL
SELECT * FROM (
SELECT jsonb_build_object('ruleId','public:sa_attack_lab:saved-table:constraint:keys','identity',jsonb_build_array(c.connamespace::regnamespace::text,CASE WHEN c.conrelid<>0 THEN c.conrelid::regclass::text ELSE NULL END,CASE WHEN c.contypid<>0 THEN c.contypid::regtype::text ELSE NULL END,c.conname)::text,'handle',d.handle,'multiplicity',1,'fact','{}'::jsonb) FROM jsonb_to_recordset($1::jsonb) AS d("ruleId" text,handle text) JOIN pg_constraint c ON c.oid=split_part(d.handle,':',2)::oid WHERE d."ruleId"='public:sa_attack_lab:saved-table:constraint:demand' AND split_part(d.handle,':',1)='pg_constraint'
) AS capture_keys_0481
