import {randomBytes} from 'node:crypto';
import path from 'node:path';

const refuse=()=>{throw Error('owned OpenFGA storage unavailable');};

// Provision only inside the independently owned loopback PostgreSQL fixture.
// Password bytes travel on stdin, never command arguments or error messages.
export async function provisionOwnedFGAStorage({command,psql,port,environment}) {
 if(typeof command!=='function'||typeof psql!=='string'||!path.isAbsolute(psql)||path.normalize(psql)!==psql||!Number.isSafeInteger(port)||port<1024||port>65535||!environment||Object.getPrototypeOf(environment)!==Object.prototype)refuse();
 const env=Object.fromEntries(Object.entries(environment).filter(([name])=>!name.startsWith('ZASP_')&&!name.startsWith('PG')));
 const operator=`postgres://zasp_e2e@127.0.0.1:${port}/postgres?sslmode=disable`;
 const password=randomBytes(32).toString('hex');
 const sql=`CREATE ROLE zasp_e2e_fga LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '${password}';
CREATE DATABASE zasp_e2e_fga OWNER zasp_e2e_fga;
REVOKE ALL ON DATABASE zasp_e2e_fga FROM PUBLIC;
GRANT CONNECT ON DATABASE zasp_e2e_fga TO zasp_e2e_fga;
`;
 const invoke=async input=>{
  let result;try{result=await command(psql,[operator,'-X','-v','ON_ERROR_STOP=1','-qAt'],{env,input,timeout:10000,reject:false});}catch{refuse();}
  if(result?.status!==0||result.signal||typeof result.stdout!=='string'||result.stdout.length>4096||result.stderr||result.outputLimitExceeded)refuse();
  return result.stdout.trim();
 };
 if(await invoke(sql)!=='')refuse();
 const result=await invoke(`SELECT r.rolcanlogin AND NOT r.rolinherit AND NOT r.rolsuper AND NOT r.rolcreatedb AND NOT r.rolcreaterole AND NOT r.rolreplication AND NOT r.rolbypassrls AND NOT EXISTS(SELECT 1 FROM pg_auth_members WHERE member=r.oid) AND EXISTS(SELECT 1 FROM pg_database WHERE datname='zasp_e2e_fga' AND datdba=r.oid) FROM pg_roles r WHERE r.rolname='zasp_e2e_fga';\n`);
 if(result!=='t')refuse();
 return Object.freeze({dsn:`postgres://zasp_e2e_fga:${password}@127.0.0.1:${port}/zasp_e2e_fga?sslmode=disable`,production:false,deployed:false});
}
