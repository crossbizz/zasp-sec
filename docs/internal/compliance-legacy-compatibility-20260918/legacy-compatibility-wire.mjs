import {createOwnedBrowserPostgres} from '../../../scripts/owned-browser-postgres.mjs';
import {spawnOwnedCommand} from '../../../scripts/owned-command.mjs';
import fs from 'node:fs';
import net from 'node:net';
const server=net.createServer();await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));const port=server.address().port;await new Promise(resolve=>server.close(resolve));
const pg=createOwnedBrowserPostgres({port});
try {
 await pg.start();
 const source=fs.readFileSync('services/platform/apiserver/administration_repository.go','utf8');
 const query=source.match(/postgresListComplianceEvidenceSQL\s*= `([^`]+)`/)[1];
 const setup="CREATE TABLE zasp_compliance_controls(organization_id text,id text,framework text,name text,fresh_until timestamptz);CREATE TABLE zasp_compliance_evidence(organization_id text,control_id text,id text,asset_id text,source text,at timestamptz);INSERT INTO zasp_compliance_controls VALUES('org','access-control','SOC 2','Logical access controls','2026-09-20T00:00:00Z');INSERT INTO zasp_compliance_evidence VALUES('org','access-control','evidence-membership','asset-member','product-membership','2026-09-19T00:00:00Z');";
 const owned=spawnOwnedCommand('/usr/local/bin/docker',['exec',pg.containerID,'psql','-U','zasp_e2e','-d','postgres','-X','-At','-v','ON_ERROR_STOP=1','-c',setup+"PREPARE legacy(text,text,text,int) AS "+query+";EXECUTE legacy('org','','',101);"],{graceMs:1000,killMs:1000});
 const result=await owned.completed;if(result.status!==0)throw new Error(result.stderr);console.log(result.stdout);fs.writeFileSync('.superpowers/sdd/2026-09-18-compliance-production-plan/legacy-compatibility-wire.json',result.stdout.trim().split('\n').at(-1));
} finally {await pg.stop();console.log('Owned PostgreSQL joined and removed');}
