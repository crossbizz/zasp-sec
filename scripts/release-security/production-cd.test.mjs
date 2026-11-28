import assert from 'node:assert/strict';
import {generateKeyPairSync, sign} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {mkdtemp, rm, writeFile} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {load, loadAll} from 'js-yaml';
import {checkTestedMain, pushChecks, validateProductionResources} from './production-cd.mjs';
import {installVPSProduction, upgradeProduction} from './deploy.mjs';
import {imageRoles} from './candidate.mjs';
import {sha256} from './trust.mjs';

const sha = 'b'.repeat(40);
const previous = 'a'.repeat(40);
const uid = '00000000-0000-4000-8000-000000000001';
const target = {profile:'vps-production', context:'test', clusterUID:uid, installationID:'fixture', namespace:'agentsec', release:'agentsec'};
const env = {GITHUB_SHA:sha, GITHUB_REPOSITORY:'example/repo', GITHUB_REF:'refs/heads/main', GH_TOKEN:'read-token'};
const workload = name => ({apiVersion:'apps/v1', kind:'Deployment', metadata:{name}, spec:{template:{spec:{containers:[{name, image:'repo/api@sha256:' + 'b'.repeat(64)}]}}}});
const app = JSON.stringify(workload('agentsec-api'));
const hook = JSON.stringify({apiVersion:'batch/v1', kind:'Job', metadata:{name:'agentsec-migrate', annotations:{'helm.sh/hook':'pre-upgrade'}}, spec:{template:{spec:{containers:[{name:'migrate', image:'repo/api@sha256:' + 'b'.repeat(64)}]}}}});
const expected = app + '\n---\n' + hook;

test('only the latest exact push commit can deploy after successful tests for each required workflow attempt', async () => {
  async function check(options = {}) {
    let queries = 0;
    const request = async url => {
      let payload;
      if (url.endsWith('/git/ref/heads/main')) {
        queries++;
        payload = {object:{sha:queries === (options.changeAt ?? 0) ? previous : sha}};
      } else if (url.includes('/actions/workflows/')) {
        const index = pushChecks.findIndex(([file]) => url.includes('/' + file + '/'));
        assert.ok(index >= 0);
        assert.ok(url.includes('event=push&head_sha=' + sha));
        payload = {workflow_runs:[{head_sha:sha, head_branch:'main', head_repository:{full_name:options.source ?? env.GITHUB_REPOSITORY}, event:options.event ?? 'push', run_number:1, run_attempt:2, id:index+1, status:'completed', conclusion:options.conclusion ?? 'success'}]};
      } else {
        const [, id] = url.match(/\/runs\/(\d+)\/attempts\/2\/jobs/);
        const jobs = pushChecks[Number(id)-1][1].map(name => ({name, conclusion:options.job ?? 'success'}));
        payload = {jobs, total_count:jobs.length};
      }
      return {ok:true, json:async () => payload};
    };
    return checkTestedMain({env, request});
  }
  assert.equal(await check(), true);
  assert.equal(await check({changeAt:1}), false);
  assert.equal(await check({changeAt:2}), false);
  await assert.rejects(check({event:'pull_request'}), /incomplete/);
  await assert.rejects(check({source:'fork/repo'}), /incomplete/);
  await assert.rejects(check({conclusion:'failure'}), /did not pass/);
  await assert.rejects(check({job:'skipped'}), /missing or skipped/);
  await assert.rejects(checkTestedMain({env:{...env,GITHUB_REF:'refs/heads/feature'}}), /main commit/);
});

test('production workload admission rejects foreign and cluster resources, including old hooks and embedded shared services', () => {
  validateProductionResources(app, [{manifest:hook}]);
  for (const namespace of ['staging','connectors','opensearch','zasp','production']) {
    const doc = workload('agentsec-api');
    doc.metadata.namespace = namespace;
    assert.throws(() => validateProductionResources(JSON.stringify(doc)), /foreign-namespace/);
    assert.throws(() => validateProductionResources(app, [{manifest:JSON.stringify(doc)}]), /foreign-namespace/);
  }
  assert.throws(() => validateProductionResources('apiVersion: v1\nkind: Namespace\nmetadata: {name: agentsec}'), /cluster-wide/);
  assert.throws(() => validateProductionResources(JSON.stringify(workload('nango'))), /shared dependency/);
  const embedded = workload('helper');
  embedded.spec.template.spec.initContainers = [{name:'setup',image:'opensearchproject/opensearch:3'}];
  assert.throws(() => validateProductionResources(JSON.stringify(embedded)), /shared dependency/);
});

test('the first install and each upgrade bind scoped resources, full image digests, namespace ownership and immutable signed evidence', async t => {
  const dir = await mkdtemp(path.join(tmpdir(),'agentsec-signed-cd-'));
  t.after(() => rm(dir, {recursive:true,force:true}));
  const key = generateKeyPairSync('ed25519');
  await writeFile(path.join(dir, 'rendered.yaml'), expected);
  await writeFile(path.join(dir, 'production-values.yaml'), 'configuration: operator\n');
  const fixtureEnv = {...env, HELM_DRIVER:'secret', ZASP_RELEASE_EVIDENCE_DIR:dir, ZASP_VPS_KUBE_CONTEXT:target.context, ZASP_VPS_CLUSTER_UID:uid, ZASP_VPS_INSTALLATION_ID:target.installationID, ZASP_RELEASE_BUILD_PUBLIC_KEY:key.publicKey.export({type:'spki', format:'pem'})};
  const productImages = Object.fromEntries(imageRoles.map(role => [role,'registry.test/' + role + '@sha256:' + 'c'.repeat(64)]));
  const signed = JSON.stringify({format:'zasp.release.candidate.v1',deploymentTarget:target,renderedSha256:sha256(expected),productImages});
  await writeFile(path.join(dir, 'candidate.json'),signed);
  await writeFile(path.join(dir, 'candidate.json.sig'),sign(null,Buffer.from(signed),key.privateKey).toString('base64'));
  const authorize = async () => ({commit:sha,candidateSha256:sha256(signed)});
  async function run(settings = {}) {
    let writes = 0, ownerChecks = 0;
    const execute = (bin,args) => {
      if (bin === 'kubectl') {
        if (args.includes('current-context')) return settings.context ?? target.context;
        if (args.includes('whoami')) return JSON.stringify({status:{userInfo:{username:settings.identity ?? 'system:serviceaccount:agentsec:zasp-cd'}}});
        const name = args[4];
        assert.ok(['kube-system','agentsec'].includes(name));
        if (name === 'agentsec') ownerChecks++;
        const owner = ownerChecks === settings.wrongOwnerAt ? 'other' : target.installationID;
        return JSON.stringify({metadata:{name, uid:settings.liveUID ?? uid, labels:{'zasp.io/installation':owner}}});
      }
      if (bin === 'git') {
        if (args.includes('merge-base') && settings.older) throw Error('commit not descendant');
        if (args.includes('show')) { assert.ok(args.includes(sha + ':deploy/vps/production/values.yaml')); return 'profile: control_plane\n'; }
        return '';
      }
      if (bin === 'tar') return '';
      assert.equal(bin,'helm');
      assert.deepEqual(args.slice(0,4), ['--kube-context',target.context,'-n','agentsec']);
      if (args.includes('list')) return JSON.stringify(settings.installed ? [{name:'agentsec'}] : []);
      if (args.includes('status')) return JSON.stringify({name:'agentsec',namespace:'agentsec',config:{global:{releaseCommit:previous}},info:{status:'deployed'},manifest:settings.installedManifest ?? app,hooks:[]});
      if (args.includes('template')) {
        const [privateValues, overlay, images] = args.flatMap((flag,i) => flag === '-f' ? [args[i+1]] : []);
        assert.match(readFileSync(privateValues,'utf8'), /operator/);
        assert.match(readFileSync(overlay,'utf8'), /control_plane/);
        const values = JSON.parse(readFileSync(images,'utf8'));
        assert.equal(values.global.releaseCommit,sha);
        assert.deepEqual(Object.values(values.global.productImages).sort(),Object.values(productImages).sort());
        return expected;
      }
      if (args.includes('--dry-run=server')) return JSON.stringify({name:'agentsec',namespace:'agentsec',manifest:app,hooks:[{manifest:settings.hook ?? hook}]});
      const install = settings.install === true;
      assert.equal(args[4], install ? 'install' : 'upgrade');
      assert.equal(args[5], 'agentsec');
      assert.ok(!args.includes('--install') && !args.includes('--create-namespace'));
      assert.ok(args.includes('--atomic') && args.includes('--wait-for-jobs') && args.includes('--post-renderer'));
      assert.equal(ownerChecks,2);
      writes++;
      return '';
    };
    try {
      const apply = settings.install ? installVPSProduction : upgradeProduction;
      await apply({env:{...fixtureEnv,...settings.env},execute,authorize,currentMain:async () => !settings.stale});
      return writes;
    } catch (error) { assert.equal(writes,0); throw error; }
  }
  assert.equal(await run(),1);
  assert.equal(await run({install:true,env:{GITHUB_SHA:undefined}}),1);
  await assert.rejects(run({install:true,installed:true}),/unused production release/);
  await assert.rejects(run({installedManifest:JSON.stringify(workload('opensearch'))}),/shared dependency/);
  await assert.rejects(run({context:'other'}),/target/);
  await assert.rejects(run({env:{ZASP_VPS_CLUSTER_UID:undefined}}),/protected cluster/);
  await assert.rejects(run({env:{ZASP_VPS_INSTALLATION_ID:'other'}}),/protected cluster/);
  await assert.rejects(run({liveUID:previous}),/ownership changed/);
  await assert.rejects(run({wrongOwnerAt:2}),/ownership changed/);
  await assert.rejects(run({identity:'admin'}),/CD identity/);
  await assert.rejects(run({stale:true}),/latest tested main/);
  await assert.rejects(run({older:true}),/not descendant/);
  await assert.rejects(run({hook:hook.replace('agentsec-migrate','substituted')}),/differs/);
});

test('CD requires protected acceptance and promotion, serializes upgrades and limits cluster permissions to named read-only identity checks', () => {
  const file = path => readFileSync(new URL('../../' + path, import.meta.url),'utf8');
  const workflow = load(file('.github/workflows/production-cd.yml'));
  assert.deepEqual(Object.keys(workflow.on).sort(), ['push','workflow_dispatch']);
  assert.deepEqual(workflow.on.push.branches, ['main']);
  assert.match(workflow.jobs['tested-main'].if, /refs\/heads\/main/);
  assert.deepEqual(workflow.jobs.promotion.needs, ['tested-main','acceptance']);
  assert.equal(workflow.jobs.promotion.uses,'./.github/workflows/production-promotion.yml');
  assert.equal(workflow.jobs.acceptance.uses,'./.github/workflows/runnable-ui-acceptance.yml');
  assert.equal(workflow.jobs.upgrade.needs,'promotion');
  assert.equal(workflow.jobs.upgrade.environment,'production');
  assert.equal(workflow.jobs.upgrade['runs-on'].group,'zasp-production');
  assert.equal(workflow.jobs.upgrade.concurrency['cancel-in-progress'],false);
  assert.ok(workflow.jobs.upgrade.steps.some(s => s.run === 'node scripts/release-security/deploy.mjs upgrade-production'));
  for (const job of Object.values(workflow.jobs)) assert.ok(!job['continue-on-error']);
  const rbac = loadAll(file('deploy/vps/production/cd-rbac.yaml'));
  for (const object of rbac) {
    if (object.kind.startsWith('Cluster')) continue;
    assert.equal(object.metadata.namespace,'agentsec');
  }
  const read = rbac.find(resource => resource.kind === 'ClusterRole');
  assert.deepEqual(read.rules,[{apiGroups:[''],resources:['namespaces'],resourceNames:['kube-system','agentsec'],verbs:['get']}]);
  assert.deepEqual(rbac.find(r => r.kind === 'RoleBinding').subjects, rbac.find(r => r.kind === 'ClusterRoleBinding').subjects);
});
