// Read-only continuation of the registered maintenance cutover. These outputs
// are review documents, never authenticated release or fleet observations.
const rejected = () => new Error('maintenance deployment review plan rejected');
const issuedPlans = new WeakSet();
const inputFields = ['schemaVersion', 'releaseReference', 'applicationNamespace', 'runtimeNamespace', 'additionalCredentialHolders'];
const baselineConsumers = Object.freeze([
  'agentsec-api', 'agentsec-discovery-scheduler', 'agentsec-discovery-worker',
  'agentsec-red-team-adapter', 'agentsec-red-team-worker', 'agentsec-security-agent',
  'zasp-authorization-projector',
]);
const prerequisites = Object.freeze([
  'actual-target-and-namespace-identity', 'established-release-publisher-and-trust',
  'existing-security-and-release-gates', 'authorized-private-network-and-credentials',
  'complete-paginated-credential-census', 'cloud-ci-secret-reader-exclusion',
  'continuous-all-container-normal-exits', 'actual-admission-and-rbac-enforcement',
  'same-persistent-datastore-and-whole-model', 'all-server-routes-old401-new-model',
  'bound-coordinator-and-existing-sql-principals', 'activation-and-first-composed-ack',
  'real-deployed-stytch-and-provider-acceptance',
]);
const phaseDefinitions = Object.freeze([
  ['release-review', ['actual-target-and-namespace-identity', 'established-release-publisher-and-trust', 'existing-security-and-release-gates'], 'Review the authentic immutable release and target through the established deployment trust boundary.'],
  ['inventory-observe', ['complete-paginated-credential-census', 'cloud-ci-secret-reader-exclusion', 'authorized-private-network-and-credentials'], 'Continuously observe every actual credential holder, controller, role, secret path and namespace UID before transitions.'],
  ['application-quiesce', ['actual-admission-and-rbac-enforcement', 'cloud-ci-secret-reader-exclusion'], 'Independently enforce reviewed Pod CREATE, exec/attach CONNECT and ephemeral-container UPDATE denial, then begin the normal client drain.'],
  ['normal-client-drain', ['continuous-all-container-normal-exits', 'complete-paginated-credential-census'], 'Retain normal terminal receipts for every old client UID and every init/main/ephemeral container; keep all external clients fenced.'],
  ['server-new-only-rotation', ['same-persistent-datastore-and-whole-model', 'continuous-all-container-normal-exits'], 'Normally rotate every authentic OpenFGA server to the approved new-only verifier binding without starting any new-key application client.'],
  ['runtime-freeze', ['actual-admission-and-rbac-enforcement', 'cloud-ci-secret-reader-exclusion'], 'Freeze both namespaces after server rotation; retain exact running coordinator and new-only server UIDs.'],
  ['final-withdrawal-check', ['all-server-routes-old401-new-model', 'complete-paginated-credential-census', 'continuous-all-container-normal-exits'], 'Recheck every actual server route and the complete continuous credential/fence inventory.'],
  ['combined-activation', ['bound-coordinator-and-existing-sql-principals', 'existing-security-and-release-gates'], 'Explicit coordinator action uses the original organization lock and unchanged compiled profile pins/activation SQL; every external writer stays fenced.'],
  ['coordinator-first-composed-ack', ['bound-coordinator-and-existing-sql-principals', 'same-persistent-datastore-and-whole-model'], 'The same bound coordinator alone performs actual composed Reconcile/Stage/Ack through the existing distinct outbox principal.'],
  ['client-release', ['activation-and-first-composed-ack', 'actual-admission-and-rbac-enforcement', 'existing-security-and-release-gates'], 'Only the trusted release executor may advance the fence and start approved new-key clients after both activation and the first Ack.'],
  ['deployed-acceptance', ['real-deployed-stytch-and-provider-acceptance'], 'Verify actual tenant isolation, revocation, approvals, budgets, recovery, audit and operational readiness before any launch claim.'],
]);
function immutable(value) {
  if (value && typeof value === 'object') {
    for (const entry of Object.values(value)) immutable(entry);
    Object.freeze(value);
  }
  return value;
}
function reviewInput(value) {
  if (!value || typeof value !== 'object' || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) throw rejected();
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (Reflect.ownKeys(descriptors).length !== inputFields.length || inputFields.some(k => !descriptors[k] || !Object.hasOwn(descriptors[k], 'value'))) throw rejected();
  const input = Object.fromEntries(inputFields.map(k => [k, descriptors[k].value]));
  const namespace = x => typeof x === 'string' && x.length <= 63 && /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(x);
  const release = input.releaseReference;
  const immutableLocator = typeof release === 'string' && release.length <= 512 && /^oci:\/\/[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?(?::[0-9]{1,5})?\/[a-z0-9][a-z0-9._/-]{0,300}@sha256:[a-f0-9]{64}$/.test(release) && !release.split('/').includes('..');
  if (input.schemaVersion !== 1 || (release !== null && !immutableLocator) || !namespace(input.applicationNamespace) || !namespace(input.runtimeNamespace) || input.applicationNamespace === input.runtimeNamespace || !Array.isArray(input.additionalCredentialHolders) || Reflect.ownKeys(input.additionalCredentialHolders).length !== 1 || input.additionalCredentialHolders.length !== 0) throw rejected();
  return input;
}

// Namespace names and immutable locator are explicit UNVERIFIED review inputs.
// Even an empty additional-holder list never establishes census completeness.
export function buildMaintenanceDeploymentCutoverPlan(value) {
  const input = reviewInput(value);
  const plan = {
    schema: 'zasp-maintenance-deployment-cutover-plan-v1',
    verified: false, productionAvailable: false, mayActivate: false,
    mutatingResources: [],
    reviewInputs: { releaseReference: input.releaseReference, applicationNamespace: input.applicationNamespace, runtimeNamespace: input.runtimeNamespace, bindingStatus: 'unverified' },
    credentialCensus: { expectedBaseline: [...baselineConsumers], completeness: 'unverified', additionalHolders: 'unknown-until-authenticated-census', unexpectedHolderAction: 'refuse' },
    prerequisites: prerequisites.map(id => ({ id, status: 'unverified' })),
    phases: phaseDefinitions.map(([id, requires, intent], index) => ({
      id, ordinal: index + 1, after: index === 0 ? null : phaseDefinitions[index - 1][0], requires: [...requires], intent, authorized: false,
      externalClientState: index >= 2 && index <= 8 ? 'fenced' : index >= 9 ? 'release-only-after-verified-activation-and-ack' : 'not-yet-observed',
      newClientCredentialAccess: index <= 8 ? 'coordinator-only' : 'release-only-after-verified-activation-and-ack',
      soleFirstAckWriter: 'same-bound-coordinator',
    })),
    limitations: [
      'No release publisher, trust root, cluster, namespace UID, credential, normal exit or installed fence is verified by this renderer.',
      'All seven shared-credential application workloads are potential tuple writers; unknown or opaque additional holders must refuse the actual protocol.',
      'Namespace admission cannot revoke IAM, SecretsStore, CI, off-cluster readers or already-running processes. Those identities require authoritative exclusion and continuous normal-termination evidence.',
      'Only the existing bound coordinator may retain the new client key and perform the first composed Ack. OpenFGA server verifier material is a distinct server purpose, never permission for another client writer.',
      '404, watch restart/gap, partition, forced deletion, signal/OOM/unknown exit or missing container history never establishes normal termination.',
      'These phases describe intended dependencies; no API accepts this object or its private JavaScript brand as activation or fleet proof.',
    ],
  };
  issuedPlans.add(plan);
  return immutable(plan);
}

const rule = (group, operations, resources) => ({ apiGroups: [group], apiVersions: ['v1'], operations, resources, scope: 'Namespaced' });

// These standalone candidates describe supported admission API semantics only.
// They are never submitted, installed, trusted or placed in mutatingResources.
export function renderMaintenanceDeploymentAdmissionReview(plan, phase) {
  if (!issuedPlans.has(plan) || !['application-quiesce', 'runtime-freeze'].includes(phase)) throw rejected();
  const app = plan.reviewInputs.applicationNamespace, runtime = plan.reviewInputs.runtimeNamespace;
  const rules = [
    rule('', ['CREATE'], ['pods']),
    rule('', ['UPDATE'], ['pods/ephemeralcontainers']),
    rule('', ['CONNECT'], ['pods/exec', 'pods/attach']),
    rule('batch', ['CREATE'], ['jobs', 'cronjobs']),
    rule('apps', ['CREATE'], ['deployments', 'replicasets', 'statefulsets', 'daemonsets']),
  ];
  if (phase === 'runtime-freeze') rules.push(
    rule('', ['DELETE'], ['pods']),
    rule('apps', ['UPDATE', 'DELETE'], ['deployments', 'replicasets', 'statefulsets', 'daemonsets']),
    rule('apps', ['UPDATE'], ['deployments/scale', 'replicasets/scale', 'statefulsets/scale']),
    rule('batch', ['UPDATE', 'DELETE'], ['jobs', 'cronjobs']),
    rule('', ['CREATE', 'UPDATE', 'DELETE'], ['services', 'endpoints']),
    rule('discovery.k8s.io', ['CREATE', 'UPDATE', 'DELETE'], ['endpointslices']),
  );
  const name = phase === 'application-quiesce' ? 'zasp-maintenance-app-quiesce-review' : 'zasp-maintenance-runtime-freeze-review';
  const metadata = { name, annotations: { 'zasp.io/review-only': 'true', 'zasp.io/enforcement-verified': 'false' } };
  const policy = {
    apiVersion: 'admissionregistration.k8s.io/v1', kind: 'ValidatingAdmissionPolicy', metadata,
    spec: {
      failurePolicy: 'Fail',
      matchConstraints: { resourceRules: rules },
      matchConditions: [{ name: 'explicit-review-namespaces', expression: phase === 'application-quiesce' ? `request.namespace == '${app}'` : `request.namespace in ['${app}','${runtime}']` }],
      validations: [{ expression: 'false', message: 'maintenance cutover review fence rejects this operation' }],
    },
  };
  const binding = {
    apiVersion: 'admissionregistration.k8s.io/v1', kind: 'ValidatingAdmissionPolicyBinding',
    metadata: { name, annotations: { ...metadata.annotations } },
    spec: { policyName: name, validationActions: ['Deny'] },
  };
  return immutable({
    schema: 'zasp-maintenance-admission-review-v1', phase,
    reviewOnly: true, installed: false, enforcementVerified: false,
    mutatingResources: [], admissionReviewResources: [policy, binding],
    remainingUnverified: [...prerequisites],
    limitations: [
      'A candidate is a cluster-scoped admission policy with namespace request conditions; it is not a namespace UID fence or authenticated release binding.',
      'Actual Kubernetes1.34 admission, RBAC and each exec/attach/ephemeral/scale/controller subresource denial must be tested against the bound deployment. This renderer supplies no enforcement result.',
      'Application quiesce candidates cover Pod CREATE, exec/attach CONNECT, ephemeral-container UPDATE and workload CREATE only, while permitting reviewed normal controller scale-down. Actual enforcement and existing-client normal drain remain unverified.',
      'Runtime freeze is a separate final stage AFTER normal server rotation and applies to both review namespaces. It also freezes route changes and normal replacement; server failure must refuse activation.',
      'RBAC portforward, proxy/GET and read/secret access, controller/IAM/CI authority, off-cluster holders, other API paths, policy tampering, watcher continuity and first composed Ack remain separate unverified mandatory gates; these candidates do not establish a complete fence.',
    ],
  });
}
