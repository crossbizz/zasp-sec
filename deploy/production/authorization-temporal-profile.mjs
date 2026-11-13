// A named logical78/79/80 profile retains exactly61 canonical migration rows.
// This validates deployment references, never live secret contents or readiness.
// The profile is installed from the baseline schema (agentsec-migrate
// install-baseline), which fixes the service login names and installs the
// approval-maintenance profile, so the deployment names its delivery key,
// its dedicated login's DSN Secret and its checksum.
export const authorizationTemporalProfileName = 'canonical61-temporal78-authorization79-80-worker-v1';
const names = ['executorPrincipal','compensationPrincipal','projectorPrincipal','adapterPrincipal'];
const secrets = ['executorDSNSecret','compensationDSNSecret','projectorDSNSecret','adapterDSNSecret'];
const roles = ['workerRoleArn','projectorRoleArn','adapterRoleArn'];
const configMaps = ['pricingBindingsConfigMap', 'gatewayPolicyKeysConfigMap'];
const approvalSecrets = ['approvalMaintenanceDSNSecret'];
const keys = ['profile',...names,...secrets,...roles,'forwardKey','compensationKey',...configMaps,'approvalMaintenanceChecksum',...approvalSecrets,'approvalMaintenanceKey','registerIdentityVerifiers'];
// The baseline creates these logins; no other names exist on it.
const baselineLogins = Object.freeze({executorPrincipal:'zasp_svc_temporal_executor',compensationPrincipal:'zasp_svc_temporal_compensation',projectorPrincipal:'zasp_svc_outbox',adapterPrincipal:'zasp_svc_red_team_adapter'});
const keyPurposes = [['forwardKey','worker-forward'],['compensationKey','captured-compensation'],['approvalMaintenanceKey','approval-forward']];
const dnsName = /^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$/;
const login = /^[a-z][a-z0-9_]{2,62}$/;
const ulid = /^[0-7][0-9A-HJKMNP-TV-Z]{25}$/;
const queue = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const reject = () => { throw new Error('authorization temporal profile rejected'); };
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const distinct = values => new Set(values).size === values.length;

export function normalizeAuthorizationTemporalProfile(value, options, accountID) {
  if (value === undefined) return undefined;
  if (!object(value) || Object.keys(value).length !== keys.length || keys.some(k => !(k in value)) || value.profile !== authorizationTemporalProfileName || options?.schemaVersion !== 61 || !/^[0-9]{12}$/.test(accountID) || accountID === '000000000000') reject();
  const runtime = options.runtimeServices;
  if (!object(runtime) || ['storeID','modelID','clientSecret','namespace','taskQueue','discoveryTaskQueue','timeout','temporalAddress','openfgaURL'].some(k => typeof runtime[k] !== 'string')) reject();
  // This named profile packages these exact Service and NetworkPolicy targets.
  if (runtime.temporalAddress !== 'temporal-frontend.zasp-runtime.svc.cluster.local:7233' || runtime.openfgaURL !== 'https://openfga.zasp-runtime.svc.cluster.local:8080') reject();
  if (!object(runtime) || runtime.enabled !== true || !ulid.test(runtime.storeID) || !ulid.test(runtime.modelID) || !dnsName.test(runtime.clientSecret) || !queue.test(runtime.namespace) || !queue.test(runtime.taskQueue) || !queue.test(runtime.discoveryTaskQueue) || runtime.taskQueue === runtime.discoveryTaskQueue || !/^([1-9]|[12][0-9]|30)s$/.test(runtime.timeout) || !/^[a-z0-9.-]+:[1-9][0-9]{0,4}$/.test(runtime.temporalAddress)) reject();
  let url;
  try { url = new URL(runtime.openfgaURL); } catch { reject(); }
  if (url.protocol !== 'https:' || url.username || url.password || url.pathname !== '/' || url.search || url.hash || !url.hostname.includes('.') || Number(runtime.temporalAddress.split(':').at(-1)) > 65535) reject();
  if ([...names,...secrets,...approvalSecrets,...roles,...configMaps].some(k => typeof value[k] !== 'string') || names.some(k => !login.test(value[k]) || value[k] !== baselineLogins[k]) || !distinct(names.map(k => value[k])) || [...secrets,...approvalSecrets,...configMaps].some(k => !dnsName.test(value[k])) || !distinct([...secrets,...approvalSecrets].map(k => value[k]))) reject();
  if (typeof value.approvalMaintenanceChecksum !== 'string' || !/^[a-f0-9]{64}$/.test(value.approvalMaintenanceChecksum) || typeof value.registerIdentityVerifiers !== 'boolean') reject();
  for (const [field,purpose] of keyPurposes) {
    const key = value[field];
    if (!object(key) || Object.keys(key).length !== 3 || key.purpose !== purpose || key.key !== 'seed' || typeof key.secretName !== 'string' || !dnsName.test(key.secretName)) reject();
  }
  if (!distinct([...secrets.map(k => value[k]), ...approvalSecrets.map(k => value[k]), ...configMaps.map(k => value[k]), value.forwardKey.secretName,value.compensationKey.secretName,value.approvalMaintenanceKey.secretName,runtime.clientSecret])) reject();
  const arn = new RegExp(`^arn:aws:iam::${accountID}:role/[A-Za-z0-9_+=,.@-]{1,64}$`);
  if (roles.some(k => !arn.test(value[k])) || !distinct(roles.map(k => value[k]))) reject();
  return Object.freeze({...value,forwardKey:Object.freeze({...value.forwardKey}),compensationKey:Object.freeze({...value.compensationKey}),approvalMaintenanceKey:Object.freeze({...value.approvalMaintenanceKey})});
}

export function authorizationTemporalMigrationCommands(profile) {
  if (profile?.profile !== authorizationTemporalProfileName) reject();
  // The baseline already binds the service logins, so no principal
  // registration runs. The identity verifiers need the first Organization.
  return Object.freeze(['register-authorization-verifier','register-worker-authorization-verifier','register-compensation-authorization-verifier','register-approval-maintenance-verifier',...(profile.registerIdentityVerifiers ? ['register-identity-session-verifier','register-identity-webhook-verifier'] : [])]);
}

// The exact schema job command the chart renders (zasp.baseline.schemaCommand).
export function authorizationTemporalMigrationShell(profile) {
  const run = command => `/app/agentsec-migrate ${command}`, file = name => `"$(cat /var/run/secrets/zasp-migration/${name})"`;
  const commands = authorizationTemporalMigrationCommands(profile), identity = commands.slice(4);
  return `export ZASP_POSTGRES_DSN=${file('postgres-dsn')}; export ZASP_WORKFLOW_SIGNING_KEY=${file('workflow-signing-key')}; if ! ${run('verify-baseline')}; then ${run('install-baseline')}; ${run('verify-baseline')}; fi; ` + commands.slice(0, 4).map(run).join('; ') +
    (identity.length ? `; export ZASP_STYTCH_PROJECT_ID=${file('stytch-project-id')}; export ZASP_STYTCH_ORGANIZATION_ID=${file('stytch-organization-id')}; ` + identity.map(run).join('; ') : '');
}

// Helm values this profile contributes outside authorizationTemporal.
export function authorizationTemporalChartValues(profile) {
  if (profile?.profile !== authorizationTemporalProfileName) reject();
  return {
    schema: { registerIdentityVerifiers: profile.registerIdentityVerifiers },
    approvalMaintenance: { profileChecksum: profile.approvalMaintenanceChecksum, dsnSecret: profile.approvalMaintenanceDSNSecret, key: { secretName: profile.approvalMaintenanceKey.secretName } },
  };
}
