// A named logical78/79/80 profile retains exactly61 canonical migration rows.
// This validates deployment references, never live secret contents or readiness.
export const authorizationTemporalProfileName = 'canonical61-temporal78-authorization79-80-worker-v1';
const names = ['executorPrincipal','compensationPrincipal','projectorPrincipal','adapterPrincipal'];
const secrets = ['executorDSNSecret','compensationDSNSecret','projectorDSNSecret','adapterDSNSecret'];
const roles = ['workerRoleArn','projectorRoleArn','adapterRoleArn'];
const configMaps = ['pricingBindingsConfigMap', 'gatewayPolicyKeysConfigMap'];
const keys = ['profile',...names,...secrets,...roles,'forwardKey','compensationKey',...configMaps];
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
  if ([...names,...secrets,...roles,...configMaps].some(k => typeof value[k] !== 'string') || names.some(k => !login.test(value[k])) || !distinct(names.map(k => value[k])) || [...secrets,...configMaps].some(k => !dnsName.test(value[k])) || !distinct(secrets.map(k => value[k]))) reject();
  for (const [field,purpose] of [['forwardKey','worker-forward'],['compensationKey','captured-compensation']]) {
    const key = value[field];
    if (!object(key) || Object.keys(key).length !== 3 || key.purpose !== purpose || key.key !== 'seed' || typeof key.secretName !== 'string' || !dnsName.test(key.secretName)) reject();
  }
  if (!distinct([...secrets.map(k => value[k]), ...configMaps.map(k => value[k]), value.forwardKey.secretName,value.compensationKey.secretName,runtime.clientSecret])) reject();
  const arn = new RegExp(`^arn:aws:iam::${accountID}:role/[A-Za-z0-9_+=,.@-]{1,64}$`);
  if (roles.some(k => !arn.test(value[k])) || !distinct(roles.map(k => value[k]))) reject();
  return Object.freeze({...value,forwardKey:Object.freeze({...value.forwardKey}),compensationKey:Object.freeze({...value.compensationKey})});
}

export function authorizationTemporalMigrationCommands(profile) {
  if (profile?.profile !== authorizationTemporalProfileName) reject();
  return Object.freeze(['up-authorization-runtime-profile','register-temporal-executor-principals','register-authorization-verifier','register-identity-session-verifier','register-identity-webhook-verifier','register-worker-authorization-verifier','register-compensation-authorization-verifier']);
}
