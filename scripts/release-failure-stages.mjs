// Diagnostic labels only. They never admit a release or retain subprocess data.
export const RELEASE_FAILURE_STAGES = Object.freeze([
  'normal-configuration', 'normal-values', 'normal-helm-lint', 'normal-helm-template', 'normal-parse', 'normal-resources', 'normal-validation', 'normal-cleanup',
  'edge-configuration', 'edge-dependency', 'edge-values', 'edge-product-lint', 'edge-product-template', 'edge-tetragon-lint', 'edge-tetragon-template', 'edge-parse', 'edge-coverage', 'edge-installation', 'edge-resources', 'edge-placement', 'edge-rbac', 'edge-cleanup',
  'sources-render', 'sources-images', 'sources-canary', 'sources-documentation', 'sources-npm-sbom', 'sources-npm-license', 'sources-go-sbom', 'sources-go-license', 'sources-contracts', 'sources-gitleaks', 'sources-ci', 'sources-image-definitions',
]);
const codes = new Map(RELEASE_FAILURE_STAGES.map(stage => ['ZASP_RELEASE_STAGE_' + stage.replaceAll('-', '_').toUpperCase(), stage]));
const stages = new Set(RELEASE_FAILURE_STAGES);
const ownedErrors = new WeakSet();

export function releaseStageForCode(code) {
  return typeof code === 'string' ? codes.get(code) : undefined;
}

export function releaseStageError(stage, original) {
  // Only errors built here preserve a nested stage. Never inspect an untrusted
  // cause's message/code/getters or copy stdout, stderr, paths or metadata.
  if (ownedErrors.has(original)) return original;
  if (!stages.has(stage)) return new Error('release sources rejected');
  const error = new Error(stage.startsWith('edge-') ? 'edge release rejected' : stage.startsWith('normal-') ? 'release rejected' : 'release sources rejected');
  Object.defineProperty(error, 'code', { value: 'ZASP_RELEASE_STAGE_' + stage.replaceAll('-', '_').toUpperCase(), enumerable: true });
  ownedErrors.add(error);
  return Object.freeze(error);
}

export async function withReleaseStage(stage, operation) {
  if (!stages.has(stage)) throw new Error('release sources rejected');
  try {
    return await operation();
  } catch (original) {
    throw releaseStageError(stage, original);
  }
}
