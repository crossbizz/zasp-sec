# Profile 'kubernetes': the evaluation chart (deploy/kubernetes/zasp) on any
# cluster, from one values file. Sourced by ./zasp.
# shellcheck shell=bash
# shellcheck disable=SC2119,SC2120

KUBE_NAMESPACE="${ZASP_KUBE_NAMESPACE:-zasp}"
KUBE_RELEASE="${ZASP_KUBE_RELEASE:-zasp}"
KUBE_VALUES="${ZASP_KUBE_VALUES:-$ZASP_ROOT/zasp-values.yaml}"
KUBE_CHART="$ZASP_ROOT/deploy/kubernetes/zasp"
KUBE_POD="$KUBE_RELEASE-0"
KUBE_ORIGIN="${ZASP_ORIGIN:-}"

KUBECTL=(kubectl -n "$KUBE_NAMESPACE")
HELM=(helm -n "$KUBE_NAMESPACE")
if [ -n "${ZASP_KUBE_CONTEXT:-}" ]; then
  KUBECTL=(kubectl --context "$ZASP_KUBE_CONTEXT" -n "$KUBE_NAMESPACE")
  HELM=(helm --kube-context "$ZASP_KUBE_CONTEXT" -n "$KUBE_NAMESPACE")
fi
kube_kubectl() { "${KUBECTL[@]}" "$@"; }
# Runs the chart's entrypoint in the toolbox container.
kube_toolbox() { kube_kubectl exec "$KUBE_POD" -c toolbox -- /bin/sh /zasp/config/entrypoint.sh "$@"; }

# True when the values file sets this key of the 'secrets' or 'images' block
# to something other than the empty string. The value is never printed.
kube_value_set() {
  grep -Eq "^  $1: *([^\"' ]|\"[^\"]|'[^'])" "$KUBE_VALUES" 2>/dev/null
}

kubernetes_doctor() {
  doctor_begin
  local rendered minor key
  doctor_tool helm "installs the chart" "install Helm 3.16 or later: https://helm.sh/docs/intro/install/"
  doctor_tool kubectl "talks to the cluster" "install kubectl: https://kubernetes.io/docs/tasks/tools/"
  doctor_tool openssl "generates keys and certificates" "install openssl with your package manager"
  if [ -f "$KUBE_VALUES" ]; then
    doctor_ok "values file $KUBE_VALUES"
    config_private "$KUBE_VALUES" || doctor_warn "$KUBE_VALUES can be read by other users; it holds keys" "run: chmod 600 '$KUBE_VALUES'"
    for key in api worker web; do
      kube_value_set "$key" || doctor_missing "images.$key is empty in $KUBE_VALUES" "build and push the product images: ./zasp install --build-images (needs ZASP_IMAGE_REGISTRY), or set the reference by hand"
    done
    for key in stytchProjectId stytchSecret stytchPublicToken; do
      kube_value_set "$key" || doctor_missing "secrets.$key is empty in $KUBE_VALUES" "copy it from the Stytch dashboard (API keys) of your B2B project"
    done
    kube_value_set organizationName || doctor_warn "bootstrap.organizationName is empty" "the API waits for a first organization; set bootstrap.* or run ./zasp bootstrap-admin after installing"
    if command -v helm >/dev/null 2>&1; then
      if rendered="$(helm template "$KUBE_RELEASE" "$KUBE_CHART" --kube-version 1.29.0 -f "$KUBE_VALUES" 2>&1 >/dev/null)"; then
        doctor_ok "the chart renders with these values"
      else
        doctor_missing "the chart does not render with these values" "$(printf '%s' "$rendered" | tail -n 1)"
      fi
    fi
  else
    doctor_missing "no values file at $KUBE_VALUES" "run: ./zasp --profile kubernetes secrets init"
  fi
  if command -v kubectl >/dev/null 2>&1; then
    if minor="$(kube_kubectl version -o json 2>/dev/null | sed -nE '/"serverVersion"/,/}/s/.*"minor": *"([0-9]+).*/\1/p' | head -n 1)" && [ -n "$minor" ]; then
      if [ "$minor" -ge 29 ]; then
        doctor_ok "the cluster answers (Kubernetes 1.$minor)"
      else
        doctor_missing "the cluster runs Kubernetes 1.$minor" "the chart needs 1.29 or later (restartable init containers)"
      fi
      if kube_kubectl get storageclass 2>/dev/null | grep -q '(default)'; then
        doctor_ok "the cluster has a default StorageClass"
      else
        doctor_warn "no default StorageClass was found" "set persistence.storageClassName, or persistence.enabled: false (data is then lost on every restart)"
      fi
    else
      doctor_missing "the cluster does not answer" "check 'kubectl cluster-info' and ZASP_KUBE_CONTEXT"
    fi
  fi
  doctor_end
}

# Prints '  key: |' followed by the file's lines, indented, for a YAML block.
kube_yaml_block() {
  printf '  %s: |\n' "$1"
  sed 's/^/    /' "$2"
}

# Creates a certificate authority that may vouch for one host name only, and
# a server certificate from it. The authority's key is deleted once it has
# signed. Arguments: directory, host name, subject of the authority.
kube_certificate() {
  local directory="$1" host="$2" subject="$3"
  (
    umask 077
    cd "$directory" || exit 1
    printf '%s\n' '[req]' 'distinguished_name = dn' 'prompt = no' '[dn]' 'CN = unused' \
      '[ca]' 'basicConstraints = critical, CA:TRUE, pathlen:0' 'keyUsage = critical, keyCertSign' 'subjectKeyIdentifier = hash' \
      "nameConstraints = critical, permitted;DNS:$host" \
      '[leaf]' 'basicConstraints = critical, CA:FALSE' 'keyUsage = critical, digitalSignature, keyEncipherment' \
      'extendedKeyUsage = serverAuth' "subjectAltName = DNS:$host" > openssl.cnf
    openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 825 -keyout ca.key -out ca.crt -subj "/CN=$subject" -config openssl.cnf -extensions ca >/dev/null 2>&1 &&
      openssl req -new -newkey rsa:2048 -nodes -keyout server.key -out server.csr -subj "/CN=$host" -config openssl.cnf >/dev/null 2>&1 &&
      openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -sha256 -days 825 -extfile openssl.cnf -extensions leaf -out leaf.crt >/dev/null 2>&1
    status=$?
    rm -f ca.key ca.srl server.csr openssl.cnf
    exit "$status"
  )
}

# Writes the values file: generated keys and certificates, and the settings
# the configuration file supplies. An existing file is never replaced, because
# the database records which keys it trusts.
kubernetes_secrets_init() {
  require_tool openssl
  local key state
  if [ -f "$KUBE_VALUES" ]; then
    note "$KUBE_VALUES already exists; its keys were kept"
  else
    [ -n "$KUBE_ORIGIN" ] || die "set ZASP_ORIGIN in $ZASP_CONFIG_FILE first (for example https://zasp.example.test:8443)"
    local host staging service_hex service_uuid planner=false nango_enabled="${ZASP_KUBE_NANGO_ENABLED:-true}"
    case "$nango_enabled" in true|false) ;; *) die "ZASP_KUBE_NANGO_ENABLED must be true or false" ;; esac
    service_hex="$(openssl rand -hex 16)" || die "could not generate the Nango service key"
    # The pinned Nango bearer middleware accepts RFC 4122 version 4 keys.
    printf -v service_uuid '%s-%s-4%s-%x%s-%s' "${service_hex:0:8}" "${service_hex:8:4}" "${service_hex:13:3}" \
      "$((8 | (16#${service_hex:16:1} & 3)))" "${service_hex:17:3}" "${service_hex:20:12}"
    host="${KUBE_ORIGIN#https://}"
    host="${host%%:*}"
    staging="$(mktemp -d)" || die "could not create a temporary directory"
    chmod 700 "$staging"
    mkdir "$staging/front" "$staging/neo4j"
    kube_certificate "$staging/front" "$host" "Zasp evaluation CA for $host" || { rm -rf "$staging"; die "the TLS certificate was not created (openssl is required)"; }
    cat "$staging/front/leaf.crt" "$staging/front/ca.crt" > "$staging/front/chain.crt"
    kube_certificate "$staging/neo4j" localhost "Zasp evaluation CA for the graph database" || { rm -rf "$staging"; die "the graph database certificate was not created"; }
    # The gateway policy signing key: the 64-byte Ed25519 key (seed, then
    # public key) in unpadded base64url, and its verifier document.
    (
      umask 077
      openssl genpkey -algorithm ed25519 -outform DER -out "$staging/gateway.der" 2>/dev/null || exit 1
      openssl pkey -inform DER -in "$staging/gateway.der" -pubout -outform DER 2>/dev/null | tail -c 32 > "$staging/gateway.public" || exit 1
      { tail -c 32 "$staging/gateway.der"; cat "$staging/gateway.public"; } | openssl base64 -A | tr '+/' '-_' | tr -d '=\n' > "$staging/gateway.key"
      printf '{"keys":[{"key_id":"zasp-gateway","public_key":"%s"}]}' "$(openssl base64 -A < "$staging/gateway.public" | tr '+/' '-_' | tr -d '=\n')" > "$staging/gateway.json"
      [ "$(wc -c < "$staging/gateway.key" | tr -d ' ')" = "86" ]
    ) || { rm -rf "$staging"; die "the gateway signing key was not generated (openssl with Ed25519 is required)"; }
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout /dev/null -days 365 -subj "/CN=zasp red-team adapter (not deployed)" \
      -out "$staging/red-team-ca.pem" 2>/dev/null || { rm -rf "$staging"; die "the red-team adapter certificate was not generated"; }
    [ -z "${OPENROUTER_API_KEY:-}" ] || planner=true
    (
      umask 077
      {
        printf '# Zasp values for the evaluation chart (deploy/kubernetes/zasp).\n'
        printf '# Written by ./zasp secrets init. It holds keys: keep it private and keep it.\n'
        printf '# The database trusts exactly these keys; a lost file means a reinstall.\n'
        printf 'publicOrigin: "%s"\n' "$KUBE_ORIGIN"
        printf 'images:\n  api: "%s"\n  worker: "%s"\n  web: "%s"\n' "${ZASP_IMAGE_API:-}" "${ZASP_IMAGE_WORKER:-}" "${ZASP_IMAGE_WEB:-}"
        printf 'identity:\n  stytchBaseUrl: "%s"\n  oauthProvider: "%s"\n' "${ZASP_STYTCH_BASE_URL:-https://test.stytch.com}" "${ZASP_OAUTH_PROVIDER:-google}"
        printf 'bootstrap:\n  organizationName: "%s"\n  organizationDomain: "%s"\n  adminEmail: "%s"\n' "${ZASP_ORGANIZATION_NAME:-}" "${ZASP_ORGANIZATION_DOMAIN:-}" "${ZASP_ADMIN_EMAIL:-}"
        printf 'securityAgent:\n  planner: %s\n' "$planner"
        printf 'nango:\n  enabled: %s\n' "$nango_enabled"
        printf 'deploymentAdmin:\n  enabled: true\n'
        printf 'secrets:\n'
        printf '  deploymentAdminPassword: "%s"\n' "$(random_hex 32)"
        printf '  nangoServiceKey: "%s"\n' "$service_uuid"
        printf '  nangoAdminKey: "%s"\n' "$(random_hex 32)"
        printf '  nangoEncryptionKey: "%s"\n' "$(random_base64 32)"
        printf '  stytchProjectId: "%s"\n  stytchSecret: "%s"\n  stytchPublicToken: "%s"\n' "${STYTCH_PROJECT_ID:-}" "${STYTCH_SECRET:-}" "${STYTCH_PUBLIC_TOKEN:-}"
        printf '  plannerApiKey: "%s"\n' "${OPENROUTER_API_KEY:-}"
        printf '  workflowSigningKey: "%s"\n' "$(random_hex 32)"
        printf '  tokenRevealKey: "%s"\n' "$(random_base64url 32)"
        printf '  stytchWebhookSecret: "whsec_%s"\n' "$(random_base64 32)"
        printf '  forwardSeedBase64: "%s"\n' "$(random_base64 64)"
        printf '  compensationSeedBase64: "%s"\n' "$(random_base64 64)"
        printf '  approvalDeliveryKeyBase64: "%s"\n' "$(random_base64 32)"
        printf '  openfgaToken: "%s"\n' "$(random_hex 32)"
        printf '  neo4jAdminPassword: "%s"\n' "$(random_hex 24)"
        printf '  neo4jWorkerPassword: "%s"\n' "$(random_hex 24)"
        printf '  awsExternalId: "%s"\n' "$(random_hex 24)"
        printf '  redTeamAdapterToken: "%s"\n' "$(random_hex 32)"
        printf '  gatewaySigningKey: "%s"\n' "$(cat "$staging/gateway.key")"
        printf "  gatewayPolicyKeysJson: '%s'\n" "$(cat "$staging/gateway.json")"
        kube_yaml_block redTeamAdapterCaPem "$staging/red-team-ca.pem"
        kube_yaml_block frontTlsCertificate "$staging/front/chain.crt"
        kube_yaml_block frontTlsKey "$staging/front/server.key"
        kube_yaml_block neo4jTlsCertificate "$staging/neo4j/leaf.crt"
        kube_yaml_block neo4jTlsKey "$staging/neo4j/server.key"
        kube_yaml_block neo4jTlsCa "$staging/neo4j/ca.crt"
      } > "$KUBE_VALUES.partial" && mv "$KUBE_VALUES.partial" "$KUBE_VALUES"
    ) || { rm -rf "$staging"; die "could not write $KUBE_VALUES"; }
    # The authority browsers must trust to open the product without a warning.
    cp "$staging/front/ca.crt" "${KUBE_VALUES%.yaml}.ca.crt" && chmod 644 "${KUBE_VALUES%.yaml}.ca.crt"
    rm -rf "$staging"
    note "wrote $KUBE_VALUES (readable by you only) and ${KUBE_VALUES%.yaml}.ca.crt (the certificate authority to trust in the browser)"
  fi
  say "Generated, in $KUBE_VALUES under 'secrets':"
  for key in workflowSigningKey tokenRevealKey stytchWebhookSecret forwardSeedBase64 compensationSeedBase64 approvalDeliveryKeyBase64 openfgaToken \
    neo4jAdminPassword neo4jWorkerPassword awsExternalId redTeamAdapterToken gatewaySigningKey gatewayPolicyKeysJson deploymentAdminPassword nangoServiceKey nangoAdminKey nangoEncryptionKey; do
    if kube_value_set "$key"; then state=present; else state=MISSING; fi
    case "$key" in
      workflowSigningKey) secret_row "$state" "$key" "signs workflow attestations and sessions (API)" ;;
      tokenRevealKey) secret_row "$state" "$key" "encrypts API tokens until they are revealed once (API)" ;;
      stytchWebhookSecret) secret_row "$state" "$key" "verifies identity provider webhooks (API)" ;;
      forwardSeedBase64|compensationSeedBase64) secret_row "$state" "$key" "authorization worker keys (discovery and Security Agent workers)" ;;
      approvalDeliveryKeyBase64) secret_row "$state" "$key" "approval notification delivery (API, workers, projector)" ;;
      openfgaToken) secret_row "$state" "$key" "token between the product and OpenFGA" ;;
      neo4jAdminPassword|neo4jWorkerPassword) secret_row "$state" "$key" "graph database logins" ;;
      awsExternalId) secret_row "$state" "$key" "external ID of the emulated AWS account" ;;
      redTeamAdapterToken) secret_row "$state" "$key" "placeholder the Security Agent worker requires" ;;
      gatewaySigningKey|gatewayPolicyKeysJson) secret_row "$state" "$key" "gateway policy signing key and its verifier (Security Agent action worker)" ;;
      nangoServiceKey) secret_row "$state" "$key" "authenticates Zasp to the in-cluster Nango environment" ;;
      deploymentAdminPassword) secret_row "$state" "$key" "signs in to the deployment operator console" ;;
      nangoAdminKey) secret_row "$state" "$key" "protects Nango dashboard sessions" ;;
      nangoEncryptionKey) secret_row "$state" "$key" "encrypts credentials in the Nango database" ;;
    esac
  done
  secret_row "$(if grep -q '^  frontTlsCertificate: |' "$KUBE_VALUES"; then echo present; else echo MISSING; fi)" "frontTls*, neo4jTls*" "TLS for the front and for the in-pod graph database"
  say ""
  say "Supplied by you:"
  for key in stytchProjectId stytchSecret stytchPublicToken; do
    if kube_value_set "$key"; then state=present; else state=MISSING; fi
    secret_row "$state" "secrets.$key" "identity provider (required): Stytch dashboard, API keys"
  done
  for key in api worker web; do
    if kube_value_set "$key"; then state=present; else state=MISSING; fi
    secret_row "$state" "images.$key" "product image (required): ./zasp install --build-images, or your own build"
  done
  if kube_value_set plannerApiKey; then state=present; else state=optional; fi
  secret_row "$state" "secrets.plannerApiKey" "model provider key for the Security Agent planner (OpenRouter)"
  say ""
  say "Configure provider credentials in the Nango dashboard after installing: ./zasp --profile kubernetes nango dashboard"
}

kubernetes_nango() {
  [ "$#" -eq 1 ] && [ "$1" = dashboard ] || die "usage: zasp --profile kubernetes nango dashboard"
  require_tool kubectl
  note "Open http://127.0.0.1:3003 while this tunnel is running. Press Ctrl-C to close it."
  run "${KUBECTL[@]}" port-forward --address 127.0.0.1 "service/$KUBE_RELEASE-nango" 3003:3003
}

# Builds the three product images and pushes them to ZASP_IMAGE_REGISTRY, then
# records the references in the values file.
kube_build_images() {
  [ -n "${ZASP_IMAGE_REGISTRY:-}" ] || die "set ZASP_IMAGE_REGISTRY in $ZASP_CONFIG_FILE (for example registry.example.com/zasp)"
  require_tool docker
  local version name dockerfile reference
  version="$(git -C "$ZASP_ROOT" rev-parse HEAD 2>/dev/null)" || die "the images are tagged with the commit; this is not a git checkout"
  for name in api worker web; do
    dockerfile="$ZASP_ROOT/deploy/production/$name.Dockerfile"
    reference="$ZASP_IMAGE_REGISTRY/zasp-$name:$version"
    note "building $reference"
    run docker build --build-arg "VERSION=$version" -f "$dockerfile" -t "$reference" "$ZASP_ROOT" || die "$name image was not built"
    run docker push "$reference" || die "$name image was not pushed"
    if [ "${ZASP_DRY_RUN:-0}" = "0" ]; then
      if sed -E "s|^  $name: .*|  $name: \"$reference\"|" "$KUBE_VALUES" > "$KUBE_VALUES.partial"; then
        (umask 077; cat "$KUBE_VALUES.partial" > "$KUBE_VALUES")
        rm -f "$KUBE_VALUES.partial"
      else
        die "could not record the $name image in $KUBE_VALUES"
      fi
    fi
  done
}

kube_apply() {
  run "${HELM[@]}" upgrade --install "$KUBE_RELEASE" "$KUBE_CHART" --create-namespace -f "$KUBE_VALUES" "$@"
}
kube_wait() {
  run "${KUBECTL[@]}" rollout status "statefulset/$KUBE_RELEASE" --timeout=30m
}

kubernetes_install() {
  local build=0 argument
  for argument in "$@"; do
    case "$argument" in
      --build-images) build=1 ;;
      *) die "usage: zasp install [--build-images]" ;;
    esac
  done
  [ -f "$KUBE_VALUES" ] || die "no values file at $KUBE_VALUES; run: ./zasp --profile kubernetes secrets init"
  [ "$build" -eq 0 ] || kube_build_images
  kubernetes_doctor || die "prerequisites are missing (see above)"
  kube_apply || die "the chart was not installed"
}

kubernetes_up() {
  kubernetes_install "$@"
  kube_wait || die "the pod did not become ready; see ./zasp status and ./zasp logs <container>"
}

kubernetes_upgrade() { kubernetes_up "$@"; }

kubernetes_bootstrap_admin() {
  [ "$#" -eq 3 ] || die "usage: zasp bootstrap-admin <organization name> <email domain> <administrator email>"
  run "${KUBECTL[@]}" exec "$KUBE_POD" -c toolbox -- /bin/sh /zasp/config/entrypoint.sh bootstrap "$1" "$2" "$3" >/dev/null || die "the first administrator was not created (see the stage above and docs/operations/first-organization-bootstrap.md)"
  note "organization '$1' exists and $3 is its administrator. The identity provider sent the invitation."
}

# Seeds, shows or removes the demo data, in the toolbox container (the API
# image), as the migration operator.
kubernetes_demo() {
  run "${KUBECTL[@]}" exec "$KUBE_POD" -c toolbox -- /bin/sh /zasp/config/entrypoint.sh demo "$@" || die "the demo command did not finish (see the message above)"
}

kubernetes_start() {
  [ "$#" -eq 0 ] || die "usage: zasp start"
  run "${KUBECTL[@]}" scale "statefulset/$KUBE_RELEASE" --replicas=1
  kube_wait
}

kubernetes_stop() {
  [ "$#" -eq 0 ] || die "usage: zasp stop"
  run "${KUBECTL[@]}" scale "statefulset/$KUBE_RELEASE" --replicas=0
}

kubernetes_status() {
  [ "$#" -eq 0 ] || die "usage: zasp status"
  kube_kubectl get statefulset,pod,pvc,service -l "app.kubernetes.io/instance=$KUBE_RELEASE" || die "the cluster does not answer"
  if kube_kubectl get pod "$KUBE_POD" >/dev/null 2>&1; then
    say ""
    kube_toolbox status 2>/dev/null || say "(the toolbox container is not running yet; the pod is still starting)"
    kube_toolbox verify 2>/dev/null || true
  fi
}

kubernetes_logs() {
  local name="" follow=0 argument
  for argument in "$@"; do
    case "$argument" in
      --follow|-f) follow=1 ;;
      -*) die "usage: zasp logs [container] [--follow]" ;;
      *) [ -z "$name" ] || die "usage: zasp logs [container] [--follow]"; name="$argument" ;;
    esac
  done
  if [ -z "$name" ]; then
    say "Containers of pod $KUBE_POD (init steps first):"
    kube_kubectl get pod "$KUBE_POD" -o jsonpath='{range .spec.initContainers[*]}{"  "}{.name}{"\n"}{end}{range .spec.containers[*]}{"  "}{.name}{"\n"}{end}'
    return 0
  fi
  if [ "$follow" -eq 1 ]; then
    kube_kubectl logs "$KUBE_POD" -c "$name" --tail 100 -f
  else
    kube_kubectl logs "$KUBE_POD" -c "$name" --tail 100
  fi
}

# One archive: a dump of the pod's PostgreSQL (product and OpenFGA
# databases), the persistent state files and the values file with its keys.
kubernetes_backup() {
  [ "$#" -le 1 ] || die "usage: zasp backup [file]"
  local target="${1:-zasp-backup-kubernetes-$(date -u +%Y%m%dT%H%M%SZ).tar.gz}" staging
  [ ! -e "$target" ] || die "$target already exists"
  require_tool tar
  staging="$(mktemp -d)" || die "could not create a temporary directory"
  chmod 700 "$staging"
  mkdir "$staging/dump"
  if ! kube_kubectl exec "$KUBE_POD" -c postgres -- pg_dumpall -h 127.0.0.1 -U postgres --clean --if-exists > "$staging/dump/postgres.sql"; then
    rm -rf "$staging"
    die "the database was not dumped (is the pod running? ./zasp status)"
  fi
  if ! kube_kubectl exec "$KUBE_POD" -c toolbox -- tar -C /var/lib/zasp -cf - . > "$staging/state.tar"; then
    rm -rf "$staging"
    die "the state files were not copied"
  fi
  cp "$KUBE_VALUES" "$staging/values.yaml" || { rm -rf "$staging"; die "could not copy $KUBE_VALUES"; }
  printf 'profile=kubernetes\ncreated=%s\ncommit=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$(git -C "$ZASP_ROOT" rev-parse HEAD 2>/dev/null || echo unknown)" > "$staging/manifest"
  if ! (umask 077; tar -czf "$target" -C "$staging" manifest dump state.tar values.yaml); then
    rm -rf "$staging"
    die "could not write $target"
  fi
  rm -rf "$staging"
  note "wrote $target (contains keys: store it like a secret)"
  note "not included: an external product database (use its provider's snapshots), Temporal's history, the search index and the graph."
}

kubernetes_restore() {
  [ "$#" -eq 1 ] || die "usage: zasp restore <file> --yes"
  local source="$1" staging
  [ -f "$source" ] || die "$source does not exist"
  require_yes "restore replaces the databases and state files of release '$KUBE_RELEASE' in namespace '$KUBE_NAMESPACE' with the contents of $source."
  staging="$(mktemp -d)" || die "could not create a temporary directory"
  chmod 700 "$staging"
  tar -xzf "$source" -C "$staging" || { rm -rf "$staging"; die "$source is not a readable archive"; }
  if ! grep -qx 'profile=kubernetes' "$staging/manifest" 2>/dev/null || [ ! -f "$staging/dump/postgres.sql" ]; then
    rm -rf "$staging"
    die "$source is not a backup of the kubernetes profile"
  fi
  if ! cmp -s "$staging/values.yaml" "$KUBE_VALUES"; then
    note "the values file in the backup differs from $KUBE_VALUES. The restored database trusts the keys of the backup:"
    note "extract values.yaml from $source and use it if sign-in or the workers fail after the restore."
  fi
  # Maintenance mode: only PostgreSQL and the toolbox run, so nothing holds
  # the databases open.
  kube_apply --set product.enabled=false || { rm -rf "$staging"; die "maintenance mode was not applied"; }
  kube_wait || { rm -rf "$staging"; die "the pod did not reach maintenance mode"; }
  if [ "${ZASP_DRY_RUN:-0}" = "1" ]; then
    say "would run: kubectl exec -i $KUBE_POD -c postgres -- psql ... < postgres.sql; kubectl exec -i $KUBE_POD -c toolbox -- tar -xf - < state.tar"
  else
    kube_kubectl exec -i "$KUBE_POD" -c postgres -- psql -X -q -h 127.0.0.1 -U postgres -d postgres < "$staging/dump/postgres.sql" >/dev/null 2>"$staging/restore.log" || true
    kube_kubectl exec -i "$KUBE_POD" -c toolbox -- tar -C /var/lib/zasp -xf - < "$staging/state.tar" || { rm -rf "$staging"; die "the state files were not restored"; }
  fi
  rm -rf "$staging"
  kube_apply || die "the product was not started again"
  kube_wait || die "the pod did not become ready after the restore; the schema step's log says why: ./zasp logs schema"
  note "restored."
}

kubernetes_uninstall() {
  [ "$#" -eq 0 ] || die "usage: zasp uninstall --yes"
  require_yes "uninstall removes release '$KUBE_RELEASE' from namespace '$KUBE_NAMESPACE' and deletes its volume with every database."
  run "${HELM[@]}" uninstall "$KUBE_RELEASE" || true
  run "${KUBECTL[@]}" delete pvc -l "app.kubernetes.io/instance=$KUBE_RELEASE"
  note "removed. $KUBE_VALUES was left in place; it holds the keys of the deleted installation."
}
