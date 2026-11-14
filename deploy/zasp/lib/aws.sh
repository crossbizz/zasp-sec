# Profile 'aws': production on EKS. Wraps the Terraform root (deploy/staging),
# the hosted chart (deploy/staging/product) and the commands of
# docs/operations/production-aws-runbook.md behind the same entry point.
#
# Nothing here has been run against an AWS account. Every command that
# changes something goes through 'run', so --dry-run shows it first.
# Sourced by ./zasp.
# shellcheck shell=bash
# shellcheck disable=SC2119,SC2120

AWS_REGION_SETTING="${ZASP_AWS_REGION:-}"
AWS_CLUSTER="${ZASP_AWS_CLUSTER:-zasp-production}"
AWS_NAMESPACE="${ZASP_AWS_NAMESPACE:-agentsec}"
AWS_RELEASE="${ZASP_AWS_RELEASE:-zasp}"
AWS_WORK="${ZASP_AWS_WORK:-${XDG_STATE_HOME:-$HOME/.local/state}/zasp-aws}"
AWS_SECRET_PREFIX="${ZASP_AWS_SECRET_PREFIX:-$AWS_CLUSTER}"
AWS_CHART="$ZASP_ROOT/deploy/staging/product"
AWS_TERRAFORM=(terraform "-chdir=$ZASP_ROOT/deploy/staging")
AWS_KUBECTL=(kubectl -n "$AWS_NAMESPACE")
AWS_HELM=(helm -n "$AWS_NAMESPACE")
AWS_CLI=(aws)
[ -z "$AWS_REGION_SETTING" ] || AWS_CLI=(aws --region "$AWS_REGION_SETTING")
AWS_TERRAFORM_VERSION=1.15.8

aws_work() {
  if ! mkdir -p "$AWS_WORK" || ! chmod 700 "$AWS_WORK"; then die "could not create $AWS_WORK"; fi
}
aws_require_file() {
  [ -n "${!1:-}" ] || die "set $1 in $ZASP_CONFIG_FILE ($2)"
  [ -f "${!1}" ] || die "$1 names '${!1}', which does not exist ($2)"
}
aws_api_image() {
  if [ -n "${ZASP_AWS_API_IMAGE:-}" ]; then
    echo "$ZASP_AWS_API_IMAGE"
  elif [ -f "$AWS_WORK/image-references.txt" ]; then
    sed -nE 's/^agentsec-api (.*)$/\1/p' "$AWS_WORK/image-references.txt" | head -n 1
  fi
}
# True when a Secrets Manager entry holds a value. The value is discarded.
aws_secret_has_value() { "${AWS_CLI[@]}" secretsmanager get-secret-value --secret-id "$AWS_SECRET_PREFIX/$1" --query Name --output text >/dev/null 2>&1; }

aws_doctor() {
  doctor_begin
  local version account count
  doctor_tool terraform "creates the AWS resources" "install Terraform $AWS_TERRAFORM_VERSION exactly: https://developer.hashicorp.com/terraform/install"
  if command -v terraform >/dev/null 2>&1; then
    version="$(terraform version 2>/dev/null | sed -nE '1s/^Terraform v([0-9.]+).*/\1/p')"
    [ "$version" = "$AWS_TERRAFORM_VERSION" ] || doctor_missing "terraform is ${version:-unknown}; deploy/staging/versions.tf requires $AWS_TERRAFORM_VERSION exactly" "install that version"
  fi
  doctor_tool helm "installs the chart" "install Helm 3.16 or later"
  doctor_tool kubectl "talks to the cluster" "install kubectl"
  doctor_tool aws "AWS CLI v2" "install the AWS CLI v2: https://docs.aws.amazon.com/cli/"
  doctor_tool docker "builds and pushes the product images, runs the operator commands" "install Docker with buildx"
  doctor_tool psql "sets the service login passwords" "install the PostgreSQL client"
  doctor_tool openssl "generates keys" "install openssl"
  doctor_tool jq "reads Terraform outputs" "install jq"
  doctor_setting ZASP_AWS_REGION "AWS region" "set it in $ZASP_CONFIG_FILE, for example us-west-2"
  doctor_setting ZASP_AWS_ACCOUNT_ID "twelve-digit AWS account ID" "set it in $ZASP_CONFIG_FILE"
  doctor_setting ZASP_AWS_HOST "public host name of the product" "set it in $ZASP_CONFIG_FILE, for example app.example.com"
  if [ -n "${ZASP_AWS_TFVARS:-}" ] && [ -f "$ZASP_AWS_TFVARS" ]; then
    count="$(grep -c 'REPLACE' "$ZASP_AWS_TFVARS" || true)"
    if [ "$count" = "0" ]; then doctor_ok "Terraform variables file $ZASP_AWS_TFVARS"; else doctor_missing "$ZASP_AWS_TFVARS still has $count lines marked REPLACE" "edit every one"; fi
  else
    doctor_missing "ZASP_AWS_TFVARS does not name a file" "run: cp deploy/production/example.tfvars /secure/zasp-production.tfvars  (outside the repository), edit every REPLACE, and set ZASP_AWS_TFVARS"
  fi
  if [ -n "${ZASP_AWS_VALUES:-}" ] && [ -f "$ZASP_AWS_VALUES" ]; then
    count="$(grep -Ec '(""|\[\])[[:space:]]*#[[:space:]]*REQUIRED' "$ZASP_AWS_VALUES" || true)"
    if [ "$count" = "0" ]; then doctor_ok "Helm values file $ZASP_AWS_VALUES"; else doctor_missing "$ZASP_AWS_VALUES still has $count empty values marked REQUIRED" "fill in every one"; fi
  else
    doctor_missing "ZASP_AWS_VALUES does not name a file" "run: cp deploy/production/values-production.example.yaml /secure/values-production.yaml, fill in every REQUIRED value, and set ZASP_AWS_VALUES"
  fi
  if [ -n "${ZASP_AWS_OPERATOR_DSN_FILE:-}" ] && [ -f "$ZASP_AWS_OPERATOR_DSN_FILE" ]; then
    doctor_ok "operator DSN file"
    config_private "$ZASP_AWS_OPERATOR_DSN_FILE" || doctor_warn "$ZASP_AWS_OPERATOR_DSN_FILE can be read by other users" "run: chmod 600 '$ZASP_AWS_OPERATOR_DSN_FILE'"
  else
    doctor_missing "ZASP_AWS_OPERATOR_DSN_FILE does not name a file" "create the zasp_operator role and database (runbook step 1) and store its DSN in a private file"
  fi
  doctor_setting STYTCH_PROJECT_ID "identity provider project (live)" "Stytch dashboard, API keys"
  doctor_setting STYTCH_SECRET "identity provider API secret" "Stytch dashboard, API keys"
  doctor_setting STYTCH_PUBLIC_TOKEN "identity provider public token" "Stytch dashboard, API keys"
  doctor_optional_setting OPENROUTER_API_KEY "model provider key for the Security Agent planner" "the Security Agent worker cannot start without it"
  if command -v aws >/dev/null 2>&1; then
    if account="$("${AWS_CLI[@]}" sts get-caller-identity --query Account --output text 2>/dev/null)" && [ -n "$account" ]; then
      if [ -z "${ZASP_AWS_ACCOUNT_ID:-}" ] || [ "$account" = "$ZASP_AWS_ACCOUNT_ID" ]; then
        doctor_ok "AWS credentials answer for account $account"
      else
        doctor_missing "AWS credentials are for account $account, not $ZASP_AWS_ACCOUNT_ID" "switch profile or credentials"
      fi
    else
      doctor_missing "AWS credentials do not answer" "run 'aws sts get-caller-identity' and fix what it reports"
    fi
  fi
  if command -v kubectl >/dev/null 2>&1; then
    if "${AWS_KUBECTL[@]}" version -o json >/dev/null 2>&1; then
      doctor_ok "the cluster answers"
    else
      doctor_warn "the cluster does not answer" "expected before 'install infrastructure'. Afterwards: the EKS endpoint is private, so run from inside the VPC (runbook decision D11)"
    fi
  fi
  doctor_end
}

aws_steps() {
  cat <<EOF
Production on AWS is a sequence of steps. ./zasp runs the ones marked [zasp];
the others need a person and are described in docs/operations/production-aws-runbook.md.

   1. Prepare the product database (role zasp_operator, database zasp)        manual, runbook step 1
   2. Create the AWS resources                                                [zasp] ./zasp install infrastructure --yes
   3. Reach the cluster; install the secrets store driver, ingress-nginx,
      Prometheus Operator CRDs, metrics-server and (optionally) cert-manager  manual, runbook step 3
   4. DNS record and TLS Secret for the public host                           manual, runbook step 4
   5. Build and push the nine product images                                  [zasp] ./zasp install images
   6. Temporal and OpenFGA in the cluster, with their databases               manual, runbook step 6
   7. Keys and secrets                                                        [zasp] ./zasp secrets init   (then supply the listed ones)
   8. First chart install: the schema job                                     [zasp] ./zasp install release
   9. Service login passwords and DSNs                                        [zasp] ./zasp install dsns
  10. First organization and administrator                                    [zasp] ./zasp bootstrap-admin <name> <domain> <email>
  11. Roll out and check                                                      [zasp] ./zasp up   then   ./zasp status
  12+ Connect customer accounts and optional providers                        manual, runbook steps 12 to 16

Add --dry-run to any [zasp] command to print what it would run.
EOF
}

aws_install_infrastructure() {
  aws_require_file ZASP_AWS_TFVARS "your copy of deploy/production/example.tfvars"
  require_tool terraform
  aws_work
  run "${AWS_TERRAFORM[@]}" init -input=false -lockfile=readonly || die "terraform init failed"
  run "${AWS_TERRAFORM[@]}" plan -input=false "-var-file=$ZASP_AWS_TFVARS" "-out=$AWS_WORK/zasp.plan" || die "terraform plan failed"
  if [ "${ZASP_YES:-0}" != "1" ]; then
    note "the plan is in $AWS_WORK/zasp.plan. Review it, then apply it with: ./zasp install infrastructure --yes"
    return 0
  fi
  run "${AWS_TERRAFORM[@]}" apply -input=false "$AWS_WORK/zasp.plan" || die "terraform apply failed"
  aws_terraform_values
}

# Writes the values Terraform derives (role ARNs, queues, buckets, keys,
# secret object names) in the chart's own shape. It holds no secret value.
aws_terraform_values() {
  aws_work
  if [ "${ZASP_DRY_RUN:-0}" = "1" ]; then
    say "would run: terraform -chdir=deploy/staging output -json helm_values > $AWS_WORK/values-terraform.json"
    return 0
  fi
  if ! "${AWS_TERRAFORM[@]}" output -json helm_values > "$AWS_WORK/values-terraform.json.partial"; then
    rm -f "$AWS_WORK/values-terraform.json.partial"
    die "terraform output helm_values failed (has \"install infrastructure --yes\" completed?)"
  fi
  mv "$AWS_WORK/values-terraform.json.partial" "$AWS_WORK/values-terraform.json"
}

# Builds and pushes the nine product images to ECR and records each as
# <repository>@<digest>, which is the only form the chart accepts.
aws_install_images() {
  require_tool docker
  require_tool aws
  [ -n "${ZASP_AWS_ACCOUNT_ID:-}" ] && [ -n "$AWS_REGION_SETTING" ] || die "set ZASP_AWS_ACCOUNT_ID and ZASP_AWS_REGION in $ZASP_CONFIG_FILE"
  aws_work
  local registry="$ZASP_AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION_SETTING.amazonaws.com" version name dockerfile key digest
  version="$(git -C "$ZASP_ROOT" rev-parse HEAD 2>/dev/null)" || die "the images are tagged with the commit; this is not a git checkout"
  if [ "${ZASP_DRY_RUN:-0}" = "1" ]; then
    say "would run: aws ecr get-login-password | docker login --username AWS --password-stdin $registry"
  else
    "${AWS_CLI[@]}" ecr get-login-password | docker login --username AWS --password-stdin "$registry" >/dev/null || die "docker could not sign in to $registry"
    : > "$AWS_WORK/image-references.txt"
    printf 'global:\n  productImages:\n' > "$AWS_WORK/values-images.yaml"
  fi
  while read -r name dockerfile key; do
    note "building zasp/$name"
    run docker buildx build --platform linux/amd64 --pull --build-arg "VERSION=$version" -f "$ZASP_ROOT/deploy/production/$dockerfile" \
      -t "$registry/zasp/$name:$version" --push "$ZASP_ROOT" </dev/null || die "zasp/$name was not built and pushed"
    [ "${ZASP_DRY_RUN:-0}" = "0" ] || continue
    digest="$("${AWS_CLI[@]}" ecr describe-images --repository-name "zasp/$name" --image-ids "imageTag=$version" --query 'imageDetails[0].imageDigest' --output text </dev/null)" || die "the digest of zasp/$name was not read"
    case "$digest" in
      sha256:*) ;;
      *) die "the digest of zasp/$name was not read" ;;
    esac
    printf '%s %s\n' "$name" "$registry/zasp/$name@$digest" >> "$AWS_WORK/image-references.txt"
    printf '    %s: "%s"\n' "$key" "$registry/zasp/$name@$digest" >> "$AWS_WORK/values-images.yaml"
  done <<'EOF'
web web.Dockerfile web
agentsec-api api.Dockerfile agentsecApi
agentsec-worker worker.Dockerfile agentsecWorker
attack-lab-runner attack-lab-runner.Dockerfile attackLabRunner
red-team-worker redteam-worker.Dockerfile redTeamWorker
event-ingest event-ingest.Dockerfile eventIngest
gateway-control gateway-control.Dockerfile gatewayControl
runtime-gateway runtime-gateway.Dockerfile runtimeGateway
sensor-agent sensor-agent.Dockerfile sensorAgent
EOF
  [ "${ZASP_DRY_RUN:-0}" = "1" ] || note "wrote $AWS_WORK/values-images.yaml; 'install release' passes it to Helm. recovery.runnerImage, if used, is the agentsec-worker reference."
}

# Installs or upgrades the chart. --wait is not used: on a first install the
# workloads cannot be ready before the DSNs and the first organization exist.
aws_install_release() {
  aws_require_file ZASP_AWS_VALUES "your copy of deploy/production/values-production.example.yaml"
  require_tool helm
  [ -f "$AWS_WORK/values-terraform.json" ] || aws_terraform_values
  local files=(-f "$AWS_WORK/values-terraform.json")
  [ ! -f "$AWS_WORK/values-images.yaml" ] || files+=(-f "$AWS_WORK/values-images.yaml")
  files+=(-f "$ZASP_AWS_VALUES")
  run "${AWS_HELM[@]}" upgrade --install "$AWS_RELEASE" "$AWS_CHART" --create-namespace "${files[@]}" --timeout 20m "$@" || die "helm upgrade failed"
}

# Sets a password on each service login and stores its DSN in Secrets
# Manager, then creates the four DSN Secrets the chart reads from Kubernetes.
# Passwords never reach a command line: psql reads them from standard input
# and the AWS CLI reads the DSN from a private temporary file.
aws_install_dsns() {
  aws_require_file ZASP_AWS_OPERATOR_DSN_FILE "the DSN of the zasp_operator role"
  [ -n "${ZASP_AWS_DATABASE_HOST:-}" ] || die "set ZASP_AWS_DATABASE_HOST in $ZASP_CONFIG_FILE (the database host the service logins use)"
  require_tool psql
  require_tool jq
  if [ "${ZASP_DRY_RUN:-0}" = "1" ]; then
    say "would run: for each login in 'terraform output postgres_dsn_secret_logins': ALTER ROLE <login> PASSWORD <generated>; aws secretsmanager put-secret-value --secret-id <entry> --secret-string file://<private file>"
    say "would run: kubectl create secret generic zasp-temporal-executor zasp-temporal-compensation zasp-authorization-adapter zasp-approval-maintenance-dsn (key postgres-dsn)"
    return 0
  fi
  local staging secret login password pair name entry
  staging="$(mktemp -d)" || die "could not create a temporary directory"
  chmod 700 "$staging"
  "${AWS_TERRAFORM[@]}" output -json postgres_dsn_secret_logins | jq -r 'to_entries[] | "\(.key) \(.value)"' > "$staging/logins" || { rm -rf "$staging"; die "terraform output postgres_dsn_secret_logins failed"; }
  while read -r secret login; do
    case "$login" in
      zasp_svc_*) ;;
      *) rm -rf "$staging"; die "unexpected login '$login' in postgres_dsn_secret_logins" ;;
    esac
    password="$(random_hex 24)"
    printf 'ALTER ROLE "%s" PASSWORD '"'"'%s'"'"';\n' "$login" "$password" | PGCONNECT_TIMEOUT=20 psql -X -q -v ON_ERROR_STOP=1 "$(cat "$ZASP_AWS_OPERATOR_DSN_FILE")" >/dev/null ||
      { rm -rf "$staging"; die "the password of $login was not set"; }
    (umask 077; printf 'postgres://%s:%s@%s/zasp?sslmode=require' "$login" "$password" "$ZASP_AWS_DATABASE_HOST" > "$staging/dsn")
    "${AWS_CLI[@]}" secretsmanager put-secret-value --secret-id "$secret" --secret-string "file://$staging/dsn" >/dev/null </dev/null || { rm -rf "$staging"; die "the DSN of $login was not stored in $secret"; }
    note "stored the DSN of $login"
  done < "$staging/logins"
  for pair in zasp-temporal-executor:postgres-temporal-executor-dsn zasp-temporal-compensation:postgres-temporal-compensation-dsn \
    zasp-authorization-adapter:postgres-red-team-adapter-dsn zasp-approval-maintenance-dsn:postgres-approval-maintenance-dsn; do
    name="${pair%%:*}"
    entry="${pair##*:}"
    "${AWS_CLI[@]}" secretsmanager get-secret-value --secret-id "$AWS_SECRET_PREFIX/$entry" --query SecretString --output text > "$staging/dsn" || { rm -rf "$staging"; die "$AWS_SECRET_PREFIX/$entry has no value"; }
    "${AWS_KUBECTL[@]}" create secret generic "$name" "--from-file=postgres-dsn=$staging/dsn" --dry-run=client -o yaml | "${AWS_KUBECTL[@]}" apply -f - >/dev/null ||
      { rm -rf "$staging"; die "the Kubernetes Secret $name was not created"; }
  done
  rm -rf "$staging"
  note "service logins have passwords, their DSNs are stored, and the four Kubernetes DSN Secrets exist."
}

aws_install() {
  case "${1:-}" in
    "") aws_steps ;;
    infrastructure) shift; aws_install_infrastructure "$@" ;;
    images) shift; aws_install_images "$@" ;;
    release) shift; aws_install_release "$@" ;;
    dsns) shift; aws_install_dsns "$@" ;;
    *) die "usage: zasp install [infrastructure|images|release|dsns]" ;;
  esac
}

# Stores one generated or supplied value in an empty Secrets Manager entry.
# Arguments: entry, 'string' or 'binary', file holding the value.
aws_put_secret() {
  local entry="$1" kind="$2" file="$3"
  if aws_secret_has_value "$entry"; then
    secret_row present "$entry" "kept: it already has a value"
    return 0
  fi
  if [ "$kind" = binary ]; then
    "${AWS_CLI[@]}" secretsmanager put-secret-value --secret-id "$AWS_SECRET_PREFIX/$entry" --secret-binary "fileb://$file" >/dev/null || die "$entry was not stored (does the entry exist? run 'install infrastructure --yes' first)"
  else
    "${AWS_CLI[@]}" secretsmanager put-secret-value --secret-id "$AWS_SECRET_PREFIX/$entry" --secret-string "file://$file" >/dev/null || die "$entry was not stored (does the entry exist? run 'install infrastructure --yes' first)"
  fi
  secret_row stored "$entry" "written now"
}

aws_secrets_init() {
  require_tool aws
  require_tool openssl
  if [ "${ZASP_DRY_RUN:-0}" = "1" ]; then
    say "would run: aws secretsmanager put-secret-value for each empty generated entry under $AWS_SECRET_PREFIX/ (values from private temporary files)"
    return 0
  fi
  local staging entry state
  staging="$(mktemp -d)" || die "could not create a temporary directory"
  chmod 700 "$staging"
  say "Generated (Secrets Manager, under $AWS_SECRET_PREFIX/):"
  (umask 077; random_hex 32 > "$staging/value") && aws_put_secret workflow-signing-key string "$staging/value"
  (umask 077; random_base64url 32 > "$staging/value") && aws_put_secret token-reveal-key string "$staging/value"
  (umask 077; openssl rand 64 > "$staging/value") && aws_put_secret authorization-worker-forward-key binary "$staging/value"
  (umask 077; openssl rand 64 > "$staging/value") && aws_put_secret authorization-worker-compensation-key binary "$staging/value"
  (umask 077; openssl rand 32 > "$staging/value") && aws_put_secret approval-maintenance-key binary "$staging/value"
  say ""
  say "Supplied from $ZASP_CONFIG_FILE:"
  if [ -n "${STYTCH_PROJECT_ID:-}" ]; then (umask 077; printf '%s' "$STYTCH_PROJECT_ID" > "$staging/value"); aws_put_secret stytch-project-id string "$staging/value"; else secret_row MISSING stytch-project-id "set STYTCH_PROJECT_ID"; fi
  if [ -n "${STYTCH_SECRET:-}" ]; then (umask 077; printf '%s' "$STYTCH_SECRET" > "$staging/value"); aws_put_secret stytch-secret string "$staging/value"; else secret_row MISSING stytch-secret "set STYTCH_SECRET"; fi
  if [ -n "${STYTCH_PUBLIC_TOKEN:-}" ]; then (umask 077; printf '%s' "$STYTCH_PUBLIC_TOKEN" > "$staging/value"); aws_put_secret stytch-public-token string "$staging/value"; else secret_row MISSING stytch-public-token "set STYTCH_PUBLIC_TOKEN"; fi
  if [ -n "${OPENROUTER_API_KEY:-}" ]; then (umask 077; printf '%s' "$OPENROUTER_API_KEY" > "$staging/value"); aws_put_secret openrouter-security-agent-api-key string "$staging/value"; else secret_row MISSING openrouter-security-agent-api-key "set OPENROUTER_API_KEY"; fi
  if [ -n "${ZASP_AWS_OPERATOR_DSN_FILE:-}" ] && [ -f "$ZASP_AWS_OPERATOR_DSN_FILE" ]; then aws_put_secret postgres-migration-dsn string "$ZASP_AWS_OPERATOR_DSN_FILE"; else secret_row MISSING postgres-migration-dsn "set ZASP_AWS_OPERATOR_DSN_FILE"; fi
  rm -rf "$staging"
  say ""
  say "Supplied by you with 'aws secretsmanager put-secret-value' (runbook step 7 says what each holds):"
  for entry in stytch-webhook-secret stytch-organization-id connectors/github/client-secret connectors/github/app-private-key connectors/okta/client-secret \
    projection/neo4j/auth/runtime projection/neo4j/auth/schema gateway-policy-signing-private-key attack-lab-egress-signing-key red-team-adapter-token \
    red-team-adapter-tls-certificate red-team-adapter-tls-private-key attack-lab-proxy-tls-certificate attack-lab-proxy-tls-private-key canary-read-token; do
    if aws_secret_has_value "$entry"; then state=present; else state=MISSING; fi
    case "$entry" in
      stytch-webhook-secret) secret_row "$state" "$entry" "Stytch dashboard, webhooks" ;;
      stytch-organization-id) secret_row "$state" "$entry" "written by ./zasp bootstrap-admin" ;;
      connectors/*) secret_row "$state" "$entry" "GitHub App or Okta application; a placeholder until the connector is used" ;;
      projection/neo4j/*) secret_row "$state" "$entry" "credentials of your Neo4j (runbook decision D8)" ;;
      *) secret_row "$state" "$entry" "see the runbook; a pod whose entry is empty cannot start" ;;
    esac
  done
  say ""
  say "The 31 service DSNs are written by: ./zasp install dsns"
  say "Three keys must also exist as Kubernetes Secrets (zasp-worker-forward-key, zasp-worker-compensation-key,"
  say "zasp-approval-maintenance-key): runbook step 7 has the commands; they need cluster access."
}

# Creates the first organization (runbook step 10): runs zasp-bootstrap from
# the API image, stores the provider's organization reference, and lets the
# schema job register the identity verifiers.
aws_bootstrap_admin() {
  [ "$#" -eq 3 ] || die "usage: zasp bootstrap-admin <organization name> <email domain> <administrator email>"
  aws_require_file ZASP_AWS_OPERATOR_DSN_FILE "the DSN of the zasp_operator role"
  [ -n "${ZASP_AWS_HOST:-}" ] || die "set ZASP_AWS_HOST in $ZASP_CONFIG_FILE"
  [ -n "${STYTCH_PROJECT_ID:-}" ] && [ -n "${STYTCH_SECRET:-}" ] || die "set STYTCH_PROJECT_ID and STYTCH_SECRET in $ZASP_CONFIG_FILE"
  [ -n "${ZASP_AWS_OPENFGA_STORE_ID:-}" ] && [ -n "${ZASP_AWS_OPENFGA_MODEL_ID:-}" ] || die "set ZASP_AWS_OPENFGA_STORE_ID and ZASP_AWS_OPENFGA_MODEL_ID (runbook step 6)"
  local image result reference staging
  image="$(aws_api_image)"
  [ -n "$image" ] || die "the API image is unknown: run './zasp install images' or set ZASP_AWS_API_IMAGE"
  require_tool docker
  if [ "${ZASP_DRY_RUN:-0}" = "1" ]; then
    say "would run: docker run --rm --entrypoint /app/zasp-bootstrap --env-file <private file> $image -organization-name '$1' -domain $2 -admin-email $3"
    say "would run: aws secretsmanager put-secret-value --secret-id $AWS_SECRET_PREFIX/stytch-organization-id --secret-string file://<private file>"
    say "would run: helm upgrade --install ... --set schema.registerIdentityVerifiers=true"
    return 0
  fi
  staging="$(mktemp -d)" || die "could not create a temporary directory"
  chmod 700 "$staging"
  (
    umask 077
    {
      printf 'ZASP_POSTGRES_DSN=%s\n' "$(cat "$ZASP_AWS_OPERATOR_DSN_FILE")"
      printf 'ZASP_PUBLIC_ORIGIN=https://%s\nZASP_DEPLOYMENT_MODE=saas\nZASP_ORGANIZATION_ID=\n' "$ZASP_AWS_HOST"
      printf 'ZASP_STYTCH_BASE_URL=%s\nZASP_STYTCH_PROJECT_ID=%s\nZASP_STYTCH_SECRET=%s\n' "${ZASP_STYTCH_BASE_URL:-https://api.stytch.com}" "$STYTCH_PROJECT_ID" "$STYTCH_SECRET"
      printf 'ZASP_OPENFGA_STORE_ID=%s\nZASP_OPENFGA_MODEL_ID=%s\n' "$ZASP_AWS_OPENFGA_STORE_ID" "$ZASP_AWS_OPENFGA_MODEL_ID"
    } > "$staging/env"
  )
  result="$(docker run --rm --entrypoint /app/zasp-bootstrap --env-file "$staging/env" "$image" -organization-name "$1" -domain "$2" -admin-email "$3")" ||
    { rm -rf "$staging"; die "bootstrap refused (see the stage above and docs/operations/first-organization-bootstrap.md)"; }
  reference="$(printf '%s' "$result" | sed -E 's/.*"organization_reference":"([^"]+)".*/\1/')"
  case "$reference" in
    organization-*) ;;
    *) rm -rf "$staging"; die "bootstrap returned no organization reference" ;;
  esac
  (umask 077; printf '%s' "$reference" > "$staging/reference")
  "${AWS_CLI[@]}" secretsmanager put-secret-value --secret-id "$AWS_SECRET_PREFIX/stytch-organization-id" --secret-string "file://$staging/reference" >/dev/null ||
    { rm -rf "$staging"; die "the organization reference was not stored"; }
  rm -rf "$staging"
  aws_install_release --set schema.registerIdentityVerifiers=true
  note "organization '$1' exists and $3 is its administrator. Set schema.registerIdentityVerifiers: true in $ZASP_AWS_VALUES and keep it."
}

aws_up() {
  aws_install_release "$@"
  aws_status
}

aws_upgrade() { aws_install_release "$@"; }

aws_start() {
  # The chart restores every replica count.
  aws_install_release
}

aws_stop() {
  [ "$#" -eq 0 ] || die "usage: zasp stop"
  run "${AWS_KUBECTL[@]}" scale deployment --all --replicas=0
  note "every Deployment is at zero replicas; data, queues and the database are untouched. './zasp start' restores them."
}

aws_status() {
  "${AWS_HELM[@]}" status "$AWS_RELEASE" 2>/dev/null | sed -n '1,6p' || true
  "${AWS_KUBECTL[@]}" get deployment,cronjob || die "the cluster does not answer (the EKS endpoint is private: run from inside the VPC)"
}

aws_logs() {
  local name="" follow=0 argument
  for argument in "$@"; do
    case "$argument" in
      --follow|-f) follow=1 ;;
      -*) die "usage: zasp logs [deployment] [--follow]" ;;
      *) [ -z "$name" ] || die "usage: zasp logs [deployment] [--follow]"; name="$argument" ;;
    esac
  done
  if [ -z "$name" ]; then
    "${AWS_KUBECTL[@]}" get deployment -o name | sed 's|^deployment.apps/|  |'
    return 0
  fi
  if [ "$follow" -eq 1 ]; then
    "${AWS_KUBECTL[@]}" logs "deployment/$name" --all-containers --tail 100 -f
  else
    "${AWS_KUBECTL[@]}" logs "deployment/$name" --all-containers --tail 100
  fi
}

# A logical dump for reference and the release's non-secret configuration.
# The backup of record in production is the database provider's snapshot:
# docs/operations/backup-restore-rollback.md.
aws_backup() {
  [ "$#" -le 1 ] || die "usage: zasp backup [file]"
  aws_require_file ZASP_AWS_OPERATOR_DSN_FILE "the DSN of the zasp_operator role"
  require_tool pg_dump
  local target="${1:-zasp-backup-aws-$(date -u +%Y%m%dT%H%M%SZ).tar.gz}" staging
  [ ! -e "$target" ] || die "$target already exists"
  staging="$(mktemp -d)" || die "could not create a temporary directory"
  chmod 700 "$staging"
  # The DSN is an argument of pg_dump for the length of the dump: run this on
  # a machine where other users cannot list your processes.
  pg_dump --format=custom --no-owner --file "$staging/zasp.dump" --dbname "$(cat "$ZASP_AWS_OPERATOR_DSN_FILE")" || { rm -rf "$staging"; die "the database was not dumped"; }
  "${AWS_HELM[@]}" get values "$AWS_RELEASE" -o yaml > "$staging/helm-values.yaml" 2>/dev/null || true
  [ ! -f "$AWS_WORK/image-references.txt" ] || cp "$AWS_WORK/image-references.txt" "$staging/"
  printf 'profile=aws\ncreated=%s\ncommit=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$(git -C "$ZASP_ROOT" rev-parse HEAD 2>/dev/null || echo unknown)" > "$staging/manifest"
  (umask 077; tar -czf "$target" -C "$staging" .) || { rm -rf "$staging"; die "could not write $target"; }
  rm -rf "$staging"
  note "wrote $target. Also take the database provider's snapshot before every release: it is the backup that can be restored."
}

aws_restore() {
  die "production restore is not automated. Restore the provider's snapshot into a new, isolated database, verify it
  (agentsec-migrate verify-baseline), then switch the DSN secrets to it. See docs/operations/backup-restore-rollback.md."
}

aws_uninstall() {
  local destroy=0 argument
  for argument in "$@"; do
    case "$argument" in
      --destroy-infrastructure) destroy=1 ;;
      *) die "usage: zasp uninstall --yes [--destroy-infrastructure]" ;;
    esac
  done
  require_yes "uninstall removes the Helm release '$AWS_RELEASE' from namespace '$AWS_NAMESPACE'."
  run "${AWS_HELM[@]}" uninstall "$AWS_RELEASE"
  if [ "$destroy" -eq 1 ]; then
    aws_require_file ZASP_AWS_TFVARS "your copy of deploy/production/example.tfvars"
    note "destroying the AWS resources: buckets, queues, keys, secrets, the cluster. The product database is not touched."
    # Terraform asks for its own confirmation before it destroys anything.
    run "${AWS_TERRAFORM[@]}" destroy "-var-file=$ZASP_AWS_TFVARS"
  else
    note "the AWS resources still exist and cost money (runbook, 'Resources that cost money'). To remove them: ./zasp uninstall --yes --destroy-infrastructure"
  fi
}
