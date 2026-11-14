#!/bin/bash
# Creates the AWS resources the API and the workers address, in the pod's
# LocalStack. LocalStack runs this script each time it becomes ready
# (/etc/localstack/init/ready.d), because it keeps nothing across a restart.
#
# It mirrors provision_local_cloud and provision_customer_account in
# deploy/local/real-stack/stack.sh. Keep the two in step. The account is
# LocalStack's fixed 000000000000. Nothing here is a real AWS resource.
set -euo pipefail

RUN=/run/zasp
aws="awslocal --region us-east-1"
fail() { echo "zasp cloud provisioning: $*" >&2; exit 1; }

# The discovery worker reads the key ARN from this file. It is removed first
# so that the pod never pairs a new emulator with an old key.
rm -f "$RUN/cloud.env"

# The discovery queue must redrive to its dead-letter queue after five receives.
$aws sqs create-queue --queue-name agentsec-discovery-jobs-dlq >/dev/null || fail "discovery dead-letter queue was not created"
$aws sqs create-queue --queue-name agentsec-discovery-jobs >/dev/null || fail "discovery queue was not created"
$aws sqs set-queue-attributes --queue-url http://sqs.us-east-1.localhost.localstack.cloud:4566/000000000000/agentsec-discovery-jobs \
  --attributes '{"RedrivePolicy":"{\"deadLetterTargetArn\":\"arn:aws:sqs:us-east-1:000000000000:agentsec-discovery-jobs-dlq\",\"maxReceiveCount\":\"5\"}"}' || fail "discovery queue redrive policy was not set"

# The discovery worker's readiness probe requires a versioned evidence bucket
# whose default encryption is a customer-managed key.
$aws s3api head-bucket --bucket zasp-real-stack-evidence >/dev/null 2>&1 || $aws s3api create-bucket --bucket zasp-real-stack-evidence >/dev/null || fail "evidence bucket was not created"
key="$($aws kms create-key --description zasp-evidence --query KeyMetadata.KeyId --output text)" || fail "evidence key was not created"
[[ "$key" =~ ^[0-9a-f-]{36}$ ]] || fail "evidence key was not created"
key_arn="arn:aws:kms:us-east-1:000000000000:key/$key"
$aws s3api put-bucket-versioning --bucket zasp-real-stack-evidence --versioning-configuration Status=Enabled || fail "evidence bucket versioning was not set"
$aws s3api put-bucket-encryption --bucket zasp-real-stack-evidence --server-side-encryption-configuration \
  "{\"Rules\":[{\"ApplyServerSideEncryptionByDefault\":{\"SSEAlgorithm\":\"aws:kms\",\"KMSMasterKeyID\":\"$key_arn\"},\"BucketKeyEnabled\":true}]}" || fail "evidence bucket encryption was not set"

# Stores a secret, replacing its value when it exists.
put_secret() {
  if $aws secretsmanager describe-secret --secret-id "$1" >/dev/null 2>&1; then
    $aws secretsmanager put-secret-value --secret-id "$1" --secret-string "$2" >/dev/null || fail "secret $1 was not updated"
  else
    $aws secretsmanager create-secret --name "$1" --secret-string "$2" >/dev/null || fail "secret $1 was not created"
  fi
}

# Provider credentials the discovery worker must be able to resolve. These
# are placeholders: no GitHub App or Okta application stands behind them.
put_secret zasp-real-stack/discovery/github/app-private-key "placeholder-not-a-credential"
put_secret zasp-real-stack/discovery/okta/client-secret "placeholder-not-a-credential"

# The graph database credentials, in the form the workers read.
put_secret zasp-real-stack/projection/neo4j/auth/graph-schema "{\"scheme\":\"basic\",\"principal\":\"neo4j\",\"credentials\":\"$NEO4J_ADMIN_PASSWORD\"}"
put_secret zasp-real-stack/projection/neo4j/auth/graph-worker "{\"scheme\":\"basic\",\"principal\":\"zasp_graph_worker\",\"credentials\":\"$NEO4J_WORKER_PASSWORD\"}"

# The emulated customer side of an AWS integration: the read-only role the
# product assumes with an external ID, and that external ID as the secret
# both the API and the discovery worker resolve from
# ref:aws/external-id/localstack-dev-0001.
[ "${#AWS_EXTERNAL_ID}" -eq 48 ] || fail "the external ID must be 48 characters (see values.yaml, secrets.awsExternalId)"
put_secret zasp-real-stack/connectors/aws/external-id/localstack-dev-0001 "$AWS_EXTERNAL_ID"
put_secret zasp-real-stack/discovery/aws/external-id/localstack-dev-0001 "$AWS_EXTERNAL_ID"

ensure_role() {
  $aws iam get-role --role-name "$2" >/dev/null 2>&1 ||
    $aws iam create-role --path "$1" --role-name "$2" --assume-role-policy-document "$3" >/dev/null || fail "role $2 was not created"
}
ensure_attached_policy() {
  local arn="arn:aws:iam::000000000000:policy/$1"
  $aws iam get-policy --policy-arn "$arn" >/dev/null 2>&1 ||
    $aws iam create-policy --policy-name "$1" --policy-document "$2" >/dev/null || fail "policy $1 was not created"
  $aws iam attach-role-policy --role-name "$3" --policy-arn "$arn" || fail "policy $1 was not attached to $3"
}

ensure_role /zasp-reference/ customer-read "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"AWS\":[\"arn:aws:iam::000000000000:role/zasp-real-stack-api-connectors\",\"arn:aws:iam::000000000000:role/zasp-real-stack-discovery\"]},\"Action\":\"sts:AssumeRole\",\"Condition\":{\"StringEquals\":{\"sts:ExternalId\":\"$AWS_EXTERNAL_ID\"}}}]}"
ensure_attached_policy zasp-customer-read-inventory '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["iam:ListRoles","iam:ListAttachedRolePolicies","iam:GetPolicy","iam:GetPolicyVersion","ec2:DescribeRegions","ec2:DescribeInstances","bedrock:ListAgents","bedrock:GetAgent","bedrock-agentcore:ListAgentRuntimes","bedrock-agentcore:GetAgentRuntime","bedrock-agentcore:ListGateways","lambda:ListFunctions","iam:GetRole","cloudtrail:LookupEvents","route53resolver:ListResolverQueryLogConfigs","ec2:DescribeFlowLogs","logs:StartQuery","logs:GetQueryResults"],"Resource":"*"}]}' customer-read

# A small fixture for a first sync to find: three roles an agent workload
# would run under, one of them with administrator access, one instance that
# still allows IMDSv1, and one Lambda function that looks like an agent.
ensure_role /agents/ agent-orchestrator '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"bedrock.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
ensure_role /agents/ support-copilot-runtime '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ecs-tasks.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
ensure_role /agents/ claims-triage-agent '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"},{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::000000000000:role/agents/agent-orchestrator"},"Action":"sts:AssumeRole"}]}'
ensure_attached_policy agent-orchestrator-delegate '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sts:AssumeRole","Resource":"arn:aws:iam::000000000000:role/agents/claims-triage-agent"},{"Effect":"Allow","Action":["bedrock:InvokeAgent","bedrock:InvokeModel"],"Resource":"*"}]}' agent-orchestrator
$aws iam attach-role-policy --role-name agent-orchestrator --policy-arn arn:aws:iam::aws:policy/AdministratorAccess || fail "AdministratorAccess was not attached to agent-orchestrator"
ensure_attached_policy support-copilot-model-invoke '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["bedrock:InvokeModel","bedrock:InvokeModelWithResponseStream"],"Resource":"arn:aws:bedrock:us-east-1::foundation-model/*"}]}' support-copilot-runtime
ensure_attached_policy support-copilot-knowledge-read '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject","s3:ListBucket"],"Resource":["arn:aws:s3:::support-knowledge-base","arn:aws:s3:::support-knowledge-base/*"]}]}' support-copilot-runtime
ensure_attached_policy claims-triage-tools '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["dynamodb:GetItem","dynamodb:Query","sqs:SendMessage","secretsmanager:GetSecretValue"],"Resource":"*"}]}' claims-triage-agent
if [ "$($aws ec2 describe-instances --filters Name=tag:zasp-fixture,Values=agent-host Name=instance-state-name,Values=pending,running --query 'length(Reservations)' --output text)" = "0" ]; then
  image="$($aws ec2 describe-images --query 'Images[0].ImageId' --output text)" || fail "fixture image was not found"
  $aws ec2 run-instances --image-id "$image" --instance-type t3.micro --count 1 --metadata-options HttpTokens=optional,HttpEndpoint=enabled \
    --tag-specifications 'ResourceType=instance,Tags=[{Key=zasp-fixture,Value=agent-host},{Key=Name,Value=support-copilot-host}]' >/dev/null || fail "fixture instance was not created"
fi
if ! $aws lambda get-function --function-name support-copilot-handler >/dev/null 2>&1; then
  staged="$(mktemp -d)"
  printf 'def handler(event, context):\n    return {}\n' > "$staged/index.py"
  (cd "$staged" && python3 -c 'import zipfile; zipfile.ZipFile("function.zip", "w").write("index.py")')
  $aws lambda create-function --function-name support-copilot-handler --runtime python3.12 --handler index.handler \
    --role arn:aws:iam::000000000000:role/agents/support-copilot-runtime --zip-file "fileb://$staged/function.zip" \
    --environment "Variables={OPENAI_API_KEY=placeholder-not-a-credential}" >/dev/null || fail "fixture function was not created"
  rm -rf "$staged"
fi

# Written last: its presence tells the pod that provisioning completed.
printf 'ZASP_EVIDENCE_KMS_KEY_ARN=%s\n' "$key_arn" > "$RUN/cloud.env.partial"
chmod 644 "$RUN/cloud.env.partial"
mv -f "$RUN/cloud.env.partial" "$RUN/cloud.env"
echo "zasp cloud provisioning: complete"
