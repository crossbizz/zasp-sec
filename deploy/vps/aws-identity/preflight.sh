# Run inside the AWS CLI container. Only the four non-secret STS response fields
# reach the shell. Keep provider errors out of pod logs, including under failures.
set -eu
identity=$(aws --region "$AWS_REGION" --endpoint-url "https://sts.$AWS_REGION.amazonaws.com" \
  --no-sign-request --no-cli-pager --cli-connect-timeout 5 --cli-read-timeout 10 \
  sts assume-role-with-web-identity --role-arn "$ROLE_ARN" --role-session-name "$SESSION_NAME" \
  --web-identity-token "file://$PROJECTED_TOKEN" --duration-seconds 900 \
  --policy '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}' \
  --query '[AssumedRoleUser.Arn,SubjectFromWebIdentityToken,Audience,Provider]' --output text 2>/dev/null) || {
  echo 'Regional STS refused the workload token or could not be reached.' >&2
  exit 1
}
tab=$(printf '\t')
expected="$EXPECTED_ARN$tab$EXPECTED_SUBJECT${tab}sts.amazonaws.com$tab$EXPECTED_ISSUER"
# STS can return the IAM OIDC provider ARN as its Provider representation.
expected_provider="$EXPECTED_ARN$tab$EXPECTED_SUBJECT${tab}sts.amazonaws.com$tab$EXPECTED_PROVIDER_ARN"
if [ "$identity" != "$expected" ] && [ "$identity" != "$expected_provider" ]; then
  echo 'STS reported an unexpected role, subject, audience or issuer.' >&2
  exit 1
fi
echo 'AWS verified the workload identity.'
