# Provider remediations of the Security Agent (optional, off by default).
#
# Two Security Agent actions change a customer's AWS account after a person
# approved them: attach_bedrock_guardrail and detach_role_administrator_policy.
# The action worker performs them with an identity of its own, created here
# only when var.security_agent_remediation.enabled is true:
#
#   - it is assumed by the action worker's service account and by nothing else;
#   - it may assume exactly the customers' remediation roles listed in
#     customer_role_arns, never a role discovery reads with;
#   - it may read the AWS external ID reference secret, which the customer's
#     remediation role trusts, and nothing else.
#
# It has no permission in the customer's account of its own: what a
# remediation may change is the customer's remediation role's policy (see
# docs/operations/production-aws-runbook.md, step 16).
resource "aws_iam_role" "security_agent_remediation" {
  count = var.security_agent_remediation.enabled ? 1 : 0
  name  = "${var.cluster_name}-security-agent-remediation"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow", Principal = { Federated = aws_iam_openid_connect_provider.eks.arn }, Action = "sts:AssumeRoleWithWebIdentity"
      Condition = { StringEquals = {
        "${replace(aws_iam_openid_connect_provider.eks.url, "https://", "")}:aud" = "sts.amazonaws.com"
        "${replace(aws_iam_openid_connect_provider.eks.url, "https://", "")}:sub" = "system:serviceaccount:agentsec:zasp-security-agent-action"
      } }
    }]
  })
}

resource "aws_iam_role_policy" "security_agent_remediation" {
  count = var.security_agent_remediation.enabled ? 1 : 0
  name  = "${var.cluster_name}-security-agent-remediation"
  role  = aws_iam_role.security_agent_remediation[0].id
  policy = jsonencode({ Version = "2012-10-17", Statement = [
    { Effect = "Allow", Action = ["sts:AssumeRole"], Resource = sort(tolist(var.security_agent_remediation.customer_role_arns)) },
    { Effect = "Allow", Action = ["secretsmanager:GetSecretValue"], Resource = aws_secretsmanager_secret.connector_reference["aws_external_id"].arn },
    {
      Effect = "Allow", Action = ["kms:Decrypt"], Resource = aws_kms_key.connector_oauth.arn
      Condition = { StringEquals = {
        "kms:ViaService"                  = "secretsmanager.${var.region}.amazonaws.com"
        "kms:EncryptionContext:SecretARN" = aws_secretsmanager_secret.connector_reference["aws_external_id"].arn
      } }
    },
  ] })
}
