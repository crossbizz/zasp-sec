# Evaluate the actual policy JSON with provider-owned values mocked at plan time.
# No AWS credentials, API calls, state backend, or apply are needed.
mock_provider "aws" {
  override_during = plan
  mock_resource "aws_opensearch_domain" {
    defaults = { arn = "arn:aws:es:us-west-2:000000000000:domain/session-search-test" }
  }
  mock_resource "aws_eks_cluster" {
    defaults = { identity = [{ oidc = [{ issuer = "https://oidc.eks.us-west-2.amazonaws.com/id/session-search-test" }] }] }
  }
  mock_resource "aws_secretsmanager_secret" {
    defaults = { arn = "arn:aws:secretsmanager:us-west-2:000000000000:secret:session-search-test" }
  }
  mock_resource "aws_kms_key" {
    defaults = { arn = "arn:aws:kms:us-west-2:000000000000:key/11111111-1111-4111-8111-111111111111" }
  }
  mock_resource "aws_s3_bucket" {
    defaults = { arn = "arn:aws:s3:::session-search-test" }
  }
  mock_resource "aws_sqs_queue" {
    defaults = { arn = "arn:aws:sqs:us-west-2:000000000000:session-search-test" }
  }
}
mock_provider "tls" {
  override_during = plan
  mock_data "tls_certificate" {
    defaults = { certificates = [{ sha1_fingerprint = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" }] }
  }
}

override_resource {
  target          = aws_iam_openid_connect_provider.eks
  override_during = plan
  values          = { arn = "arn:aws:iam::000000000000:oidc-provider/oidc.eks.us-west-2.amazonaws.com/id/session-search-test" }
}
override_resource {
  target          = aws_kms_key.staging
  override_during = plan
  values          = { arn = "arn:aws:kms:us-west-2:000000000000:key/11111111-1111-4111-8111-111111111111" }
}
override_resource {
  target          = aws_kms_key.red_team
  override_during = plan
  values          = { arn = "arn:aws:kms:us-west-2:000000000000:key/22222222-2222-4222-8222-222222222222" }
}
override_resource {
  target          = aws_kms_key.attack_lab
  override_during = plan
  values          = { arn = "arn:aws:kms:us-west-2:000000000000:key/33333333-3333-4333-8333-333333333333" }
}

override_resource {
  target          = aws_sqs_queue.work["audit-exports"]
  override_during = plan
  values          = { arn = "arn:aws:sqs:us-west-2:000000000000:agentsec-audit-exports", id = "https://sqs.us-west-2.amazonaws.com/000000000000/agentsec-audit-exports" }
}
override_resource {
  target          = aws_sqs_queue.dead_letter["audit-exports"]
  override_during = plan
  values          = { arn = "arn:aws:sqs:us-west-2:000000000000:agentsec-audit-exports-dlq" }
}

override_resource {
  target          = aws_iam_role.api
  override_during = plan
  values          = { id = "owned-api-role" }
}
override_resource {
  target          = aws_iam_role.audit_exports["writer"]
  override_during = plan
  values          = { id = "owned-export-writer-role", arn = "arn:aws:iam::000000000000:role/owned-export-writer-role" }
}
override_resource {
  target          = aws_iam_role.audit_exports["publisher"]
  override_during = plan
  values          = { id = "owned-export-publisher-role", arn = "arn:aws:iam::000000000000:role/owned-export-publisher-role" }
}
override_resource {
  target          = aws_iam_role.audit_exports["reader"]
  override_during = plan
  values          = { arn = "arn:aws:iam::000000000000:role/owned-export-reader-role" }
}
override_resource {
  target          = aws_secretsmanager_secret.audit_exports["postgres-audit-export-worker-dsn"]
  override_during = plan
  values          = { arn = "arn:aws:secretsmanager:us-west-2:000000000000:secret:export-worker-owned" }
}
override_resource {
  target          = aws_secretsmanager_secret.audit_exports["postgres-audit-export-outbox-dsn"]
  override_during = plan
  values          = { arn = "arn:aws:secretsmanager:us-west-2:000000000000:secret:export-outbox-owned" }
}
override_resource {
  target          = aws_secretsmanager_secret.audit_exports["audit-export-cursor-signing-key"]
  override_during = plan
  values          = { arn = "arn:aws:secretsmanager:us-west-2:000000000000:secret:export-cursor-owned" }
}

run "audit_export_secret_metadata_and_access" {
  command = plan
  assert {
    condition     = toset(keys(output.audit_export_deployment_metadata)) == toset(["role_arns", "secret_arns", "database_principals", "queue_url", "bucket", "expected_bucket_owner", "kms_key_arn", "web_identity_token_file"])
    error_message = "Deployment output must contain only the exact non-secret identifiers needed to configure export workloads."
  }
  assert {
    condition = (toset(keys(output.audit_export_deployment_metadata.role_arns)) == toset(["reader", "writer", "publisher"]) &&
      output.audit_export_deployment_metadata.role_arns == { for name, role in aws_iam_role.audit_exports : name => role.arn } &&
      output.audit_export_deployment_metadata.queue_url == aws_sqs_queue.work["audit-exports"].id &&
      output.audit_export_deployment_metadata.secret_arns == { for name, secret in aws_secretsmanager_secret.audit_exports : name => secret.arn } &&
      output.audit_export_deployment_metadata.database_principals == var.audit_export_database_principals &&
      output.audit_export_deployment_metadata.bucket == aws_s3_bucket.evidence.bucket &&
      output.audit_export_deployment_metadata.expected_bucket_owner == var.account_id &&
      output.audit_export_deployment_metadata.kms_key_arn == aws_kms_key.staging.arn &&
    output.audit_export_deployment_metadata.web_identity_token_file == "/var/run/secrets/eks.amazonaws.com/serviceaccount/token")
    error_message = "Export deployment metadata must preserve the exact provisioned references and projected token path."
  }
  assert {
    condition = (toset(keys(aws_secretsmanager_secret.audit_exports)) == toset(["postgres-audit-export-worker-dsn", "postgres-audit-export-outbox-dsn", "audit-export-cursor-signing-key"]) &&
    toset(keys(aws_iam_role_policy.audit_export_secrets)) == toset(keys(aws_secretsmanager_secret.audit_exports)))
    error_message = "Export deployment needs exactly two dedicated DSN metadata records and one cursor-key record."
  }
  assert {
    condition = alltrue([for name, binding in {
      postgres-audit-export-worker-dsn = { principal = var.audit_export_database_principals.worker, role = try(aws_iam_role.audit_exports["writer"].id, "missing") }
      postgres-audit-export-outbox-dsn = { principal = var.audit_export_database_principals.outbox, role = try(aws_iam_role.audit_exports["publisher"].id, "missing") }
      audit-export-cursor-signing-key  = { principal = "", role = aws_iam_role.api.id }
      } : try(
      aws_secretsmanager_secret.audit_exports[name].name == "${var.cluster_name}/${name}" &&
      aws_secretsmanager_secret.audit_exports[name].kms_key_id == aws_kms_key.staging.arn &&
      aws_secretsmanager_secret.audit_exports[name].recovery_window_in_days == 30 &&
      try(aws_secretsmanager_secret.audit_exports[name].tags.DatabasePrincipal, "") == binding.principal &&
      aws_iam_role_policy.audit_export_secrets[name].role == binding.role &&
      jsondecode(aws_iam_role_policy.audit_export_secrets[name].policy) == {
        Version = "2012-10-17"
        Statement = [
          { Effect = "Allow", Action = ["secretsmanager:DescribeSecret", "secretsmanager:GetSecretValue"], Resource = aws_secretsmanager_secret.audit_exports[name].arn },
          { Effect = "Allow", Action = ["kms:Decrypt"], Resource = aws_kms_key.staging.arn, Condition = { StringEquals = {
            "kms:ViaService"                  = "secretsmanager.${var.region}.amazonaws.com"
            "kms:EncryptionContext:SecretARN" = aws_secretsmanager_secret.audit_exports[name].arn
          } } }
        ]
    }, false)])
    error_message = "Each runtime must access only its own encrypted export secret with an exact SecretARN context."
  }
}

run "audit_export_rejects_reused_principals" {
  command = plan
  variables { audit_export_database_principals = { worker = "zasp_api_runtime", outbox = "zasp_api_runtime" } }
  expect_failures = [var.audit_export_database_principals]
}

run "audit_export_rejects_capability_principals" {
  command = plan
  variables { audit_export_database_principals = { worker = "zasp_audit_export_worker", outbox = "zasp_audit_export_outbox" } }
  expect_failures = [var.audit_export_database_principals]
}

run "audit_export_rejects_duplicate_new_principals" {
  command = plan
  variables { audit_export_database_principals = { worker = "owned_export_login", outbox = "owned_export_login" } }
  expect_failures = [var.audit_export_database_principals]
}

run "audit_export_rejects_malformed_principals" {
  command = plan
  variables { audit_export_database_principals = { worker = "Uppercase", outbox = "a" } }
  expect_failures = [var.audit_export_database_principals]
}

run "audit_export_rejects_oversized_principals" {
  command = plan
  variables { audit_export_database_principals = { worker = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", outbox = "owned_outbox" } }
  expect_failures = [var.audit_export_database_principals]
}

run "audit_export_rejects_existing_distinct_principal" {
  command = plan
  variables { audit_export_database_principals = { worker = "zasp_api_runtime", outbox = "owned_outbox" } }
  expect_failures = [var.audit_export_database_principals]
}

run "audit_export_roles_have_exact_authority" {
  command = plan
  assert {
    condition     = alltrue([for rule in aws_s3_bucket_server_side_encryption_configuration.evidence.rule : rule.bucket_key_enabled])
    error_message = "Export bucket-ARN KMS context requires the existing S3 Bucket Keys configuration."
  }
  assert {
    condition = alltrue([for name, expected_sids in {
      reader    = ["ReadExportVersions", "ExportBucketKey"]
      writer    = ["ReadExportVersions", "WriteEncryptedExports", "ExportBucketKey", "ExportQueue", "ExportQueueKey"]
      publisher = ["ExportQueue", "ExportQueueKey"]
      } : try(
      length(jsondecode(aws_iam_role_policy.audit_exports[name].policy).Statement) == length(expected_sids) &&
      toset([for statement in jsondecode(aws_iam_role_policy.audit_exports[name].policy).Statement : statement.Sid]) == toset(expected_sids) &&
      alltrue([for statement in jsondecode(aws_iam_role_policy.audit_exports[name].policy).Statement :
        statement.Effect == "Allow" && toset(statement.Action) == {
          ReadExportVersions    = toset(["s3:GetObject", "s3:GetObjectVersion"])
          WriteEncryptedExports = toset(["s3:PutObject"])
          ExportBucketKey       = toset(concat(["kms:Decrypt"], name == "writer" ? ["kms:GenerateDataKey"] : []))
          ExportQueue           = toset(concat(["sqs:GetQueueAttributes"], name == "writer" ? ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:ChangeMessageVisibility"] : ["sqs:SendMessage"]))
          ExportQueueKey        = toset(concat(["kms:Decrypt"], name == "publisher" ? ["kms:GenerateDataKey"] : []))
          }[statement.Sid] && jsonencode(try(statement.Condition, {})) == {
          ReadExportVersions = jsonencode({})
          ExportQueue        = jsonencode({})
          WriteEncryptedExports = jsonencode({ StringEquals = {
            "s3:x-amz-server-side-encryption"                = "aws:kms"
            "s3:x-amz-server-side-encryption-aws-kms-key-id" = aws_kms_key.staging.arn
          } })
          ExportBucketKey = jsonencode({ StringEquals = {
            "kms:ViaService"                   = "s3.${var.region}.amazonaws.com"
            "kms:EncryptionContext:aws:s3:arn" = aws_s3_bucket.evidence.arn
          } })
          ExportQueueKey = jsonencode({ StringEquals = {
            "kms:ViaService"                    = "sqs.${var.region}.amazonaws.com"
            "kms:EncryptionContext:aws:sqs:arn" = aws_sqs_queue.work["audit-exports"].arn
          } })
        }[statement.Sid]
    ]), false)])
    error_message = "Export grants must retain exact encryption and service/context conditions without duplicate or unexpected statements."
  }
  assert {
    condition     = toset(keys(aws_iam_role.audit_exports)) == toset(["reader", "writer", "publisher"])
    error_message = "Audit exports require three distinct purpose-bound provider roles."
  }
  assert {
    condition = alltrue([for name, subject in {
      reader = "agentsec-api", writer = "zasp-audit-export-worker", publisher = "zasp-audit-export-outbox"
      } : try(jsondecode(aws_iam_role.audit_exports[name].assume_role_policy) == {
        Version = "2012-10-17"
        Statement = [{
          Effect    = "Allow"
          Principal = { Federated = aws_iam_openid_connect_provider.eks.arn }
          Action    = "sts:AssumeRoleWithWebIdentity"
          Condition = { StringEquals = {
            "${replace(aws_iam_openid_connect_provider.eks.url, "https://", "")}:aud" = "sts.amazonaws.com"
            "${replace(aws_iam_openid_connect_provider.eks.url, "https://", "")}:sub" = "system:serviceaccount:agentsec:${subject}"
          } }
        }]
    }, false)])
    error_message = "Each role must trust only its exact workload subject and STS audience."
  }
  assert {
    condition = alltrue([for name in ["reader", "writer", "publisher"] : try(
      toset(flatten([for statement in jsondecode(aws_iam_role_policy.audit_exports[name].policy).Statement : [
        for action in statement.Action : "${action} ${statement.Resource}"
        ]])) == toset(concat(
        name == "publisher" ? [] : [for action in concat(["s3:GetObject", "s3:GetObjectVersion"], name == "writer" ? ["s3:PutObject"] : []) : "${action} ${aws_s3_bucket.evidence.arn}/organizations/*/workspaces/*/environments/*/exports/*"],
        name == "reader" ? [] : [for action in concat(["sqs:GetQueueAttributes"], name == "writer" ? ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:ChangeMessageVisibility"] : ["sqs:SendMessage"]) : "${action} ${aws_sqs_queue.work["audit-exports"].arn}"],
        [for action in concat(["kms:Decrypt"], name == "reader" ? [] : ["kms:GenerateDataKey"]) : "${action} ${aws_kms_key.staging.arn}"]
    )), false)])
    error_message = "Role action/resource pairs must be closed: no list, object deletion, wildcard action, foreign prefix or mixed publisher/consumer authority."
  }
}

run "audit_export_queue_is_dedicated_and_bounded" {
  command = plan
  assert {
    condition = { for name, contract in local.queue_contract : name => contract if name != "audit-exports" } == {
      background            = { visibility = 300, max_receive = 5, schema = "agentsec.background.v1" }
      discovery-jobs        = { visibility = 30, max_receive = 5, schema = "agentsec.discovery-jobs.v1" }
      runtime-events        = { visibility = 120, max_receive = 5, schema = "agentsec.runtime-events.v1" }
      red-team-tests        = { visibility = 900, max_receive = 5, schema = "agentsec.red-team-tests.v1" }
      attack-lab-jobs       = { visibility = 60, max_receive = 5, schema = "agentsec.attack-lab-jobs.v1" }
      recovery-backup-jobs  = { visibility = 30, max_receive = 100, schema = "agentsec.recovery-backup-jobs.v1" }
      recovery-restore-jobs = { visibility = 30, max_receive = 100, schema = "agentsec.recovery-restore-jobs.v1" }
    }
    error_message = "The seven predecessor queue contracts must remain unchanged."
  }
  assert {
    condition = try(
      aws_sqs_queue.work["audit-exports"].name == "agentsec-audit-exports" &&
      aws_sqs_queue.dead_letter["audit-exports"].name == "agentsec-audit-exports-dlq" &&
      aws_sqs_queue.work["audit-exports"].visibility_timeout_seconds == 300 &&
      aws_sqs_queue.work["audit-exports"].message_retention_seconds == 345600 &&
      aws_sqs_queue.dead_letter["audit-exports"].message_retention_seconds == 1209600 &&
      aws_sqs_queue.work["audit-exports"].receive_wait_time_seconds == 20 &&
      aws_sqs_queue.work["audit-exports"].max_message_size == 262144 &&
      aws_sqs_queue.work["audit-exports"].tags.Schema == "agentsec.audit-exports.v1" &&
      jsondecode(aws_sqs_queue.work["audit-exports"].redrive_policy).maxReceiveCount == 20 &&
      jsondecode(aws_sqs_queue.work["audit-exports"].redrive_policy).deadLetterTargetArn == aws_sqs_queue.dead_letter["audit-exports"].arn &&
      jsondecode(aws_sqs_queue_redrive_allow_policy.dead_letter["audit-exports"].redrive_allow_policy) == {
        redrivePermission = "byQueue"
        sourceQueueArns   = [aws_sqs_queue.work["audit-exports"].arn]
    }, false)
    error_message = "Audit exports need a dedicated bounded queue/DLQ with twenty deliveries, independently of the five-attempt job execution budget."
  }
}

run "all_work_and_dead_letter_queues_keep_customer_keys" {
  command = plan
  assert {
    condition = alltrue([
      for queues in [aws_sqs_queue.work, aws_sqs_queue.dead_letter] :
      { for name, queue in queues : name => queue.kms_master_key_id } == {
        background            = "arn:aws:kms:us-west-2:000000000000:key/11111111-1111-4111-8111-111111111111"
        discovery-jobs        = "arn:aws:kms:us-west-2:000000000000:key/11111111-1111-4111-8111-111111111111"
        runtime-events        = "arn:aws:kms:us-west-2:000000000000:key/11111111-1111-4111-8111-111111111111"
        red-team-tests        = "arn:aws:kms:us-west-2:000000000000:key/22222222-2222-4222-8222-222222222222"
        attack-lab-jobs       = "arn:aws:kms:us-west-2:000000000000:key/33333333-3333-4333-8333-333333333333"
        recovery-backup-jobs  = "arn:aws:kms:us-west-2:000000000000:key/11111111-1111-4111-8111-111111111111"
        recovery-restore-jobs = "arn:aws:kms:us-west-2:000000000000:key/11111111-1111-4111-8111-111111111111"
        audit-exports         = "arn:aws:kms:us-west-2:000000000000:key/11111111-1111-4111-8111-111111111111"
      }
    ])
    error_message = "All 16 work/DLQ instances must retain their explicit customer KMS keys, including separate red-team and attack-lab authority."
  }
}

run "session_search_exact_method_path_authority" {
  command = plan

  # These are the complete existing OpenSearch grants plus the closed v2
  # additions, not just a filter for resources whose name happens to contain v2.
  # Comparing all ES action/resource pairs also catches domain wildcards,
  # cross-product method broadening, and accidental removal of v1 access.
  assert {
    condition = toset(flatten([
      for statement in jsondecode(aws_iam_role_policy.runtime["index"].policy).Statement : [
        for action in statement.Action : [
          for resource in try(tolist(statement.Resource), [statement.Resource]) : "${action} ${resource}"
        ] if startswith(lower(action), "es:") || action == "*"
      ]
      ])) == toset(concat(
      [for action in ["es:ESHttpGet", "es:ESHttpPost", "es:ESHttpPut"] : "${action} arn:aws:es:us-west-2:000000000000:domain/session-search-test/zasp-runtime-events-v1/*"],
      flatten([for version in [1, 2] : concat(
        [for path in ["_mapping", "_doc/_zasp_session_schema_v${version}"] : "es:ESHttpGet arn:aws:es:us-west-2:000000000000:domain/session-search-test/zasp-runtime-sessions-v${version}/${path}"],
        [for path in ["_bulk", "_mget", "_refresh"] : "es:ESHttpPost arn:aws:es:us-west-2:000000000000:domain/session-search-test/zasp-runtime-sessions-v${version}/${path}"]
      )])
    ))
    error_message = "Runtime index must retain v1 and have only v2 mapping/marker GET plus bulk/mget/refresh POST; no search, PUT, DELETE, or wildcard expansion."
  }

  assert {
    condition = toset(flatten([
      for statement in jsondecode(aws_iam_role_policy.api_connectors.policy).Statement : [
        for action in statement.Action : [
          for resource in try(tolist(statement.Resource), [statement.Resource]) : "${action} ${resource}"
        ] if startswith(lower(action), "es:") || action == "*"
      ]
      ])) == toset(concat(
      [for path in ["_mapping", "_doc/_zasp_schema_v1"] : "es:ESHttpGet arn:aws:es:us-west-2:000000000000:domain/session-search-test/zasp-runtime-events-v1/${path}"],
      ["es:ESHttpPost arn:aws:es:us-west-2:000000000000:domain/session-search-test/zasp-runtime-events-v1/_search"],
      flatten([for version in [1, 2] : concat(
        [for path in ["_mapping", "_doc/_zasp_session_schema_v${version}"] : "es:ESHttpGet arn:aws:es:us-west-2:000000000000:domain/session-search-test/zasp-runtime-sessions-v${version}/${path}"],
        ["es:ESHttpPost arn:aws:es:us-west-2:000000000000:domain/session-search-test/zasp-runtime-sessions-v${version}/_search"]
      )])
    ))
    error_message = "API must retain v1 and have only v2 mapping/marker GET and search POST; it cannot write or use bulk/mget/refresh."
  }

  assert {
    condition = toset(flatten([
      for statement in jsondecode(aws_iam_role_policy.projection_search_init.policy).Statement : [
        for action in statement.Action : [
          for resource in try(tolist(statement.Resource), [statement.Resource]) : "${action} ${resource}"
        ] if startswith(lower(action), "es:") || action == "*"
      ]
      ])) == toset(concat(
      flatten([for index in ["zasp-inventory-v1", "zasp-runtime-events-v1"] : concat(
        [for path in ["_mapping", "_doc/_zasp_schema_v1"] : "es:ESHttpGet arn:aws:es:us-west-2:000000000000:domain/session-search-test/${index}/${path}"],
        [for path in ["", "/_doc/_zasp_schema_v1"] : "es:ESHttpPut arn:aws:es:us-west-2:000000000000:domain/session-search-test/${index}${path}"]
      )]),
      flatten([for version in [1, 2] : concat(
        [for path in ["_mapping", "_doc/_zasp_session_schema_v${version}"] : "es:ESHttpGet arn:aws:es:us-west-2:000000000000:domain/session-search-test/zasp-runtime-sessions-v${version}/${path}"],
        [for path in ["", "/_doc/_zasp_session_schema_v${version}"] : "es:ESHttpPut arn:aws:es:us-west-2:000000000000:domain/session-search-test/zasp-runtime-sessions-v${version}${path}"]
      )])
    ))
    error_message = "Initializer must retain v1 and have only v2 mapping/marker GET plus exact index/marker PUT; no document wildcard, DELETE, or POST."
  }

  assert {
    condition = alltrue(flatten([
      for policy in [aws_iam_role_policy.runtime["index"].policy, aws_iam_role_policy.api_connectors.policy, aws_iam_role_policy.projection_search_init.policy] : [
        for statement in jsondecode(policy).Statement : statement.Effect == "Allow" && !contains(keys(statement), "NotAction") && !contains(keys(statement), "NotResource")
      ]
    ]))
    error_message = "The closed action/resource comparison requires positive Allow statements; negated or deny policy changes require explicit review."
  }

  assert {
    condition = alltrue(flatten([
      for name, policy in aws_iam_role_policy.runtime : [
        for statement in jsondecode(policy.policy).Statement : alltrue([
          for action in statement.Action : !startswith(lower(action), "es:") && action != "*"
        ])
      ] if name != "index"
    ]))
    error_message = "Session search grants must not leak to another runtime worker."
  }

}
