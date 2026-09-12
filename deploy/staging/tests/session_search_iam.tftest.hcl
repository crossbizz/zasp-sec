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
      }
    ])
    error_message = "All 14 work/DLQ instances must retain their explicit customer KMS keys, including separate red-team and attack-lab authority."
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
