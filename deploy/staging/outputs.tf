output "vpc_id" {
  value = aws_vpc.staging.id
}
output "private_subnet_ids" {
  value = aws_subnet.private[*].id
}
output "cluster_name" {
  value = aws_eks_cluster.staging.name
}
output "cluster_endpoint" {
  value     = aws_eks_cluster.staging.endpoint
  sensitive = true
}
output "bucket_name" {
  value = aws_s3_bucket.evidence.bucket
}
output "kms_key_arn" {
  value = aws_kms_key.staging.arn
}
output "secret_arns" {
  value = { for key, secret in aws_secretsmanager_secret.product : key => secret.arn }
}
output "queue_urls" {
  value = { for key, queue in aws_sqs_queue.work : key => queue.id }
}
output "dead_letter_queue_urls" {
  value = { for key, queue in aws_sqs_queue.dead_letter : key => queue.id }
}
output "opensearch_endpoint" {
  value     = aws_opensearch_domain.events.endpoint
  sensitive = true
}
output "api_role_arn" {
  value = aws_iam_role.api.arn
}
output "migration_role_arn" {
  value = aws_iam_role.migration.arn
}
output "canary_secret_sync_role_arn" {
  value = aws_iam_role.canary_secret_sync.arn
}
output "attack_lab_security_group_id" {
  value = aws_security_group.attack_lab.id
}
output "attack_lab_fargate_profile_arn" {
  value = aws_eks_fargate_profile.attack_lab.arn
}
