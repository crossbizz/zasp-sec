run "isolated_image_layer_network" {
  command = plan
  assert {
    condition     = aws_subnet.attack_lab[0].cidr_block == "10.80.32.0/20" && aws_subnet.attack_lab[1].cidr_block == "10.80.48.0/20"
    error_message = "Runner subnet derivation must be separate from product subnets."
  }
  assert {
    condition     = jsondecode(aws_vpc_endpoint.attack_lab_s3.policy).Statement[0].Resource == "arn:aws:s3:::prod-us-west-2-starport-layer-bucket/*" && jsondecode(aws_vpc_endpoint.attack_lab_s3.policy).Statement[0].Action == "s3:GetObject"
    error_message = "Runner S3 endpoint must permit only regional image layer reads."
  }
  assert {
    condition     = aws_vpc_security_group_egress_rule.attack_lab_runner_proxy.from_port == 8443 && aws_vpc_security_group_egress_rule.attack_lab_runner_proxy.to_port == 8443 && aws_vpc_security_group_egress_rule.attack_lab_runner_s3.from_port == 443 && aws_vpc_security_group_egress_rule.attack_lab_runner_dns_udp.from_port == 53
    error_message = "Planned runner ports must preserve the bounded contract."
  }
}

run "reject_product_subnet_overlap" {
  command = plan
  variables { attack_lab_subnet_cidrs = ["10.80.0.0/20", "10.80.48.0/20"] }
  expect_failures = [aws_subnet.attack_lab]
}

run "reject_runner_subnet_overlap" {
  command = plan
  variables { attack_lab_subnet_cidrs = ["10.80.32.0/20", "10.80.32.0/21"] }
  expect_failures = [aws_subnet.attack_lab]
}

run "reject_outside_vpc" {
  command = plan
  variables { attack_lab_subnet_cidrs = ["10.81.32.0/20", "10.80.48.0/20"] }
  expect_failures = [aws_subnet.attack_lab]
}

run "explicit_disjoint_subnets" {
  command = plan
  variables { attack_lab_subnet_cidrs = ["10.80.64.0/20", "10.80.80.0/20"] }
  assert {
    condition     = aws_subnet.attack_lab[0].cidr_block == "10.80.64.0/20"
    error_message = "Explicit isolated CIDRs must remain configurable."
  }
}
