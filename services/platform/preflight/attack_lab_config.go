package preflight

type AWSAttackLabTarget struct {
	ProfileARN               string            `json:"profile_arn"`
	ExpectedCNIAddonVersion  string            `json:"expected_cni_addon_version"`
	SubnetIDs                []string          `json:"subnet_ids"`
	ProductSubnetIDs         []string          `json:"product_subnet_ids"`
	IsolatedRouteTableID     string            `json:"isolated_route_table_id"`
	RunnerSecurityGroupID    string            `json:"runner_security_group_id"`
	ProxySecurityGroupID     string            `json:"proxy_security_group_id"`
	ImagePullSecurityGroupID string            `json:"image_pull_security_group_id"`
	EndpointSecurityGroupID  string            `json:"endpoint_security_group_id"`
	RunnerBoundaryPolicyARN  string            `json:"runner_boundary_policy_arn"`
	ProxyCASHA256            string            `json:"proxy_ca_sha256"`
	EndpointIDs              map[string]string `json:"endpoint_ids"`
	TargetCIDRs              []string          `json:"target_cidrs"`
	DatabaseCIDRs            []string          `json:"database_cidrs"`
}
type attackLabEvidence struct {
	profile, namespace, runner, policy, topology                                              bool
	profileAttempted, namespaceAttempted, runnerAttempted, policyAttempted, topologyAttempted bool
	failures                                                                                  []Failure
}
type AttackLabConfigurationSummary struct {
	Profile               Observation `json:"profile"`
	Namespace             Observation `json:"namespace"`
	RunnerIdentity        Observation `json:"runner_identity"`
	SecurityGroupPolicies Observation `json:"security_group_policies"`
	TopologyMetadata      Observation `json:"topology_metadata"`
	NetworkEnforcement    string      `json:"network_enforcement"`
	CanaryAndCleanup      string      `json:"canary_and_cleanup"`
}
