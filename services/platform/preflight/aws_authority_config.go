package preflight

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/aws"
)

type AWSClusterTarget struct {
	Name       string `json:"name"`
	ARN        string `json:"arn"`
	VPCID      string `json:"vpc_id"`
	Issuer     string `json:"issuer"`
	Endpoint   string `json:"endpoint"`
	CASHA256   string `json:"ca_sha256"`
	ClusterUID string `json:"cluster_uid"`
}
type AWSRoleBinding struct {
	Purpose string `json:"purpose"`
	RoleARN string `json:"role_arn"`
}
type AWSSelectedWorkload struct {
	Purpose string `json:"purpose"`
	PodName string `json:"pod_name"`
	PodUID  string `json:"pod_uid"`
}
type AWSAuthorityConfig struct {
	Fargate    *AWSAttackLabTarget  `json:"fargate,omitempty"`
	Inspection CredentialConfig     `json:"inspection"`
	Cluster    AWSClusterTarget     `json:"cluster"`
	Roles      []AWSRoleBinding     `json:"roles"`
	Selected   *AWSSelectedWorkload `json:"selected,omitempty"`
}
type awsRoleRequirement struct{ purpose, subject, trustClass string }
type KubernetesServiceAccountBinding struct {
	Namespace, Name, UID, RoleARN string
	Deleting                      bool
}
type KubernetesWorkloadBinding struct {
	Namespace, Name, UID, ServiceAccount, Phase, ProjectedAudience string
	Deleting                                                       bool
}
type KubernetesIdentityReader interface {
	ClusterUID(context.Context) (string, error)
	ServiceAccount(context.Context, string, string) (KubernetesServiceAccountBinding, error)
	Pod(context.Context, string, string) (KubernetesWorkloadBinding, error)
}
type awsAuthorityEvidence struct {
	inspectionRelease                                          func()
	inspectionSDK                                              *aws.Config
	clusterSecurityGroupID                                     string
	requiredRoles, observedRoles, requiredTrust, observedTrust int
	inspectionAttempted                                        bool
	clusterVerified                                            bool
	selectedExchangeVerified, selectedSpecVerified             bool
}
