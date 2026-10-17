// Package preflight observes configured installation prerequisites. Read-only
// observations never certify deployed end-to-end behavior or mutation authority.
package preflight

import (
	"errors"
	"github.com/zasp-ai/zasp-sec/services/platform/sensoradapter"
	"net/http"
	"time"
)

var ErrRejected = errors.New("preflight prerequisites unavailable")

type Deployment struct {
	AccountID      string `json:"account_id"`
	Region         string `json:"region"`
	Partition      string `json:"partition"`
	Profile        string `json:"profile"`
	ReleaseVersion string `json:"release_version"`
}
type Scope struct {
	OrganizationID string `json:"organization_id"`
	WorkspaceID    string `json:"workspace_id"`
	EnvironmentID  string `json:"environment_id"`
}
type CredentialConfig struct {
	Kind            string `json:"kind"`
	ExpectedRoleARN string `json:"expected_role_arn"`
	File            string `json:"file,omitempty"`
	TokenFile       string `json:"token_file,omitempty"`
	Namespace       string `json:"namespace,omitempty"`
	ServiceAccount  string `json:"service_account,omitempty"`
}
type Features struct {
	AttackLab  string `json:"attack_lab"`
	SensorMode string `json:"sensor_mode"`
}
type Bucket struct {
	Name      string `json:"name"`
	Owner     string `json:"owner"`
	Region    string `json:"region"`
	KMSKeyARN string `json:"kms_key_arn"`
	Class     string `json:"class"`
}
type Secret struct {
	LogicalName string `json:"logical_name"`
	ARN         string `json:"arn"`
}
type Queue struct {
	URL                 string `json:"url"`
	ARN                 string `json:"arn"`
	DeadLetterURL       string `json:"dead_letter_url"`
	DeadLetterARN       string `json:"dead_letter_arn"`
	MaximumReceiveCount int    `json:"maximum_receive_count"`
	KMSKeyARN           string `json:"kms_key_arn"`
	Purpose             string `json:"purpose"`
}
type AWSConfig struct {
	Buckets []Bucket `json:"buckets"`
	Secrets []Secret `json:"secrets"`
	Queues  []Queue  `json:"queues"`
}
type Config struct {
	AWSAuthority *AWSAuthorityConfig                  `json:"aws_authority,omitempty"`
	Neon         *NeonConfig                          `json:"neon,omitempty"`
	Stytch       *StytchConfig                        `json:"stytch,omitempty"`
	Schema       string                               `json:"schema"`
	Deployment   Deployment                           `json:"deployment"`
	Scope        Scope                                `json:"scope"`
	Credentials  CredentialConfig                     `json:"credentials"`
	Features     Features                             `json:"features"`
	AWS          AWSConfig                            `json:"aws"`
	Kubernetes   *KubernetesAuthority                 `json:"kubernetes,omitempty"`
	Sensor       *sensoradapter.NodeCoverageSelection `json:"sensor,omitempty"`
}
type Failure struct {
	Operation    string `json:"operation"`
	Hint         string `json:"hint"`
	TargetDigest string `json:"target_digest"`
	Outcome      string `json:"outcome"`
}

type Observation struct {
	Failures     []Failure  `json:"failures,omitempty"`
	Name         string     `json:"name"`
	Status       string     `json:"status"`
	Kind         string     `json:"kind"`
	Code         string     `json:"code"`
	ObservedAt   *time.Time `json:"observed_at,omitempty"`
	TargetDigest string     `json:"target_digest,omitempty"`
	IdentityKind string     `json:"identity_kind"`
}
type Check struct {
	Name         string        `json:"name"`
	Status       string        `json:"status"`
	Required     bool          `json:"required"`
	Hint         string        `json:"hint"`
	Observations []Observation `json:"observations"`
}
type AWSAuthoritySummary struct {
	RequiredRoles                  int  `json:"required_roles"`
	ObservedRoles                  int  `json:"observed_roles"`
	RequiredTrust                  int  `json:"required_trust"`
	ObservedTrust                  int  `json:"observed_trust"`
	SelectedServiceAccountExchange bool `json:"selected_service_account_exchange"`
	SelectedDeployedSpec           bool `json:"selected_deployed_spec"`
}
type Report struct {
	AWSAuthority               *AWSAuthoritySummary `json:"aws_authority,omitempty"`
	Schema                     string               `json:"schema"`
	Mode                       string               `json:"mode"`
	Source                     string               `json:"source"`
	Ready                      bool                 `json:"ready"`
	InstallPrerequisitesReady  bool                 `json:"install_prerequisites_ready"`
	RuntimeObservationsReady   bool                 `json:"runtime_observations_ready"`
	ProductionEndToEndVerified bool                 `json:"production_end_to_end_verified"`
	Checks                     []Check              `json:"checks"`
}

type Runner struct {
	config Config
	http   *http.Client
}
