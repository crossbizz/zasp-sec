package main

import (
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/zasp-ai/zasp-sec/services/platform/artifactstore/s3driver"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/awsdiscovery"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/kubernetesdiscovery"
)

// The seam contains external IO only. Product SQL, credentials and collection
// composition are never replaceable through it.
type discoveryDependencyIO struct {
	Credentials aws.CredentialsProvider
	Secrets     discoverySecretsManagerAPI
	AssumeRole  interface {
		discoveryAssumeRoleAPI
		discoveryRoleReadinessAPI
	}
	S3 interface {
		s3driver.API
		discoveryArtifactReadinessAPI
	}
	KMS               discoveryKMSReadinessAPI
	Queue             discoveryQueueAPI
	Inventory         discoveryAWSInventoryFactory
	Security          awsdiscovery.CollectionSecurityAnalyzer
	KubernetesNetwork *kubernetesdiscovery.CollectionNetwork
	Close             func() error
}

func newProductionDiscoveryIO(config productionDiscoveryDependencyConfig) (discoveryDependencyIO, error) {
	if !validProductionDiscoveryDependencyAuthority(config) {
		return discoveryDependencyIO{}, errRuntimeUnavailable
	}
	cloud, err := newProductionDiscoveryCloudAuthority(config.Cloud)
	if err != nil {
		return discoveryDependencyIO{}, err
	}
	fail := func() (discoveryDependencyIO, error) {
		cloud.Close()
		return discoveryDependencyIO{}, errRuntimeUnavailable
	}
	runner, err := awsdiscovery.NewSecurityRunner(15 * time.Minute)
	if err != nil {
		return fail()
	}
	security, err := newDiscoveryAWSSecurityRunner(runner, config.Cloud.Clock)
	if err != nil {
		return fail()
	}
	return discoveryDependencyIO{Credentials: cloud.credentials, Secrets: cloud.secrets, AssumeRole: cloud.assumeRole, S3: cloud.s3, KMS: cloud.kms, Queue: cloud.sqs, Inventory: discoveryAWSInventoryFactory{Identity: cloud.NewCallerIdentity, IAM: cloud.NewIAM, EC2: cloud.NewEC2}, Security: security, Close: cloud.Close}, nil
}
