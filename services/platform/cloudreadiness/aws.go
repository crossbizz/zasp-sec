// Package cloudreadiness shares finite provider-output predicates between runtime
// readiness and operator inspection. These predicates confer no permissions.
package cloudreadiness

import (
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

func Role(output *sts.GetCallerIdentityOutput, partition, account, roleARN string) bool {
	roleName := roleARN[strings.LastIndex(roleARN, "/")+1:]
	prefix := "arn:" + partition + ":sts::" + account + ":assumed-role/" + roleName + "/"
	return output != nil && aws.ToString(output.Account) == account && strings.HasPrefix(aws.ToString(output.Arn), prefix)
}
func BucketHead(output *s3.HeadBucketOutput, region string) bool {
	return output != nil && aws.ToString(output.BucketRegion) == region
}
func BucketVersioning(output *s3.GetBucketVersioningOutput) bool {
	return output != nil && output.Status == s3types.BucketVersioningStatusEnabled
}
func BucketEncryption(output *s3.GetBucketEncryptionOutput, keyARN string) bool {
	if output == nil || output.ServerSideEncryptionConfiguration == nil || len(output.ServerSideEncryptionConfiguration.Rules) != 1 {
		return false
	}
	r := output.ServerSideEncryptionConfiguration.Rules[0]
	return r.ApplyServerSideEncryptionByDefault != nil && r.ApplyServerSideEncryptionByDefault.SSEAlgorithm == s3types.ServerSideEncryptionAwsKms && aws.ToString(r.ApplyServerSideEncryptionByDefault.KMSMasterKeyID) == keyARN && aws.ToBool(r.BucketKeyEnabled)
}
func Key(output *kms.DescribeKeyOutput, keyARN, account string) bool {
	if output == nil || output.KeyMetadata == nil {
		return false
	}
	m := output.KeyMetadata
	p := strings.Split(keyARN, ":")
	if len(p) != 6 {
		return false
	}
	return aws.ToString(m.Arn) == keyARN && aws.ToString(m.KeyId) == strings.TrimPrefix(p[5], "key/") && aws.ToString(m.AWSAccountId) == account && m.Enabled && m.KeyManager == kmstypes.KeyManagerTypeCustomer && m.KeyState == kmstypes.KeyStateEnabled && m.KeyUsage == kmstypes.KeyUsageTypeEncryptDecrypt && m.KeySpec == kmstypes.KeySpecSymmetricDefault && m.Origin == kmstypes.OriginTypeAwsKms
}
