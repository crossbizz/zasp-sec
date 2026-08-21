package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/awsdiscovery"
	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
)

const maximumAWSInventoryItems = 1_000

type discoveryAWSIAMAPI interface {
	ListRoles(context.Context, *iam.ListRolesInput, ...func(*iam.Options)) (*iam.ListRolesOutput, error)
	ListAttachedRolePolicies(context.Context, *iam.ListAttachedRolePoliciesInput, ...func(*iam.Options)) (*iam.ListAttachedRolePoliciesOutput, error)
	GetPolicy(context.Context, *iam.GetPolicyInput, ...func(*iam.Options)) (*iam.GetPolicyOutput, error)
	GetPolicyVersion(context.Context, *iam.GetPolicyVersionInput, ...func(*iam.Options)) (*iam.GetPolicyVersionOutput, error)
}

type discoveryAWSEC2API interface {
	DescribeRegions(context.Context, *ec2.DescribeRegionsInput, ...func(*ec2.Options)) (*ec2.DescribeRegionsOutput, error)
	DescribeInstances(context.Context, *ec2.DescribeInstancesInput, ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error)
}

type discoveryAWSInventoryFactory struct {
	Identity discoveryCallerIdentityFactory
	IAM      func(string, aws.Credentials) (discoveryAWSIAMAPI, error)
	EC2      func(string, aws.Credentials) (discoveryAWSEC2API, error)
}

type discoveryAWSCollectionInventoryCaller struct {
	factory discoveryAWSInventoryFactory
	clock   func() time.Time
}

type discoveryAWSNativeRole struct {
	ARN                      string
	AssumeRolePolicyDocument map[string]any
	AttachedPolicyNames      []string
	CreateDate               string
	IsServiceRole            bool
	Path                     string
	RoleID                   string
	RoleName                 string
	ManagedPolicies          map[string][]any
}

type discoveryAWSNativeInstance struct {
	ARN, HTTPEndpoint, HTTPTokens, InstanceID, Region, State string
}

func newDiscoveryAWSCollectionInventoryCaller(factory discoveryAWSInventoryFactory, clock func() time.Time) (*discoveryAWSCollectionInventoryCaller, error) {
	if factory.Identity == nil || factory.IAM == nil || factory.EC2 == nil || clock == nil {
		return nil, errRuntimeUnavailable
	}
	now := clock()
	if now.IsZero() || now.Location() != time.UTC {
		return nil, errRuntimeUnavailable
	}
	return &discoveryAWSCollectionInventoryCaller{factory: factory, clock: clock}, nil
}

func (caller *discoveryAWSCollectionInventoryCaller) GetCollectionInventory(ctx context.Context, credential []byte) (awsdiscovery.CollectionInventory, error) {
	if caller == nil || ctx == nil || ctx.Err() != nil || caller.clock == nil {
		return awsdiscovery.CollectionInventory{}, awsdiscovery.ErrDenied
	}
	envelope, err := decodeDiscoveryCredentialEnvelope(credential)
	if err != nil || envelope.Provider != collection.ProviderAWS || !envelope.ExpiresAt.After(caller.clock()) {
		envelope.Destroy()
		return awsdiscovery.CollectionInventory{}, discoveryCredentialFailure(ctx, collection.FailureRetryable)
	}
	defer envelope.Destroy()
	credentials := aws.Credentials{AccessKeyID: string(envelope.AccessKeyID), SecretAccessKey: string(envelope.SecretAccessKey), SessionToken: string(envelope.SessionToken), CanExpire: true, Expires: envelope.ExpiresAt, Source: "zasp-discovery-assume-role"}
	defer clearAWSCredentials(&credentials)
	identityAPI, err := caller.factory.Identity(envelope.Region, credentials)
	if err != nil || nilDiscoveryClientDependency(identityAPI) {
		return awsdiscovery.CollectionInventory{}, awsdiscovery.ErrDenied
	}
	identityOutput, err := identityAPI.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{}, func(options *sts.Options) { options.Retryer = aws.NopRetryer{} })
	if err != nil || ctx.Err() != nil || identityOutput == nil || aws.ToString(identityOutput.Account) != envelope.SubjectID || !strings.HasPrefix(aws.ToString(identityOutput.Arn), "arn:aws:sts::"+envelope.SubjectID+":assumed-role/") {
		return awsdiscovery.CollectionInventory{}, awsdiscovery.ErrDenied
	}
	identity := awsdiscovery.Identity{AccountID: aws.ToString(identityOutput.Account), PrincipalARN: aws.ToString(identityOutput.Arn)}
	iamAPI, err := caller.factory.IAM(envelope.Region, credentials)
	if err != nil || nilDiscoveryClientDependency(iamAPI) {
		return awsdiscovery.CollectionInventory{}, awsdiscovery.ErrDenied
	}
	roles, err := collectDiscoveryAWSRoles(ctx, iamAPI, identity.AccountID)
	if err != nil {
		return awsdiscovery.CollectionInventory{}, err
	}
	ec2API, err := caller.factory.EC2(envelope.Region, credentials)
	if err != nil || nilDiscoveryClientDependency(ec2API) {
		return awsdiscovery.CollectionInventory{}, awsdiscovery.ErrDenied
	}
	instances, err := collectDiscoveryAWSInstances(ctx, caller.factory.EC2, ec2API, credentials, identity.AccountID)
	if err != nil {
		return awsdiscovery.CollectionInventory{}, err
	}
	cartography, prowler, err := marshalDiscoveryAWSSecuritySources(identity.AccountID, roles, instances)
	if err != nil {
		return awsdiscovery.CollectionInventory{}, awsdiscovery.ErrDenied
	}
	return awsdiscovery.CollectionInventory{Identity: identity, CredentialExpiresAt: envelope.ExpiresAt, CartographySource: cartography, CartographyDigest: sha256.Sum256(cartography), ProwlerSource: prowler, ProwlerDigest: sha256.Sum256(prowler)}, nil
}

func (caller *discoveryAWSCollectionInventoryCaller) CheckCollectionReadiness(ctx context.Context) error {
	if caller == nil || ctx == nil || ctx.Err() != nil || caller.factory.Identity == nil || caller.factory.IAM == nil || caller.factory.EC2 == nil {
		return awsdiscovery.ErrDenied
	}
	return nil
}

func collectDiscoveryAWSRoles(ctx context.Context, api discoveryAWSIAMAPI, accountID string) ([]discoveryAWSNativeRole, error) {
	roles := make([]discoveryAWSNativeRole, 0)
	var marker *string
	for {
		output, err := api.ListRoles(ctx, &iam.ListRolesInput{Marker: marker, MaxItems: aws.Int32(1000)}, func(options *iam.Options) { options.Retryer = aws.NopRetryer{} })
		if err != nil || ctx.Err() != nil || output == nil || len(roles)+len(output.Roles) > maximumAWSInventoryItems {
			return nil, awsdiscovery.ErrDenied
		}
		for _, role := range output.Roles {
			native, err := collectDiscoveryAWSRole(ctx, api, accountID, role)
			if err != nil {
				return nil, err
			}
			roles = append(roles, native)
		}
		if !output.IsTruncated {
			break
		}
		if output.Marker == nil || output.Marker == marker || strings.TrimSpace(aws.ToString(output.Marker)) == "" {
			return nil, awsdiscovery.ErrDenied
		}
		marker = output.Marker
	}
	sort.Slice(roles, func(i, j int) bool { return roles[i].ARN < roles[j].ARN })
	return roles, nil
}

func collectDiscoveryAWSRole(ctx context.Context, api discoveryAWSIAMAPI, accountID string, role iamtypes.Role) (discoveryAWSNativeRole, error) {
	arn, name := aws.ToString(role.Arn), aws.ToString(role.RoleName)
	if !strings.HasPrefix(arn, "arn:aws:iam::"+accountID+":role/") || name == "" || role.CreateDate == nil || role.AssumeRolePolicyDocument == nil || role.Path == nil || role.RoleId == nil {
		return discoveryAWSNativeRole{}, awsdiscovery.ErrDenied
	}
	trust, err := decodeDiscoveryAWSPolicyDocument(*role.AssumeRolePolicyDocument)
	if err != nil {
		return discoveryAWSNativeRole{}, err
	}
	native := discoveryAWSNativeRole{ARN: arn, AssumeRolePolicyDocument: trust, CreateDate: role.CreateDate.UTC().Format(time.RFC3339), IsServiceRole: strings.HasPrefix(aws.ToString(role.Path), "/aws-service-role/"), Path: aws.ToString(role.Path), RoleID: aws.ToString(role.RoleId), RoleName: name, ManagedPolicies: make(map[string][]any)}
	var marker *string
	for {
		attached, err := api.ListAttachedRolePolicies(ctx, &iam.ListAttachedRolePoliciesInput{RoleName: role.RoleName, Marker: marker, MaxItems: aws.Int32(1000)}, func(options *iam.Options) { options.Retryer = aws.NopRetryer{} })
		if err != nil || attached == nil || len(native.AttachedPolicyNames)+len(attached.AttachedPolicies) > maximumAWSInventoryItems {
			return discoveryAWSNativeRole{}, awsdiscovery.ErrDenied
		}
		for _, policy := range attached.AttachedPolicies {
			policyARN, policyName := aws.ToString(policy.PolicyArn), aws.ToString(policy.PolicyName)
			if policyARN == "" || policyName == "" {
				return discoveryAWSNativeRole{}, awsdiscovery.ErrDenied
			}
			statements, err := collectDiscoveryAWSPolicy(ctx, api, policyARN, policyName)
			if err != nil {
				return discoveryAWSNativeRole{}, err
			}
			native.AttachedPolicyNames = append(native.AttachedPolicyNames, policyName)
			native.ManagedPolicies[policyARN] = statements
		}
		if !attached.IsTruncated {
			break
		}
		if attached.Marker == nil || attached.Marker == marker || strings.TrimSpace(aws.ToString(attached.Marker)) == "" {
			return discoveryAWSNativeRole{}, awsdiscovery.ErrDenied
		}
		marker = attached.Marker
	}
	sort.Strings(native.AttachedPolicyNames)
	return native, nil
}

func collectDiscoveryAWSPolicy(ctx context.Context, api discoveryAWSIAMAPI, arn, expectedName string) ([]any, error) {
	policy, err := api.GetPolicy(ctx, &iam.GetPolicyInput{PolicyArn: aws.String(arn)}, func(options *iam.Options) { options.Retryer = aws.NopRetryer{} })
	if err != nil || policy == nil || policy.Policy == nil || aws.ToString(policy.Policy.Arn) != arn || aws.ToString(policy.Policy.PolicyName) != expectedName || policy.Policy.DefaultVersionId == nil {
		return nil, awsdiscovery.ErrDenied
	}
	version, err := api.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{PolicyArn: aws.String(arn), VersionId: policy.Policy.DefaultVersionId}, func(options *iam.Options) { options.Retryer = aws.NopRetryer{} })
	if err != nil || version == nil || version.PolicyVersion == nil || version.PolicyVersion.Document == nil || aws.ToString(version.PolicyVersion.VersionId) != aws.ToString(policy.Policy.DefaultVersionId) {
		return nil, awsdiscovery.ErrDenied
	}
	document, err := decodeDiscoveryAWSPolicyDocument(*version.PolicyVersion.Document)
	if err != nil {
		return nil, err
	}
	switch statements := document["Statement"].(type) {
	case []any:
		return statements, nil
	case map[string]any:
		return []any{statements}, nil
	default:
		return nil, awsdiscovery.ErrDenied
	}
}

func collectDiscoveryAWSInstances(ctx context.Context, factory func(string, aws.Credentials) (discoveryAWSEC2API, error), primary discoveryAWSEC2API, credentials aws.Credentials, accountID string) ([]discoveryAWSNativeInstance, error) {
	regionsOutput, err := primary.DescribeRegions(ctx, &ec2.DescribeRegionsInput{AllRegions: aws.Bool(false)}, func(options *ec2.Options) { options.Retryer = aws.NopRetryer{} })
	if err != nil || regionsOutput == nil || len(regionsOutput.Regions) < 1 || len(regionsOutput.Regions) > 64 {
		return nil, awsdiscovery.ErrDenied
	}
	regions := make([]string, 0, len(regionsOutput.Regions))
	for _, region := range regionsOutput.Regions {
		name, status := aws.ToString(region.RegionName), aws.ToString(region.OptInStatus)
		if !discoveryRegionPattern.MatchString(name) || status != "opt-in-not-required" && status != "opted-in" {
			return nil, awsdiscovery.ErrDenied
		}
		regions = append(regions, name)
	}
	sort.Strings(regions)
	instances := make([]discoveryAWSNativeInstance, 0)
	for _, region := range regions {
		api, err := factory(region, credentials)
		if err != nil || nilDiscoveryClientDependency(api) {
			return nil, awsdiscovery.ErrDenied
		}
		var token *string
		for {
			output, err := api.DescribeInstances(ctx, &ec2.DescribeInstancesInput{NextToken: token, MaxResults: aws.Int32(1000)}, func(options *ec2.Options) { options.Retryer = aws.NopRetryer{} })
			if err != nil || output == nil {
				return nil, awsdiscovery.ErrDenied
			}
			for _, reservation := range output.Reservations {
				for _, instance := range reservation.Instances {
					if len(instances) >= maximumAWSInventoryItems {
						return nil, awsdiscovery.ErrDenied
					}
					native, err := discoveryAWSInstance(accountID, region, instance)
					if err != nil {
						return nil, err
					}
					instances = append(instances, native)
				}
			}
			if output.NextToken == nil {
				break
			}
			if output.NextToken == token || strings.TrimSpace(aws.ToString(output.NextToken)) == "" {
				return nil, awsdiscovery.ErrDenied
			}
			token = output.NextToken
		}
	}
	sort.Slice(instances, func(i, j int) bool { return instances[i].ARN < instances[j].ARN })
	return instances, nil
}

func discoveryAWSInstance(accountID, region string, instance ec2types.Instance) (discoveryAWSNativeInstance, error) {
	id := aws.ToString(instance.InstanceId)
	if id == "" || instance.MetadataOptions == nil || instance.State == nil {
		return discoveryAWSNativeInstance{}, awsdiscovery.ErrDenied
	}
	return discoveryAWSNativeInstance{ARN: "arn:aws:ec2:" + region + ":" + accountID + ":instance/" + id, HTTPEndpoint: string(instance.MetadataOptions.HttpEndpoint), HTTPTokens: string(instance.MetadataOptions.HttpTokens), InstanceID: id, Region: region, State: string(instance.State.Name)}, nil
}

func decodeDiscoveryAWSPolicyDocument(encoded string) (map[string]any, error) {
	decoded, err := url.QueryUnescape(encoded)
	if err != nil || len(decoded) < 2 || len(decoded) > 1<<20 {
		return nil, awsdiscovery.ErrDenied
	}
	var document map[string]any
	if json.Unmarshal([]byte(decoded), &document) != nil || document == nil || len(document) > 64 {
		return nil, awsdiscovery.ErrDenied
	}
	return document, nil
}

func marshalDiscoveryAWSSecuritySources(accountID string, roles []discoveryAWSNativeRole, instances []discoveryAWSNativeInstance) (json.RawMessage, json.RawMessage, error) {
	cartographyRoles := make([]map[string]any, 0, len(roles))
	prowlerRoles := make([]map[string]any, 0, len(roles))
	managed := make(map[string]map[string][]any, len(roles))
	for _, role := range roles {
		cartographyRoles = append(cartographyRoles, map[string]any{"Arn": role.ARN, "AssumeRolePolicyDocument": role.AssumeRolePolicyDocument, "CreateDate": role.CreateDate, "Path": role.Path, "RoleId": role.RoleID, "RoleName": role.RoleName})
		attached := make([]map[string]string, 0, len(role.AttachedPolicyNames))
		for _, name := range role.AttachedPolicyNames {
			attached = append(attached, map[string]string{"PolicyName": name})
		}
		prowlerRoles = append(prowlerRoles, map[string]any{"Arn": role.ARN, "AssumeRolePolicyDocument": role.AssumeRolePolicyDocument, "AttachedPolicies": attached, "IsServiceRole": role.IsServiceRole, "RoleId": role.RoleID, "RoleName": role.RoleName})
		managed[role.ARN] = role.ManagedPolicies
	}
	prowlerInstances := make([]map[string]string, 0, len(instances))
	for _, instance := range instances {
		prowlerInstances = append(prowlerInstances, map[string]string{"Arn": instance.ARN, "HttpEndpoint": instance.HTTPEndpoint, "HttpTokens": instance.HTTPTokens, "InstanceId": instance.InstanceID, "Region": instance.Region, "State": instance.State})
	}
	cartography, firstErr := json.Marshal(map[string]any{"account_id": accountID, "managed_policies": managed, "roles": cartographyRoles})
	prowler, secondErr := json.Marshal(map[string]any{"account_id": accountID, "instances": prowlerInstances, "roles": prowlerRoles})
	if firstErr != nil || secondErr != nil || len(cartography) > 16<<20 || len(prowler) > 16<<20 {
		return nil, nil, awsdiscovery.ErrDenied
	}
	return cartography, prowler, nil
}

var _ awsdiscovery.CollectionInventoryCaller = (*discoveryAWSCollectionInventoryCaller)(nil)
