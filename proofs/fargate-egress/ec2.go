package main

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

var accessKeyPattern = regexp.MustCompile(`^[A-Z0-9]{20,128}$`)

type EC2API interface {
	DescribeSecurityGroups(context.Context, *ec2.DescribeSecurityGroupsInput, ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error)
	DescribeNetworkInterfaces(context.Context, *ec2.DescribeNetworkInterfacesInput, ...func(*ec2.Options)) (*ec2.DescribeNetworkInterfacesOutput, error)
}

type EC2ReadBoundary struct{ api EC2API }

type RealEC2Options struct {
	Region          string
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
}

func NewEC2ReadBoundary(api EC2API) (*EC2ReadBoundary, error) {
	if api == nil {
		return nil, ErrConfiguration
	}
	return &EC2ReadBoundary{api: api}, nil
}

func NewRealEC2Boundary(options RealEC2Options) (*EC2ReadBoundary, error) {
	if !validRegion(options.Region) || !accessKeyPattern.MatchString(options.AccessKeyID) ||
		len(options.SecretAccessKey) < 16 || len(options.SecretAccessKey) > 256 || containsControl(options.SecretAccessKey) ||
		len(options.SessionToken) > 4096 || containsControl(options.SessionToken) {
		return nil, ErrConfiguration
	}
	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          8,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ExpectContinueTimeout: time.Second,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
	}
	config := aws.Config{
		Region:      options.Region,
		Credentials: aws.NewCredentialsCache(credentials.NewStaticCredentialsProvider(options.AccessKeyID, options.SecretAccessKey, options.SessionToken)),
		HTTPClient:  &http.Client{Transport: transport, Timeout: 10 * time.Second},
		Retryer: func() aws.Retryer {
			return retry.NewStandard(func(settings *retry.StandardOptions) { settings.MaxAttempts = 1 })
		},
	}
	return NewEC2ReadBoundary(ec2.NewFromConfig(config))
}

func (boundary *EC2ReadBoundary) InspectSecurityGroup(ctx context.Context, id string) (SecurityGroupState, error) {
	if boundary == nil || boundary.api == nil || !securityGroupPattern.MatchString(id) || ctx.Err() != nil {
		return SecurityGroupState{}, ErrConfiguration
	}
	output, err := boundary.api.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{GroupIds: []string{id}})
	if err != nil || output == nil || len(output.SecurityGroups) != 1 {
		return SecurityGroupState{}, ErrProvider
	}
	group := output.SecurityGroups[0]
	if aws.ToString(group.GroupId) != id || !vpcPattern.MatchString(aws.ToString(group.VpcId)) {
		return SecurityGroupState{}, ErrProvider
	}
	state := SecurityGroupState{ID: id, VPCID: aws.ToString(group.VpcId)}
	state.Ingress, err = convertPermissions(group.IpPermissions)
	if err != nil {
		return SecurityGroupState{}, err
	}
	state.Egress, err = convertPermissions(group.IpPermissionsEgress)
	if err != nil {
		return SecurityGroupState{}, err
	}
	return state, nil
}

func convertPermissions(permissions []types.IpPermission) ([]SecurityGroupRule, error) {
	result := make([]SecurityGroupRule, 0, len(permissions))
	seen := map[string]struct{}{}
	for _, permission := range permissions {
		protocol := aws.ToString(permission.IpProtocol)
		if protocol != "tcp" && protocol != "udp" {
			return nil, ErrProvider
		}
		if permission.FromPort == nil || permission.ToPort == nil || *permission.FromPort < 1 || *permission.ToPort > 65535 || *permission.FromPort != *permission.ToPort ||
			len(permission.Ipv6Ranges) != 0 || len(permission.PrefixListIds) != 0 {
			return nil, ErrProvider
		}
		targetCount := len(permission.IpRanges) + len(permission.UserIdGroupPairs)
		if targetCount != 1 {
			return nil, ErrProvider
		}
		rule := SecurityGroupRule{Protocol: protocol, FromPort: *permission.FromPort, ToPort: *permission.ToPort}
		if len(permission.IpRanges) == 1 {
			rangeValue := permission.IpRanges[0]
			if rangeValue.Description != nil && aws.ToString(rangeValue.Description) != "" {
				return nil, ErrProvider
			}
			rule.CIDR = aws.ToString(rangeValue.CidrIp)
			if !strings.HasSuffix(rule.CIDR, "/32") {
				return nil, ErrProvider
			}
		} else {
			pair := permission.UserIdGroupPairs[0]
			if pair.Description != nil && aws.ToString(pair.Description) != "" || pair.GroupName != nil && aws.ToString(pair.GroupName) != "" ||
				pair.PeeringStatus != nil && aws.ToString(pair.PeeringStatus) != "" || pair.VpcPeeringConnectionId != nil && aws.ToString(pair.VpcPeeringConnectionId) != "" {
				return nil, ErrProvider
			}
			rule.DestinationSecurityGroupID = aws.ToString(pair.GroupId)
			if !securityGroupPattern.MatchString(rule.DestinationSecurityGroupID) {
				return nil, ErrProvider
			}
		}
		key := permissionKey(rule)
		if _, exists := seen[key]; exists {
			return nil, ErrProvider
		}
		seen[key] = struct{}{}
		result = append(result, rule)
	}
	return result, nil
}

func permissionKey(rule SecurityGroupRule) string {
	return rule.Protocol + "/" + strconv.FormatInt(int64(rule.FromPort), 10) + "/" + rule.CIDR + "/" + rule.DestinationSecurityGroupID
}

func (boundary *EC2ReadBoundary) InspectNetworkInterface(ctx context.Context, id string) (NetworkInterfaceState, error) {
	if boundary == nil || boundary.api == nil || !eniPattern.MatchString(id) || ctx.Err() != nil {
		return NetworkInterfaceState{}, ErrConfiguration
	}
	output, err := boundary.api.DescribeNetworkInterfaces(ctx, &ec2.DescribeNetworkInterfacesInput{NetworkInterfaceIds: []string{id}})
	if err != nil || output == nil || len(output.NetworkInterfaces) != 1 {
		return NetworkInterfaceState{}, ErrProvider
	}
	item := output.NetworkInterfaces[0]
	if aws.ToString(item.NetworkInterfaceId) != id || !vpcPattern.MatchString(aws.ToString(item.VpcId)) || item.Status != types.NetworkInterfaceStatusInUse {
		return NetworkInterfaceState{}, ErrProvider
	}
	groups := make([]string, 0, len(item.Groups))
	for _, group := range item.Groups {
		id := aws.ToString(group.GroupId)
		if !securityGroupPattern.MatchString(id) || slices.Contains(groups, id) {
			return NetworkInterfaceState{}, ErrProvider
		}
		groups = append(groups, id)
	}
	if len(groups) == 0 {
		return NetworkInterfaceState{}, ErrProvider
	}
	sort.Strings(groups)
	return NetworkInterfaceState{ID: id, VPCID: aws.ToString(item.VpcId), Status: "in-use", SecurityGroupIDs: groups}, nil
}
