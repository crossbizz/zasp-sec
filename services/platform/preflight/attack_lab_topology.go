package preflight

import (
	"context"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

type attackLabTopologySnapshot struct {
	vpcs      []ec2types.Vpc
	subnets   []ec2types.Subnet
	tables    []ec2types.RouteTable
	groups    []ec2types.SecurityGroup
	endpoints []ec2types.VpcEndpoint
	prefixes  []ec2types.PrefixList
}

func collectAttackLabPages[T any](ctx context.Context, fetch func(context.Context, string) ([]T, string, error)) ([]T, error) {
	var collected []T
	cursor := ""
	seen := map[string]bool{}
	for page := 0; page < 4; page++ {
		call, cancel := context.WithTimeout(ctx, 10*time.Second)
		rows, next, e := fetch(call, cursor)
		expired := call.Err()
		cancel()
		if e != nil {
			return nil, e
		}
		if expired != nil {
			return nil, expired
		}
		if len(rows) > 400 || len(collected)+len(rows) > 400 {
			return nil, errMalformedProviderObservation
		}
		collected = append(collected, rows...)
		if next == "" {
			return collected, nil
		}
		if len(next) > 1024 || seen[next] {
			return nil, ErrRejected
		}
		seen[next] = true
		cursor = next
	}
	return nil, ErrRejected
}
func attackLabNextToken(token string) *string {
	if token == "" {
		return nil
	}
	return aws.String(token)
}

// clusterGroup is private data from the SAME bound DescribeCluster response;
// it is not a field accepted from the caller's target configuration.
func (r *Runner) observeAttackLabTopology(ctx context.Context, sdk aws.Config, authority *AWSAuthorityConfig, target *AWSAttackLabTarget, clusterGroup string, enabled bool) *attackLabEvidence {
	evidence := &attackLabEvidence{}
	if !enabled || ctx == nil || ctx.Err() != nil || authority == nil || target == nil || clusterGroup == "" {
		return evidence
	}
	bounded, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	api := ec2.NewFromConfig(sdk)
	var snapshot attackLabTopologySnapshot
	var e error
	operation := "ec2:DescribeVpcs"
	failureTargets := []string{authority.Cluster.VPCID}
	defer func() {
		if evidence.topologyAttempted && !evidence.topology {
			evidence.failures = attackLabFailures(operation, failureTargets, e)
		}
	}()
	evidence.topologyAttempted = true
	snapshot.vpcs, e = collectAttackLabPages(bounded, func(call context.Context, next string) ([]ec2types.Vpc, string, error) {
		out, e := api.DescribeVpcs(call, &ec2.DescribeVpcsInput{VpcIds: []string{authority.Cluster.VPCID}, NextToken: attackLabNextToken(next)})
		if e != nil {
			return nil, "", e
		}
		if out == nil {
			return nil, "", errMalformedProviderObservation
		}
		return out.Vpcs, aws.ToString(out.NextToken), nil
	})
	if e != nil {
		return evidence
	}
	ids := append(append([]string{}, target.SubnetIDs...), target.ProductSubnetIDs...)
	operation = "ec2:DescribeSubnets"
	failureTargets = ids
	snapshot.subnets, e = collectAttackLabPages(bounded, func(call context.Context, next string) ([]ec2types.Subnet, string, error) {
		out, e := api.DescribeSubnets(call, &ec2.DescribeSubnetsInput{SubnetIds: ids, NextToken: attackLabNextToken(next)})
		if e != nil {
			return nil, "", e
		}
		if out == nil {
			return nil, "", errMalformedProviderObservation
		}
		return out.Subnets, aws.ToString(out.NextToken), nil
	})
	if e != nil {
		return evidence
	}
	operation = "ec2:DescribeRouteTables"
	failureTargets = []string{authority.Cluster.VPCID}
	snapshot.tables, e = collectAttackLabPages(bounded, func(call context.Context, next string) ([]ec2types.RouteTable, string, error) {
		out, e := api.DescribeRouteTables(call, &ec2.DescribeRouteTablesInput{Filters: []ec2types.Filter{{Name: aws.String("vpc-id"), Values: []string{authority.Cluster.VPCID}}}, MaxResults: aws.Int32(100), NextToken: attackLabNextToken(next)})
		if e != nil {
			return nil, "", e
		}
		if out == nil {
			return nil, "", errMalformedProviderObservation
		}
		return out.RouteTables, aws.ToString(out.NextToken), nil
	})
	if e != nil {
		return evidence
	}
	prefix := ""
	for _, table := range snapshot.tables {
		if aws.ToString(table.RouteTableId) == target.IsolatedRouteTableID {
			for _, route := range table.Routes {
				p := aws.ToString(route.DestinationPrefixListId)
				if p != "" {
					if prefix != "" && prefix != p {
						return evidence
					}
					prefix = p
				}
			}
		}
	}
	if prefix == "" {
		return evidence
	}
	operation = "ec2:DescribePrefixLists"
	failureTargets = []string{prefix}
	snapshot.prefixes, e = collectAttackLabPages(bounded, func(call context.Context, next string) ([]ec2types.PrefixList, string, error) {
		out, e := api.DescribePrefixLists(call, &ec2.DescribePrefixListsInput{PrefixListIds: []string{prefix}, NextToken: attackLabNextToken(next)})
		if e != nil {
			return nil, "", e
		}
		if out == nil {
			return nil, "", errMalformedProviderObservation
		}
		return out.PrefixLists, aws.ToString(out.NextToken), nil
	})
	if e != nil {
		return evidence
	}
	groups := []string{target.RunnerSecurityGroupID, target.ProxySecurityGroupID, target.ImagePullSecurityGroupID, target.EndpointSecurityGroupID, clusterGroup}
	operation = "ec2:DescribeSecurityGroups"
	failureTargets = groups
	snapshot.groups, e = collectAttackLabPages(bounded, func(call context.Context, next string) ([]ec2types.SecurityGroup, string, error) {
		out, e := api.DescribeSecurityGroups(call, &ec2.DescribeSecurityGroupsInput{GroupIds: groups, NextToken: attackLabNextToken(next)})
		if e != nil {
			return nil, "", e
		}
		if out == nil {
			return nil, "", errMalformedProviderObservation
		}
		return out.SecurityGroups, aws.ToString(out.NextToken), nil
	})
	if e != nil {
		return evidence
	}
	endpointIDs := make([]string, 0, len(target.EndpointIDs))
	for _, id := range target.EndpointIDs {
		endpointIDs = append(endpointIDs, id)
	}
	operation = "ec2:DescribeVpcEndpoints"
	failureTargets = endpointIDs
	snapshot.endpoints, e = collectAttackLabPages(bounded, func(call context.Context, next string) ([]ec2types.VpcEndpoint, string, error) {
		out, e := api.DescribeVpcEndpoints(call, &ec2.DescribeVpcEndpointsInput{VpcEndpointIds: endpointIDs, NextToken: attackLabNextToken(next)})
		if e != nil {
			return nil, "", e
		}
		if out == nil {
			return nil, "", errMalformedProviderObservation
		}
		return out.VpcEndpoints, aws.ToString(out.NextToken), nil
	})
	if e != nil {
		return evidence
	}
	operation = "configuration:ValidateAttackLabTopology"
	failureTargets = []string{authority.Cluster.VPCID}
	evidence.topology = validAttackLabTopologySnapshot(snapshot, authority, target, clusterGroup, r.config)
	return evidence
}
