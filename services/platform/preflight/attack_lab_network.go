package preflight

import (
	"github.com/aws/aws-sdk-go-v2/aws"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

// A missing explicit association is not an empty safe route table: it inherits
// the unique same-VPC main table. Runner isolation additionally requires its
// original dedicated explicit association, unlike product subnets.
func resolveAttackLabSubnetRoute(tables []ec2types.RouteTable, subnet, vpc, expected string, requireExplicit bool) (ec2types.RouteTable, error) {
	if len(tables) == 0 || len(tables) > 400 || subnet == "" || vpc == "" || expected == "" {
		return ec2types.RouteTable{}, ErrRejected
	}
	seen := map[string]bool{}
	mainCount, explicitCount := 0, 0
	var main, explicit ec2types.RouteTable
	for _, table := range tables {
		id := aws.ToString(table.RouteTableId)
		if id == "" || seen[id] || aws.ToString(table.VpcId) != vpc {
			return ec2types.RouteTable{}, ErrRejected
		}
		seen[id] = true
		for _, association := range table.Associations {
			isMain := aws.ToBool(association.Main)
			isTarget := aws.ToString(association.SubnetId) == subnet
			if !isMain && !isTarget {
				continue
			}
			if aws.ToString(association.RouteTableId) != id || association.AssociationState == nil || association.AssociationState.State != ec2types.RouteTableAssociationStateCodeAssociated || aws.ToString(association.GatewayId) != "" {
				return ec2types.RouteTable{}, ErrRejected
			}
			if isMain {
				if aws.ToString(association.SubnetId) != "" {
					return ec2types.RouteTable{}, ErrRejected
				}
				mainCount++
				main = table
			}
			if isTarget {
				explicitCount++
				explicit = table
			}
		}
	}
	if mainCount != 1 || explicitCount > 1 {
		return ec2types.RouteTable{}, ErrRejected
	}
	selected := main
	if explicitCount == 1 {
		selected = explicit
	} else if requireExplicit {
		return ec2types.RouteTable{}, ErrRejected
	}
	if aws.ToString(selected.RouteTableId) != expected {
		return ec2types.RouteTable{}, ErrRejected
	}
	return selected, nil
}
