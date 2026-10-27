package preflight

import (
	"github.com/aws/aws-sdk-go-v2/aws"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"testing"
)

func TestAttackLabRouteAssociationUsesUniqueMainAndRunnerExplicitIsolation(t *testing.T) {
	for _, mode := range []string{"runner-explicit", "product-main-fallback", "runner-main-fallback", "ambiguous-explicit", "ambiguous-main", "foreign-vpc", "missing-main", "pending-association", "duplicate-table"} {
		t.Run(mode, func(t *testing.T) {
			vpc, subnet := "vpc-11111111111111111", "subnet-11111111111111111"
			main := ec2types.RouteTable{RouteTableId: aws.String("rtb-11111111111111111"), VpcId: aws.String(vpc), Associations: []ec2types.RouteTableAssociation{{Main: aws.Bool(true), RouteTableId: aws.String("rtb-11111111111111111"), AssociationState: &ec2types.RouteTableAssociationState{State: ec2types.RouteTableAssociationStateCodeAssociated}}}}
			runner := ec2types.RouteTable{RouteTableId: aws.String("rtb-22222222222222222"), VpcId: aws.String(vpc), Associations: []ec2types.RouteTableAssociation{{Main: aws.Bool(false), SubnetId: aws.String(subnet), RouteTableId: aws.String("rtb-22222222222222222"), AssociationState: &ec2types.RouteTableAssociationState{State: ec2types.RouteTableAssociationStateCodeAssociated}}}}
			tables := []ec2types.RouteTable{main, runner}
			explicit := true
			expected := "rtb-22222222222222222"
			switch mode {
			case "product-main-fallback":
				explicit = false
				expected = "rtb-11111111111111111"
				tables = []ec2types.RouteTable{main}
			case "runner-main-fallback":
				tables = []ec2types.RouteTable{main}
			case "ambiguous-explicit":
				other := runner
				other.RouteTableId = aws.String("rtb-33333333333333333")
				tables = append(tables, other)
			case "ambiguous-main":
				other := main
				other.RouteTableId = aws.String("rtb-33333333333333333")
				tables = append(tables, other)
			case "foreign-vpc":
				tables[1].VpcId = aws.String("vpc-99999999999999999")
			case "missing-main":
				tables = []ec2types.RouteTable{runner}
			case "pending-association":
				tables[1].Associations[0].AssociationState.State = ec2types.RouteTableAssociationStateCodeAssociating
			case "duplicate-table":
				tables = append(tables, runner)
			}
			result, e := resolveAttackLabSubnetRoute(tables, subnet, vpc, expected, explicit)
			positive := mode == "runner-explicit" || mode == "product-main-fallback"
			if positive {
				if e != nil || aws.ToString(result.RouteTableId) != expected {
					t.Fatal("actual explicit or main route association not resolved")
				}
			} else if e == nil {
				t.Fatal("ambiguous, foreign or implicit runner association accepted")
			}
		})
	}
}
