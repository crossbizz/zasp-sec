package main

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

type fakeEC2API struct {
	securityGroupOutput    *ec2.DescribeSecurityGroupsOutput
	networkInterfaceOutput *ec2.DescribeNetworkInterfacesOutput
	securityGroupInput     *ec2.DescribeSecurityGroupsInput
	networkInterfaceInput  *ec2.DescribeNetworkInterfacesInput
}

func (f *fakeEC2API) DescribeSecurityGroups(_ context.Context, input *ec2.DescribeSecurityGroupsInput, _ ...func(*ec2.Options)) (*ec2.DescribeSecurityGroupsOutput, error) {
	f.securityGroupInput = input
	return f.securityGroupOutput, nil
}

func (f *fakeEC2API) DescribeNetworkInterfaces(_ context.Context, input *ec2.DescribeNetworkInterfacesInput, _ ...func(*ec2.Options)) (*ec2.DescribeNetworkInterfacesOutput, error) {
	f.networkInterfaceInput = input
	return f.networkInterfaceOutput, nil
}

func TestEC2BoundaryConvertsExactSecurityGroupAndENI(t *testing.T) {
	api := &fakeEC2API{
		securityGroupOutput: &ec2.DescribeSecurityGroupsOutput{SecurityGroups: []types.SecurityGroup{{
			GroupId: aws.String("sg-0123456789abcdef0"), VpcId: aws.String("vpc-0123456789abcdef0"),
			IpPermissionsEgress: []types.IpPermission{
				{IpProtocol: aws.String("tcp"), FromPort: aws.Int32(443), ToPort: aws.Int32(443), UserIdGroupPairs: []types.UserIdGroupPair{{GroupId: aws.String("sg-11111111111111111"), UserId: aws.String("000000000000"), VpcId: aws.String("vpc-0123456789abcdef0")}}},
				{IpProtocol: aws.String("udp"), FromPort: aws.Int32(53), ToPort: aws.Int32(53), IpRanges: []types.IpRange{{CidrIp: aws.String("10.0.0.2/32")}}},
			},
		}}},
		networkInterfaceOutput: &ec2.DescribeNetworkInterfacesOutput{NetworkInterfaces: []types.NetworkInterface{{
			NetworkInterfaceId: aws.String("eni-0123456789abcdef0"), VpcId: aws.String("vpc-0123456789abcdef0"), Status: types.NetworkInterfaceStatusInUse,
			Groups: []types.GroupIdentifier{{GroupId: aws.String("sg-0123456789abcdef0")}},
		}}},
	}
	boundary, err := NewEC2ReadBoundary(api)
	if err != nil {
		t.Fatal(err)
	}
	group, err := boundary.InspectSecurityGroup(context.Background(), "sg-0123456789abcdef0")
	if err != nil || len(group.Egress) != 2 || api.securityGroupInput == nil || len(api.securityGroupInput.GroupIds) != 1 {
		t.Fatalf("group=%#v err=%v input=%#v", group, err, api.securityGroupInput)
	}
	interfaceState, err := boundary.InspectNetworkInterface(context.Background(), "eni-0123456789abcdef0")
	if err != nil || interfaceState.Status != "in-use" || len(interfaceState.SecurityGroupIDs) != 1 || api.networkInterfaceInput == nil {
		t.Fatalf("eni=%#v err=%v input=%#v", interfaceState, err, api.networkInterfaceInput)
	}
}

func TestEC2BoundaryRejectsAmbiguousOrMalformedProviderState(t *testing.T) {
	tests := map[string]*ec2.DescribeSecurityGroupsOutput{
		"empty":         {},
		"duplicate":     {SecurityGroups: []types.SecurityGroup{{GroupId: aws.String("sg-0123456789abcdef0")}, {GroupId: aws.String("sg-0123456789abcdef0")}}},
		"ipv6":          {SecurityGroups: []types.SecurityGroup{{GroupId: aws.String("sg-0123456789abcdef0"), VpcId: aws.String("vpc-0123456789abcdef0"), IpPermissionsEgress: []types.IpPermission{{IpProtocol: aws.String("tcp"), FromPort: aws.Int32(443), ToPort: aws.Int32(443), Ipv6Ranges: []types.Ipv6Range{{CidrIpv6: aws.String("::/0")}}}}}}},
		"mixed targets": {SecurityGroups: []types.SecurityGroup{{GroupId: aws.String("sg-0123456789abcdef0"), VpcId: aws.String("vpc-0123456789abcdef0"), IpPermissionsEgress: []types.IpPermission{{IpProtocol: aws.String("tcp"), FromPort: aws.Int32(443), ToPort: aws.Int32(443), IpRanges: []types.IpRange{{CidrIp: aws.String("10.0.0.2/32")}}, UserIdGroupPairs: []types.UserIdGroupPair{{GroupId: aws.String("sg-11111111111111111")}}}}}}},
	}
	for name, output := range tests {
		t.Run(name, func(t *testing.T) {
			boundary, err := NewEC2ReadBoundary(&fakeEC2API{securityGroupOutput: output})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := boundary.InspectSecurityGroup(context.Background(), "sg-0123456789abcdef0"); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestRealEC2BoundaryRejectsInvalidStaticAuthority(t *testing.T) {
	tests := []RealEC2Options{
		{},
		{Region: "us-west-2", AccessKeyID: "key", SecretAccessKey: "secret"},
		{Region: "us-gov-west-1", AccessKeyID: "ABCDEFGHIJKLMNOPQRST", SecretAccessKey: "synthetic-secret-value"},
	}
	for _, options := range tests {
		if _, err := NewRealEC2Boundary(options); err == nil {
			t.Fatalf("accepted %#v", options)
		}
	}
}
