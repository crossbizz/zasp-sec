package preflight

import (
	"encoding/json"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

func exactAttackLabImagePolicy(raw string, partition, region string) bool {
	if len(raw) == 0 || len(raw) > 32768 || !uniqueProviderJSON([]byte(raw)) {
		return false
	}
	top, ok := exactObjectKeys([]byte(raw), "Version", "Statement")
	if !ok || !scalarPolicyString(top["Version"], "2012-10-17") {
		return false
	}
	var rows []json.RawMessage
	if json.Unmarshal(top["Statement"], &rows) != nil || len(rows) != 1 {
		return false
	}
	row, ok := exactObjectKeys(rows[0], "Sid", "Effect", "Principal", "Action", "Resource")
	return ok && scalarPolicyString(row["Sid"], "ImageLayersOnly") && scalarPolicyString(row["Effect"], "Allow") && exactPolicyString(row["Principal"], "*") && exactPolicyString(row["Action"], "s3:GetObject") && exactPolicyString(row["Resource"], "arn:"+partition+":s3:::prod-"+region+"-starport-layer-bucket/*")
}
func attackLabRouteTableMatches(table ec2types.RouteTable, cidr, prefix, endpoint string) bool {
	if len(table.Routes) != 2 || len(table.PropagatingVgws) != 0 {
		return false
	}
	local, s3 := false, false
	for _, route := range table.Routes {
		if string(route.State) != "active" || (string(route.Origin) != "CreateRoute" && string(route.Origin) != "CreateRouteTable") || aws.ToString(route.DestinationIpv6CidrBlock) != "" {
			return false
		}
		for _, foreign := range []*string{route.CarrierGatewayId, route.CoreNetworkArn, route.EgressOnlyInternetGatewayId, route.InstanceId, route.InstanceOwnerId, route.IpAddress, route.LocalGatewayId, route.NatGatewayId, route.NetworkInterfaceId, route.OdbNetworkArn, route.TransitGatewayId, route.VpcPeeringConnectionId} {
			if aws.ToString(foreign) != "" {
				return false
			}
		}
		if aws.ToString(route.GatewayId) == "local" && aws.ToString(route.DestinationCidrBlock) == cidr && aws.ToString(route.DestinationPrefixListId) == "" && !local {
			local = true
			continue
		}
		if aws.ToString(route.GatewayId) == endpoint && aws.ToString(route.DestinationCidrBlock) == "" && aws.ToString(route.DestinationPrefixListId) == prefix && !s3 {
			s3 = true
			continue
		}
		return false
	}
	return local && s3
}
func validAttackLabTopologySnapshot(s attackLabTopologySnapshot, authority *AWSAuthorityConfig, t *AWSAttackLabTarget, clusterGroup string, c Config) bool {
	account, vpc := c.Deployment.AccountID, authority.Cluster.VPCID
	if len(s.vpcs) != 1 || aws.ToString(s.vpcs[0].VpcId) != vpc || aws.ToString(s.vpcs[0].OwnerId) != account || string(s.vpcs[0].State) != "available" || s.vpcs[0].IsDefault == nil || aws.ToBool(s.vpcs[0].IsDefault) || len(s.vpcs[0].Ipv6CidrBlockAssociationSet) != 0 {
		return false
	}
	cidr := aws.ToString(s.vpcs[0].CidrBlock)
	vpcPrefix, e := netip.ParsePrefix(cidr)
	if e != nil || !vpcPrefix.Addr().Is4() || vpcPrefix != vpcPrefix.Masked() {
		return false
	}
	ids := append(append([]string{}, t.SubnetIDs...), t.ProductSubnetIDs...)
	if len(t.SubnetIDs) != 2 || len(t.ProductSubnetIDs) < 2 || len(t.ProductSubnetIDs) > 16 || len(s.subnets) != len(ids) {
		return false
	}
	wanted := map[string]bool{}
	for _, id := range ids {
		if id == "" || wanted[id] {
			return false
		}
		wanted[id] = true
	}
	var subnets []netip.Prefix
	runnerAZ := map[string]bool{}
	for _, subnet := range s.subnets {
		id := aws.ToString(subnet.SubnetId)
		if !wanted[id] || aws.ToString(subnet.OwnerId) != account || aws.ToString(subnet.VpcId) != vpc || string(subnet.State) != "available" || subnet.MapPublicIpOnLaunch == nil || aws.ToBool(subnet.MapPublicIpOnLaunch) || len(subnet.Ipv6CidrBlockAssociationSet) != 0 || aws.ToString(subnet.OutpostArn) != "" {
			return false
		}
		delete(wanted, id)
		p, e := netip.ParsePrefix(aws.ToString(subnet.CidrBlock))
		if e != nil || !p.Addr().Is4() || p != p.Masked() || p.Bits() < vpcPrefix.Bits() || !vpcPrefix.Contains(p.Addr()) {
			return false
		}
		for _, other := range subnets {
			if p.Overlaps(other) {
				return false
			}
		}
		subnets = append(subnets, p)
		for _, runner := range t.SubnetIDs {
			if id == runner {
				az := aws.ToString(subnet.AvailabilityZone)
				if az == "" || runnerAZ[az] {
					return false
				}
				runnerAZ[az] = true
			}
		}
	}
	if len(wanted) != 0 || len(runnerAZ) != 2 {
		return false
	}
	mainID := ""
	for _, table := range s.tables {
		if aws.ToString(table.OwnerId) != account || aws.ToString(table.VpcId) != vpc {
			return false
		}
		for _, a := range table.Associations {
			if aws.ToBool(a.Main) {
				if mainID != "" {
					return false
				}
				mainID = aws.ToString(table.RouteTableId)
			}
		}
	}
	if mainID == "" || mainID == t.IsolatedRouteTableID {
		return false
	}
	if len(s.prefixes) != 1 || aws.ToString(s.prefixes[0].PrefixListId) == "" || aws.ToString(s.prefixes[0].PrefixListName) != "com.amazonaws."+c.Deployment.Region+".s3" || len(s.prefixes[0].Cidrs) == 0 {
		return false
	}
	prefix := aws.ToString(s.prefixes[0].PrefixListId)
	for _, id := range t.SubnetIDs {
		table, e := resolveAttackLabSubnetRoute(s.tables, id, vpc, t.IsolatedRouteTableID, true)
		if e != nil || !attackLabRouteTableMatches(table, cidr, prefix, t.EndpointIDs["image-s3"]) {
			return false
		}
	}
	for _, id := range t.ProductSubnetIDs {
		table, e := resolveAttackLabSubnetRoute(s.tables, id, vpc, mainID, false)
		if e != nil || !attackLabRouteTableMatches(table, cidr, prefix, t.EndpointIDs["product-s3"]) {
			return false
		}
	}
	purposes := []string{"ecr.api", "ecr.dkr", "kms", "logs", "secretsmanager", "sqs", "sts", "product-s3", "image-s3"}
	if len(t.EndpointIDs) != len(purposes) || len(s.endpoints) != len(purposes) {
		return false
	}
	endpointPurpose := map[string]string{}
	for _, purpose := range purposes {
		id := t.EndpointIDs[purpose]
		if id == "" || endpointPurpose[id] != "" {
			return false
		}
		endpointPurpose[id] = purpose
	}
	for _, endpoint := range s.endpoints {
		id := aws.ToString(endpoint.VpcEndpointId)
		purpose := endpointPurpose[id]
		if purpose == "" || aws.ToString(endpoint.OwnerId) != account || aws.ToString(endpoint.VpcId) != vpc || string(endpoint.State) != "available" || aws.ToString(endpoint.FailureReason) != "" || endpoint.LastError != nil {
			return false
		}
		delete(endpointPurpose, id)
		service := purpose
		if purpose == "product-s3" || purpose == "image-s3" {
			service = "s3"
		}
		if aws.ToString(endpoint.ServiceName) != "com.amazonaws."+c.Deployment.Region+"."+service || aws.ToString(endpoint.ServiceRegion) != "" && aws.ToString(endpoint.ServiceRegion) != c.Deployment.Region {
			return false
		}
		if service == "s3" {
			table := mainID
			if purpose == "image-s3" {
				table = t.IsolatedRouteTableID
				if !exactAttackLabImagePolicy(aws.ToString(endpoint.PolicyDocument), c.Deployment.Partition, c.Deployment.Region) {
					return false
				}
			}
			if string(endpoint.VpcEndpointType) != "Gateway" || !equalClosedStrings(endpoint.RouteTableIds, []string{table}) || len(endpoint.SubnetIds) != 0 || len(endpoint.Groups) != 0 {
				return false
			}
		} else {
			groups := []string{t.EndpointSecurityGroupID}
			if strings.HasPrefix(service, "ecr.") {
				groups = append(groups, t.ImagePullSecurityGroupID)
			}
			actual := make([]string, 0, len(endpoint.Groups))
			for _, group := range endpoint.Groups {
				actual = append(actual, aws.ToString(group.GroupId))
			}
			if string(endpoint.VpcEndpointType) != "Interface" || endpoint.PrivateDnsEnabled == nil || !*endpoint.PrivateDnsEnabled || !equalClosedStrings(endpoint.SubnetIds, t.ProductSubnetIDs) || !equalClosedStrings(actual, groups) || len(endpoint.RouteTableIds) != 0 {
				return false
			}
		}
	}
	if len(endpointPurpose) != 0 {
		return false
	}
	return attackLabSecurityGroupsMatch(s.groups, t, clusterGroup, account, vpc, cidr, prefix)
}
func attackLabPermissionTuples(rows []ec2types.IpPermission, account, vpc string) ([]string, bool) {
	var out []string
	seen := map[string]bool{}
	for _, row := range rows {
		protocol := aws.ToString(row.IpProtocol)
		if protocol == "6" {
			protocol = "tcp"
		}
		if protocol == "17" {
			protocol = "udp"
		}
		if protocol != "tcp" && protocol != "udp" || row.FromPort == nil || row.ToPort == nil || *row.FromPort != *row.ToPort || len(row.Ipv6Ranges) != 0 {
			return nil, false
		}
		stem := protocol + "/" + strconv.Itoa(int(*row.FromPort)) + "/"
		count := 0
		add := func(value string) bool {
			key := stem + value
			if seen[key] {
				return false
			}
			seen[key] = true
			out = append(out, key)
			count++
			return true
		}
		for _, peer := range row.UserIdGroupPairs {
			if aws.ToString(peer.UserId) != account || aws.ToString(peer.GroupId) == "" || aws.ToString(peer.VpcPeeringConnectionId) != "" || aws.ToString(peer.PeeringStatus) != "" || aws.ToString(peer.VpcId) != "" && aws.ToString(peer.VpcId) != vpc || !add("sg:"+aws.ToString(peer.GroupId)) {
				return nil, false
			}
		}
		for _, peer := range row.IpRanges {
			cidr := aws.ToString(peer.CidrIp)
			p, e := netip.ParsePrefix(cidr)
			if e != nil || !p.Addr().Is4() || p != p.Masked() || !add("cidr:"+cidr) {
				return nil, false
			}
		}
		for _, peer := range row.PrefixListIds {
			if aws.ToString(peer.PrefixListId) == "" || !add("prefix:"+aws.ToString(peer.PrefixListId)) {
				return nil, false
			}
		}
		if count == 0 {
			return nil, false
		}
	}
	sort.Strings(out)
	return out, true
}
func attackLabSecurityGroupsMatch(groups []ec2types.SecurityGroup, t *AWSAttackLabTarget, cluster, account, vpc, cidr, prefix string) bool {
	expectedIDs := []string{t.RunnerSecurityGroupID, t.ProxySecurityGroupID, t.ImagePullSecurityGroupID, t.EndpointSecurityGroupID, cluster}
	if len(groups) != len(expectedIDs) {
		return false
	}
	expected := map[string]bool{}
	for _, id := range expectedIDs {
		if id == "" || expected[id] {
			return false
		}
		expected[id] = true
	}
	byID := map[string]ec2types.SecurityGroup{}
	for _, group := range groups {
		id := aws.ToString(group.GroupId)
		if !expected[id] || aws.ToString(group.OwnerId) != account || aws.ToString(group.VpcId) != vpc {
			return false
		}
		delete(expected, id)
		byID[id] = group
	}
	if len(expected) != 0 {
		return false
	}
	runner, proxy, image, general := t.RunnerSecurityGroupID, t.ProxySecurityGroupID, t.ImagePullSecurityGroupID, t.EndpointSecurityGroupID
	tuples := map[string][2][]string{
		runner: {{"tcp/10250/sg:" + cluster}, {"tcp/8443/sg:" + proxy, "tcp/443/sg:" + image, "tcp/443/prefix:" + prefix, "tcp/443/sg:" + cluster, "udp/53/sg:" + cluster, "tcp/53/sg:" + cluster}},
		proxy:  {{"tcp/8443/sg:" + runner, "tcp/8081/sg:" + cluster}, {"udp/53/sg:" + cluster, "tcp/53/sg:" + cluster, "tcp/443/sg:" + general}},
		image:  {{"tcp/443/sg:" + runner}, {}}, general: {{"tcp/443/cidr:" + cidr}, {}},
	}
	p := tuples[proxy]
	for _, cidr := range t.TargetCIDRs {
		p[1] = append(p[1], "tcp/443/cidr:"+cidr)
	}
	for _, cidr := range t.DatabaseCIDRs {
		p[1] = append(p[1], "tcp/5432/cidr:"+cidr)
	}
	tuples[proxy] = p
	for id, want := range tuples {
		group := byID[id]
		in, ok := attackLabPermissionTuples(group.IpPermissions, account, vpc)
		if !ok || !equalClosedStrings(in, want[0]) {
			return false
		}
		out, ok := attackLabPermissionTuples(group.IpPermissionsEgress, account, vpc)
		if !ok || !equalClosedStrings(out, want[1]) {
			return false
		}
	}
	// The cluster SG also contains AWS-managed default/self rules. Require the
	// original explicit reciprocal permissions without inventing a closed cluster
	// SG baseline or claiming the eventual ENI's effective security-group union.
	for _, wanted := range []struct {
		protocol string
		port     int32
		peer     string
	}{{"tcp", 443, runner}, {"udp", 53, runner}, {"tcp", 53, runner}, {"udp", 53, proxy}, {"tcp", 53, proxy}} {
		found := false
		for _, row := range byID[cluster].IpPermissions {
			if aws.ToString(row.IpProtocol) != wanted.protocol || aws.ToInt32(row.FromPort) != wanted.port || aws.ToInt32(row.ToPort) != wanted.port {
				continue
			}
			for _, peer := range row.UserIdGroupPairs {
				found = found || aws.ToString(peer.GroupId) == wanted.peer && aws.ToString(peer.UserId) == account
			}
		}
		if !found {
			return false
		}
	}
	return true
}
