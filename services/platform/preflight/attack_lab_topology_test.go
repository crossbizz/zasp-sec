package preflight

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
)

type topologyXML map[string]any

func topologyXMLBytes(name string, value any) string {
	var b bytes.Buffer
	b.WriteString("<" + name + ">")
	switch v := value.(type) {
	case topologyXML:
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			b.WriteString(topologyXMLBytes(k, v[k]))
		}
	case []any:
		for _, item := range v {
			b.WriteString(topologyXMLBytes("item", item))
		}
	case string:
		_ = xml.EscapeText(&b, []byte(v))
	case bool:
		if v {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	}
	b.WriteString("</" + name + ">")
	return b.String()
}
func topologyGroup(protocol, port, id string) topologyXML {
	return topologyXML{"ipProtocol": protocol, "fromPort": port, "toPort": port, "groups": []any{topologyXML{"groupId": id, "userId": "123456789012"}}}
}
func topologyCIDR(protocol, port, cidr string) topologyXML {
	return topologyXML{"ipProtocol": protocol, "fromPort": port, "toPort": port, "ipRanges": []any{topologyXML{"cidrIp": cidr}}}
}
func attackLabTopologyTarget() *AWSAttackLabTarget {
	target := attackLabTargetFixture()
	target.ProductSubnetIDs = []string{"subnet-33333333333333333", "subnet-44444444444444444"}
	target.IsolatedRouteTableID = "rtb-22222222222222222"
	target.RunnerSecurityGroupID = "sg-11111111111111111"
	target.ProxySecurityGroupID = "sg-22222222222222222"
	target.ImagePullSecurityGroupID = "sg-33333333333333333"
	target.EndpointSecurityGroupID = "sg-44444444444444444"
	target.TargetCIDRs = []string{"203.0.113.0/28"}
	target.DatabaseCIDRs = []string{"10.30.0.0/24"}
	target.EndpointIDs = map[string]string{}
	for i, purpose := range []string{"ecr.api", "ecr.dkr", "kms", "logs", "secretsmanager", "sqs", "sts", "product-s3", "image-s3"} {
		target.EndpointIDs[purpose] = "vpce-" + strings.Repeat(string(rune('1'+i)), 17)
	}
	return target
}

type attackLabTopologyTransport struct {
	mode       string
	target     *AWSAttackLabTarget
	calls      []string
	routePages int
	forbidden  bool
}

func (tr *attackLabTopologyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	raw, _ := io.ReadAll(io.LimitReader(req.Body, 65537))
	q, _ := url.ParseQuery(string(raw))
	action := q.Get("Action")
	tr.calls = append(tr.calls, action)
	if req.Method != "POST" {
		tr.forbidden = true
		return nil, ErrRejected
	}
	owner, vpc, clusterSG := "123456789012", "vpc-11111111111111111", "sg-55555555555555555"
	if tr.mode == "wrong-owner" {
		owner = "999999999999"
	}
	runner, proxy, image, general := tr.target.RunnerSecurityGroupID, tr.target.ProxySecurityGroupID, tr.target.ImagePullSecurityGroupID, tr.target.EndpointSecurityGroupID
	prefix := "pl-11111111"
	answer := topologyXML{}
	switch action {
	case "DescribeVpcs":
		answer["vpcSet"] = []any{topologyXML{"vpcId": vpc, "ownerId": owner, "cidrBlock": "10.80.0.0/16", "state": "available", "isDefault": false}}
	case "DescribeSubnets":
		var subnets []any
		ids := append(append([]string{}, tr.target.SubnetIDs...), tr.target.ProductSubnetIDs...)
		cidrs := []string{"10.80.32.0/20", "10.80.48.0/20", "10.80.0.0/20", "10.80.16.0/20"}
		for i, id := range ids {
			cidr := cidrs[i]
			if tr.mode == "overlapping-subnets" && i == 1 {
				cidr = cidrs[0]
			}
			svpc := vpc
			if tr.mode == "foreign-subnet" && i == 0 {
				svpc = "vpc-99999999999999999"
			}
			subnets = append(subnets, topologyXML{"subnetId": id, "ownerId": owner, "vpcId": svpc, "cidrBlock": cidr, "availabilityZone": []string{"us-west-2a", "us-west-2b"}[i%2], "state": "available", "mapPublicIpOnLaunch": tr.mode == "public-subnet" && i == 0})
		}
		answer["subnetSet"] = subnets
	case "DescribeRouteTables":
		tr.routePages++
		mainID := "rtb-11111111111111111"
		isolated := tr.target.IsolatedRouteTableID
		local := topologyXML{"destinationCidrBlock": "10.80.0.0/16", "gatewayId": "local", "state": "active", "origin": "CreateRouteTable"}
		main := topologyXML{"routeTableId": mainID, "vpcId": vpc, "ownerId": owner, "associationSet": []any{topologyXML{"main": true, "routeTableId": mainID, "associationState": topologyXML{"state": "associated"}}}, "routeSet": []any{local, topologyXML{"destinationPrefixListId": prefix, "gatewayId": tr.target.EndpointIDs["product-s3"], "state": "active", "origin": "CreateRoute"}}}
		associations := []any{}
		for _, id := range tr.target.SubnetIDs {
			associations = append(associations, topologyXML{"main": false, "subnetId": id, "routeTableId": isolated, "associationState": topologyXML{"state": "associated"}})
		}
		if tr.mode == "implicit-runner" {
			associations = []any{}
		}
		routes := []any{local, topologyXML{"destinationPrefixListId": prefix, "gatewayId": tr.target.EndpointIDs["image-s3"], "state": "active", "origin": "CreateRoute"}}
		if tr.mode == "nat-route" {
			routes = append(routes, topologyXML{"destinationCidrBlock": "0.0.0.0/0", "natGatewayId": "nat-11111111111111111", "state": "active"})
		}
		isolatedTable := topologyXML{"routeTableId": isolated, "vpcId": vpc, "ownerId": owner, "associationSet": associations, "routeSet": routes}
		tables := []any{main, isolatedTable}
		if tr.mode == "duplicate-main" {
			other := topologyXML{"routeTableId": "rtb-33333333333333333", "vpcId": vpc, "ownerId": owner, "associationSet": []any{topologyXML{"main": true, "routeTableId": "rtb-33333333333333333", "associationState": topologyXML{"state": "associated"}}}}
			tables = append(tables, other)
		}
		if tr.mode == "paged-routes" {
			if tr.routePages == 1 {
				tables = []any{main}
				answer["nextToken"] = "second"
			} else {
				tables = []any{isolatedTable}
			}
		}
		if tr.mode == "repeated-route-cursor" {
			tables = []any{main}
			answer["nextToken"] = "repeated"
		}
		answer["routeTableSet"] = tables
	case "DescribeSecurityGroups":
		runnerOut := []any{topologyGroup("tcp", "8443", proxy), topologyGroup("tcp", "443", image), topologyXML{"ipProtocol": "tcp", "fromPort": "443", "toPort": "443", "prefixListIds": []any{topologyXML{"prefixListId": prefix}}}, topologyGroup("tcp", "443", clusterSG), topologyGroup("udp", "53", clusterSG), topologyGroup("tcp", "53", clusterSG)}
		if tr.mode == "widened-runner-sg" {
			runnerOut = append(runnerOut, topologyCIDR("tcp", "443", "0.0.0.0/0"))
		}
		proxyOut := []any{topologyGroup("udp", "53", clusterSG), topologyGroup("tcp", "53", clusterSG), topologyGroup("tcp", "443", general), topologyCIDR("tcp", "443", tr.target.TargetCIDRs[0]), topologyCIDR("tcp", "5432", tr.target.DatabaseCIDRs[0])}
		clusterIn := []any{topologyXML{"ipProtocol": "-1", "groups": []any{topologyXML{"groupId": clusterSG, "userId": owner}}}, topologyGroup("tcp", "443", runner), topologyGroup("udp", "53", runner), topologyGroup("tcp", "53", runner), topologyGroup("udp", "53", proxy), topologyGroup("tcp", "53", proxy)}
		group := func(id string, in, out []any) topologyXML {
			return topologyXML{"groupId": id, "groupName": "fixture-group", "ownerId": owner, "vpcId": vpc, "ipPermissions": in, "ipPermissionsEgress": out}
		}
		answer["securityGroupInfo"] = []any{group(runner, []any{topologyGroup("tcp", "10250", clusterSG)}, runnerOut), group(proxy, []any{topologyGroup("tcp", "8443", runner), topologyGroup("tcp", "8081", clusterSG)}, proxyOut), group(image, []any{topologyGroup("tcp", "443", runner)}, nil), group(general, []any{topologyCIDR("tcp", "443", "10.80.0.0/16")}, nil), group(clusterSG, clusterIn, []any{topologyXML{"ipProtocol": "-1", "ipRanges": []any{topologyXML{"cidrIp": "0.0.0.0/0"}}}})}
	case "DescribeVpcEndpoints":
		var endpoints []any
		for purpose, id := range tr.target.EndpointIDs {
			service := purpose
			if purpose == "product-s3" || purpose == "image-s3" {
				service = "s3"
			}
			e := topologyXML{"vpcEndpointId": id, "vpcId": vpc, "ownerId": owner, "state": "available", "serviceName": "com.amazonaws.us-west-2." + service}
			if service == "s3" {
				e["vpcEndpointType"] = "Gateway"
				table := "rtb-11111111111111111"
				policy := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"*","Resource":"*"}]}`
				if purpose == "image-s3" {
					table = tr.target.IsolatedRouteTableID
					resource := "arn:aws:s3:::prod-us-west-2-starport-layer-bucket/*"
					if tr.mode == "widened-image-policy" {
						resource = "*"
					}
					b, _ := json.Marshal(map[string]any{"Version": "2012-10-17", "Statement": []any{map[string]any{"Sid": "ImageLayersOnly", "Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": resource}}})
					policy = string(b)
				}
				e["routeTableIdSet"] = []any{table}
				e["policyDocument"] = policy
			} else {
				e["vpcEndpointType"] = "Interface"
				e["privateDnsEnabled"] = true
				e["subnetIdSet"] = []any{tr.target.ProductSubnetIDs[0], tr.target.ProductSubnetIDs[1]}
				groups := []any{topologyXML{"groupId": general}}
				if strings.HasPrefix(service, "ecr.") {
					groups = append(groups, topologyXML{"groupId": image})
				}
				e["groupSet"] = groups
			}
			if tr.mode == "foreign-endpoint-service" && purpose == "ecr.api" {
				e["serviceName"] = "com.amazonaws.us-west-2.ec2"
			}
			if tr.mode == "missing-endpoint" && purpose == "sts" {
				continue
			}
			endpoints = append(endpoints, e)
		}
		answer["vpcEndpointSet"] = endpoints
	case "DescribePrefixLists":
		name := "com.amazonaws.us-west-2.s3"
		if tr.mode == "foreign-prefix" {
			name = "com.amazonaws.us-east-1.s3"
		}
		answer["prefixListSet"] = []any{topologyXML{"prefixListId": prefix, "prefixListName": name, "cidrSet": []any{"52.92.0.0/16"}}}
	default:
		tr.forbidden = true
		return nil, ErrRejected
	}
	status := 200
	body := topologyXMLBytes(action+"Response", answer)
	if tr.mode == "denied" {
		status = 403
		body = `<Response><Errors><Error><Code>UnauthorizedOperation</Code><Message>NEVER_REFLECT_PROVIDER_TEXT</Message></Error></Errors></Response>`
	}
	return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": []string{"text/xml"}}, Body: io.NopCloser(strings.NewReader(body)), Request: req}, nil
}
func TestAttackLabActualTopologyJoinsAndFiniteMainFallback(t *testing.T) {
	for _, mode := range []string{"observed", "paged-routes", "public-subnet", "overlapping-subnets", "foreign-subnet", "wrong-owner", "implicit-runner", "duplicate-main", "nat-route", "widened-runner-sg", "widened-image-policy", "foreign-endpoint-service", "missing-endpoint", "foreign-prefix", "repeated-route-cursor", "denied", "disabled"} {
		t.Run(mode, func(t *testing.T) {
			authority, _, _ := awsAuthorityFixtureConfig(t)
			target := attackLabTopologyTarget()
			tr := &attackLabTopologyTransport{mode: mode, target: target}
			r := &Runner{config: sdkContractConfig(t), http: &http.Client{Transport: tr}}
			sdk := aws.Config{Region: "us-west-2", HTTPClient: r.http, Credentials: aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
				return aws.Credentials{AccessKeyID: "fixture-inspector-key", SecretAccessKey: "fixture-inspector-secret"}, nil
			}), Retryer: func() aws.Retryer { return aws.NopRetryer{} }}
			evidence := r.observeAttackLabTopology(context.Background(), sdk, authority, target, "sg-55555555555555555", mode != "disabled")
			if mode == "disabled" {
				if len(tr.calls) != 0 || evidence.topology {
					t.Fatal("disabled feature read topology or became observed")
				}
				return
			}
			if len(tr.calls) == 0 || len(tr.calls) > 24 || tr.routePages > 4 || tr.forbidden {
				t.Fatal("actual finite read-only EC2 boundary absent or widened")
			}
			expected := mode == "observed" || mode == "paged-routes"
			if evidence.topology != expected {
				t.Fatal("complete actual topology missing or widened/incomplete topology accepted")
			}
		})
	}
}
