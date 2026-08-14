package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestValidateLoopbackEndpoint(t *testing.T) {
	valid := httptest.NewServer(http.NotFoundHandler())
	defer valid.Close()

	got, err := ValidateLoopbackEndpoint(context.Background(), valid.URL)
	if err != nil || got != valid.URL {
		t.Fatalf("ValidateLoopbackEndpoint() = %q, %v; want %q, nil", got, err, valid.URL)
	}
	for _, raw := range []string{
		"", "ftp://127.0.0.1:4566", "http://example.com:4566", "http://127.0.0.1", "http://127.0.0.1:0", "http://user@127.0.0.1:4566", "http://127.0.0.1:4566/path", "http://127.0.0.1:4566?x=1", "http://[::2]:4566",
	} {
		t.Run(raw, func(t *testing.T) {
			if _, err := ValidateLoopbackEndpoint(context.Background(), raw); !errors.Is(err, errConfiguration) {
				t.Fatalf("ValidateLoopbackEndpoint(%q) error = %v, want configuration error", raw, err)
			}
		})
	}
}

func TestSDKBoundary_UsesExactIAMAndSTSQueryOperations(t *testing.T) {
	marker := "0123456789abcdef"
	principal, role := expectedSpecs(ProofOptions{Marker: marker})
	var actions []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/" {
			t.Fatalf("request = %s %s, want POST /", r.Method, r.URL.Path)
		}
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		action := r.Form.Get("Action")
		actions = append(actions, action)
		version := "2010-05-08"
		if action == "GetCallerIdentity" || action == "AssumeRole" {
			version = "2011-06-15"
		}
		if r.Form.Get("Version") != version {
			t.Fatalf("%s Version = %q", action, r.Form.Get("Version"))
		}
		credential := "000000000041"
		if strings.Contains(action, "Role") || (action == "GetUser" && r.Form.Get("UserName") == "") {
			credential = "000000000042"
		}
		if action == "AssumeRole" {
			credential = "AKIA0123456789ABCDEF"
		}
		if !strings.Contains(r.Header.Get("Authorization"), "Credential="+credential+"/") && action != "GetRole" && action != "ListRoles" {
			t.Fatalf("%s authorization did not use namespace credential %s", action, credential)
		}
		switch action {
		case "GetCallerIdentity":
			writeXML(w, `<GetCallerIdentityResponse><GetCallerIdentityResult><Account>000000000041</Account><Arn>arn:aws:iam::000000000041:root</Arn><UserId>source-root</UserId></GetCallerIdentityResult></GetCallerIdentityResponse>`)
		case "ListUsers":
			if r.Form.Get("PathPrefix") != "" {
				t.Fatalf("ListUsers PathPrefix = %q", r.Form.Get("PathPrefix"))
			}
			writeXML(w, `<ListUsersResponse><ListUsersResult><Users></Users></ListUsersResult></ListUsersResponse>`)
		case "CreateUser":
			assertForm(t, r, map[string]string{"UserName": principal.Name, "Path": principal.Path, "Tags.member.1.Key": "proof", "Tags.member.1.Value": marker})
			writeXML(w, userResponse("CreateUser", principal, "AIDA0123456789ABCDEF"))
		case "GetUser":
			if r.Form.Get("UserName") == "" {
				writeXML(w, `<GetUserResponse><GetUserResult><User><Path>/</Path><UserName>target-root</UserName><UserId>target-root</UserId><Arn>arn:aws:iam::000000000042:root</Arn></User></GetUserResult></GetUserResponse>`)
				return
			}
			if r.Form.Get("UserName") != principal.Name {
				t.Fatalf("GetUser UserName = %q", r.Form.Get("UserName"))
			}
			writeXML(w, userResponse("GetUser", principal, "AIDA0123456789ABCDEF"))
		case "CreateAccessKey":
			if r.Form.Get("UserName") != principal.Name {
				t.Fatalf("CreateAccessKey UserName = %q", r.Form.Get("UserName"))
			}
			writeXML(w, `<CreateAccessKeyResponse><CreateAccessKeyResult><AccessKey><AccessKeyId>AKIA0123456789ABCDEF</AccessKeyId><SecretAccessKey>source-secret</SecretAccessKey><Status>Active</Status><UserName>`+principal.Name+`</UserName></AccessKey></CreateAccessKeyResult></CreateAccessKeyResponse>`)
		case "ListAccessKeys":
			if r.Form.Get("UserName") != principal.Name {
				t.Fatalf("ListAccessKeys UserName = %q", r.Form.Get("UserName"))
			}
			writeXML(w, `<ListAccessKeysResponse><ListAccessKeysResult><AccessKeyMetadata><member><UserName>`+principal.Name+`</UserName><AccessKeyId>AKIA0123456789ABCDEF</AccessKeyId><Status>Active</Status></member></AccessKeyMetadata></ListAccessKeysResult></ListAccessKeysResponse>`)
		case "CreateRole":
			assertForm(t, r, map[string]string{"RoleName": role.Name, "Path": role.Path, "Description": role.Description, "AssumeRolePolicyDocument": role.TrustPolicy, "Tags.member.1.Key": "proof", "Tags.member.1.Value": marker})
			writeXML(w, roleResponse("CreateRole", role, "AROA0123456789ABCDEF"))
		case "GetRole":
			if r.Form.Get("RoleName") != role.Name {
				t.Fatalf("GetRole RoleName = %q", r.Form.Get("RoleName"))
			}
			writeXML(w, roleResponse("GetRole", role, "AROA0123456789ABCDEF"))
		case "PutRolePolicy":
			assertForm(t, r, map[string]string{"RoleName": role.Name, "PolicyName": role.PolicyName, "PolicyDocument": role.PermissionPolicy})
			writeXML(w, `<PutRolePolicyResponse><ResponseMetadata><RequestId>x</RequestId></ResponseMetadata></PutRolePolicyResponse>`)
		case "GetRolePolicy":
			assertForm(t, r, map[string]string{"RoleName": role.Name, "PolicyName": role.PolicyName})
			writeXML(w, `<GetRolePolicyResponse><GetRolePolicyResult><RoleName>`+role.Name+`</RoleName><PolicyName>`+role.PolicyName+`</PolicyName><PolicyDocument>`+xmlEscape(pinnedLocalStackPolicyFixture(role.PermissionPolicy))+`</PolicyDocument></GetRolePolicyResult></GetRolePolicyResponse>`)
		case "AssumeRole":
			assertForm(t, r, map[string]string{"RoleArn": role.ARN, "RoleSessionName": "session", "ExternalId": "external", "SourceIdentity": "source", "Tags.member.1.Key": "proof", "Tags.member.1.Value": marker})
			writeXML(w, `<AssumeRoleResponse><AssumeRoleResult><Credentials><AccessKeyId>ASIA0123456789ABCDEF</AccessKeyId><SecretAccessKey>assumed-secret</SecretAccessKey><SessionToken>assumed-token</SessionToken><Expiration>2030-01-01T00:00:00Z</Expiration></Credentials><AssumedRoleUser><Arn>arn:aws:sts::000000000042:assumed-role/`+role.Name+`/session</Arn><AssumedRoleId>AROA0123456789ABCDEF:session</AssumedRoleId></AssumedRoleUser><SourceIdentity>source</SourceIdentity></AssumeRoleResult></AssumeRoleResponse>`)
		case "ListRoles":
			if strings.Contains(r.Header.Get("Authorization"), "Credential=000000000041/") {
				t.Fatal("assumed ListRoles used source credentials")
			}
			writeError(w, http.StatusForbidden, "AccessDenied", "explicit deny")
		case "DeleteRolePolicy":
			assertExactForm(t, r, map[string]string{"Action": action, "Version": "2010-05-08", "RoleName": role.Name, "PolicyName": role.PolicyName})
			writeXML(w, `<DeleteRolePolicyResponse><ResponseMetadata><RequestId>x</RequestId></ResponseMetadata></DeleteRolePolicyResponse>`)
		case "DeleteRole":
			assertExactForm(t, r, map[string]string{"Action": action, "Version": "2010-05-08", "RoleName": role.Name})
			writeXML(w, `<DeleteRoleResponse><ResponseMetadata><RequestId>x</RequestId></ResponseMetadata></DeleteRoleResponse>`)
		case "DeleteAccessKey":
			assertExactForm(t, r, map[string]string{"Action": action, "Version": "2010-05-08", "UserName": principal.Name, "AccessKeyId": "AKIA0123456789ABCDEF"})
			writeXML(w, `<DeleteAccessKeyResponse><ResponseMetadata><RequestId>x</RequestId></ResponseMetadata></DeleteAccessKeyResponse>`)
		case "DeleteUser":
			assertExactForm(t, r, map[string]string{"Action": action, "Version": "2010-05-08", "UserName": principal.Name})
			writeXML(w, `<DeleteUserResponse><ResponseMetadata><RequestId>x</RequestId></ResponseMetadata></DeleteUserResponse>`)
		default:
			t.Fatalf("unexpected Action %q", action)
		}
	}))
	defer server.Close()

	b, err := NewSDKBoundary(context.Background(), server.URL, sourceNamespace, targetNamespace)
	if err != nil {
		t.Fatalf("NewSDKBoundary() error = %v", err)
	}
	if _, err := b.SourceIdentity(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := b.TargetIdentity(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := b.ListPrincipals(context.Background(), principal.Path); err != nil {
		t.Fatal(err)
	}
	createdPrincipal, err := b.CreatePrincipal(context.Background(), principal)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.InspectPrincipal(context.Background(), createdPrincipal.Name); err != nil {
		t.Fatal(err)
	}
	keyID, keySecret, err := b.CreateAccessKey(context.Background(), principal.Name)
	if err != nil || keyID == "" || keySecret == "" {
		t.Fatalf("CreateAccessKey() = %q, %q, %v", keyID, keySecret, err)
	}
	if keys, err := b.ListAccessKeys(context.Background(), principal.Name); err != nil || len(keys) != 1 || keys[0] != keyID {
		t.Fatalf("ListAccessKeys() = %#v, %v", keys, err)
	}
	createdRole, err := b.CreateRole(context.Background(), role)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.InspectRole(context.Background(), createdRole.Name); err != nil {
		t.Fatal(err)
	}
	if err := b.PutRolePolicy(context.Background(), role.Name, role.PolicyName, role.PermissionPolicy); err != nil {
		t.Fatal(err)
	}
	if policy, err := b.GetRolePolicy(context.Background(), role.Name, role.PolicyName); err != nil || !sameJSON(policy, role.PermissionPolicy) {
		t.Fatalf("GetRolePolicy() = %q, %v", policy, err)
	}
	session, err := b.AssumeRole(context.Background(), AssumeRequest{RoleARN: role.ARN, ExternalID: "external", SessionName: "session", SourceIdentity: "source", Tags: map[string]string{"proof": marker}}, keyID, keySecret)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.AllowedGetRole(context.Background(), session, role.Name); err != nil {
		t.Fatal(err)
	}
	if err := b.DeniedListRoles(context.Background(), session); !errors.As(err, new(explicitDenyError)) {
		t.Fatalf("DeniedListRoles() error = %v, want explicit denial", err)
	}
	if err := b.DeleteRolePolicy(context.Background(), role.Name, role.PolicyName); err != nil {
		t.Fatal(err)
	}
	if err := b.DeleteAccessKey(context.Background(), principal.Name, keyID); err != nil {
		t.Fatal(err)
	}
	if err := b.DeletePrincipal(context.Background(), principal.Name); err != nil {
		t.Fatal(err)
	}
	if err := b.DeleteRole(context.Background(), role.Name); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(actions, ","); !strings.Contains(got, "GetCallerIdentity,GetUser,ListUsers,CreateUser,GetUser,CreateAccessKey,ListAccessKeys,CreateRole,GetRole,GetRolePolicy,PutRolePolicy,GetRolePolicy,AssumeRole,GetRole,ListRoles,DeleteRolePolicy,DeleteAccessKey,DeleteUser,DeleteRole") {
		t.Fatalf("action sequence = %s", got)
	}
}

func TestSDKBoundary_RejectsRedirectsAndBoundsMutationsAndReads(t *testing.T) {
	redirect := httptest.NewServer(http.RedirectHandler("http://127.0.0.1:1/", http.StatusFound))
	defer redirect.Close()
	b, err := NewSDKBoundary(context.Background(), redirect.URL, sourceNamespace, targetNamespace)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.SourceIdentity(context.Background()); !errors.Is(err, errProvider) {
		t.Fatalf("redirect error = %v, want provider", err)
	}

	var mutations, reads int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		switch r.Form.Get("Action") {
		case "CreateUser":
			mutations++
			writeError(w, http.StatusInternalServerError, "ServiceFailure", "retry must not apply")
		case "ListUsers":
			reads++
			if reads == 1 {
				writeError(w, http.StatusInternalServerError, "ServiceFailure", "retry once")
			} else {
				writeXML(w, `<ListUsersResponse><ListUsersResult><Users></Users></ListUsersResult></ListUsersResponse>`)
			}
		default:
			t.Fatalf("unexpected action %q", r.Form.Get("Action"))
		}
	}))
	defer server.Close()
	b, err = NewSDKBoundary(context.Background(), server.URL, sourceNamespace, targetNamespace)
	if err != nil {
		t.Fatal(err)
	}
	principal, _ := expectedSpecs(ProofOptions{Marker: "0123456789abcdef"})
	if _, err := b.CreatePrincipal(context.Background(), principal); !errors.Is(err, errProvider) {
		t.Fatalf("CreatePrincipal() error = %v", err)
	}
	if mutations != 1 {
		t.Fatalf("mutation attempts = %d, want 1", mutations)
	}
	if _, err := b.ListPrincipals(context.Background(), principal.Path); err != nil {
		t.Fatal(err)
	}
	if reads != 2 {
		t.Fatalf("read attempts = %d, want 2", reads)
	}
}

func TestSDKBoundary_RejectsInvalidProviderPolicyRepresentations(t *testing.T) {
	const validRaw = `{"Version":"2012-10-17","Statement":[{"Condition":"space + percent %"}]}`
	const validCanonical = `%7B%22Version%22%3A%222012-10-17%22%2C%22Statement%22%3A%5B%7B%22Condition%22%3A%22space%20%2B%20percent%20%25%22%7D%5D%7D`
	if got, ok := decodeProviderPolicy(validCanonical); !ok || got != validRaw {
		t.Fatalf("decodeProviderPolicy(real canonical representation) = %q, %v", got, ok)
	}

	validWithoutSpaces := `{"Version":"2012-10-17","Statement":[{}]}`
	for _, tc := range []struct {
		name string
		raw  string
	}{
		{name: "raw", raw: validRaw},
		{name: "form", raw: url.QueryEscape(validRaw)},
		{name: "lowercase escape", raw: strings.Replace(validCanonical, "%7B", "%7b", 1)},
		{name: "path segment alias", raw: url.PathEscape(validRaw)},
		{name: "partial", raw: strings.Replace(validCanonical, "%3A", ":", 1)},
		{name: "double", raw: canonicalPolicyFixture(validCanonical)},
		{name: "invalid escape", raw: strings.Replace(validCanonical, "%7B", "%GZ", 1)},
		{name: "duplicate", raw: canonicalPolicyFixture(`{"Version":"2012-10-17","Version":"2012-10-17","Statement":[{}]}`)},
		{name: "case alias", raw: canonicalPolicyFixture(`{"version":"2012-10-17","Statement":[{}]}`)},
		{name: "unknown", raw: canonicalPolicyFixture(`{"Version":"2012-10-17","Statement":[{}],"Unknown":true}`)},
		{name: "missing", raw: canonicalPolicyFixture(`{"Version":"2012-10-17"}`)},
		{name: "null", raw: canonicalPolicyFixture(`null`)},
		{name: "trailing", raw: canonicalPolicyFixture(validWithoutSpaces + ` trailing`)},
		{name: "oversize", raw: strings.Repeat("x", maxBodySize+1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, ok := decodeProviderPolicy(tc.raw); ok {
				t.Fatalf("decodeProviderPolicy(%q) accepted an invalid policy representation", tc.raw)
			}
		})
	}
}

func TestSDKBoundary_DecodesCanonicalRFC3986PolicyOnce(t *testing.T) {
	raw := `{"Version":"2012-10-17","Statement":[{"Condition":"space value %"}]}`
	encoded := canonicalPolicyFixture(raw)
	if got, ok := decodeProviderPolicy(encoded); !ok || got != raw {
		t.Fatalf("decodeProviderPolicy(%q) = %q, %v", encoded, got, ok)
	}
	for _, alias := range []string{raw, url.QueryEscape(raw), strings.ToLower(encoded), canonicalPolicyFixture(encoded), strings.Replace(encoded, "%20", "+", 1)} {
		if _, ok := decodeProviderPolicy(alias); ok {
			t.Fatalf("accepted noncanonical policy alias %q", alias)
		}
	}
}

func TestSDKBoundary_DecodesPinnedLocalStackPathSafePolicyOnce(t *testing.T) {
	raw := `{"Version":"2012-10-17","Statement":[{"Condition":"arn:aws:iam::000000000041:user/proof/name"}]}`
	encoded := pinnedLocalStackPolicyFixture(raw)
	if got, ok := decodeProviderPolicy(encoded); !ok || got != raw {
		t.Fatalf("decodeProviderPolicy(pinned LocalStack representation) = %q, %v", got, ok)
	}
	if _, ok := decodeProviderPolicy(canonicalPolicyFixture(raw)); ok {
		t.Fatal("accepted fully slash-escaped alias for pinned LocalStack representation")
	}
}

func TestSDKBoundary_DecodesPinnedLocalStackUTF8AndPreservesOnlySlash(t *testing.T) {
	const raw = `{"Version":"2012-10-17","Statement":[{"Condition":"AZaz09-._~ :@&=+$,/?#[]!é"}]}`
	const canonical = `%7B%22Version%22%3A%222012-10-17%22%2C%22Statement%22%3A%5B%7B%22Condition%22%3A%22AZaz09-._~%20%3A%40%26%3D%2B%24%2C/%3F%23%5B%5D%21%C3%A9%22%7D%5D%7D`
	if got, ok := decodeProviderPolicy(canonical); !ok || got != raw {
		t.Fatalf("decodeProviderPolicy(canonical UTF-8 representation) = %q, %v", got, ok)
	}
}

func TestSDKBoundary_RejectsCanonicalPoliciesContainingInvalidUTF8(t *testing.T) {
	const prefix = `%7B%22Version%22%3A%222012-10-17%22%2C%22Statement%22%3A%5B%7B%22Condition%22%3A%22`
	const suffix = `%22%7D%5D%7D`
	for _, tc := range []struct {
		name, encodedBytes string
	}{
		{name: "invalid byte", encodedBytes: `%FF`},
		{name: "truncated two byte sequence", encodedBytes: `%C3`},
		{name: "malformed two byte sequence", encodedBytes: `%C3%28`},
		{name: "truncated three byte sequence", encodedBytes: `%E2%82`},
		{name: "truncated four byte sequence", encodedBytes: `%F0%9F%92`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			encoded := prefix + tc.encodedBytes + suffix
			if decoded, ok := decodeProviderPolicy(encoded); ok {
				parsed, _ := decodeStrictJSON(decoded)
				t.Fatalf("decodeProviderPolicy(%q) accepted invalid UTF-8 as %#v", encoded, parsed)
			}
		})
	}
}

func TestSDKBoundary_ClassifiesInvalidUTF8InProviderPolicyFields(t *testing.T) {
	_, role := expectedSpecs(ProofOptions{Marker: "0123456789abcdef"})
	for _, encodedBytes := range []string{`%FF`, `%E2%82`, `%C3%28`} {
		t.Run("trust policy "+encodedBytes, func(t *testing.T) {
			invalidPolicy := invalidUTF8PolicyFixture(encodedBytes)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if err := r.ParseForm(); err != nil {
					t.Fatal(err)
				}
				switch r.Form.Get("Action") {
				case "GetRole":
					response := roleResponse("GetRole", role, "AROA0123456789ABCDEF")
					response = strings.Replace(response, pinnedLocalStackPolicyFixture(role.TrustPolicy), invalidPolicy, 1)
					writeXML(w, response)
				case "GetRolePolicy":
					writeXML(w, `<GetRolePolicyResponse><GetRolePolicyResult><RoleName>`+role.Name+`</RoleName><PolicyName>`+role.PolicyName+`</PolicyName><PolicyDocument>`+xmlEscape(pinnedLocalStackPolicyFixture(role.PermissionPolicy))+`</PolicyDocument></GetRolePolicyResult></GetRolePolicyResponse>`)
				default:
					t.Fatalf("unexpected Action %q", r.Form.Get("Action"))
				}
			}))
			defer server.Close()

			boundary, err := NewSDKBoundary(context.Background(), server.URL, sourceNamespace, targetNamespace)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := boundary.InspectRole(context.Background(), role.Name); !errors.Is(err, errProvider) {
				t.Fatalf("InspectRole() error = %v, want provider error", err)
			}
		})

		t.Run("permission policy "+encodedBytes, func(t *testing.T) {
			invalidPolicy := invalidUTF8PolicyFixture(encodedBytes)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				writeXML(w, `<GetRolePolicyResponse><GetRolePolicyResult><RoleName>`+role.Name+`</RoleName><PolicyName>`+role.PolicyName+`</PolicyName><PolicyDocument>`+invalidPolicy+`</PolicyDocument></GetRolePolicyResult></GetRolePolicyResponse>`)
			}))
			defer server.Close()

			boundary, err := NewSDKBoundary(context.Background(), server.URL, sourceNamespace, targetNamespace)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := boundary.GetRolePolicy(context.Background(), role.Name, role.PolicyName); !errors.Is(err, errProvider) {
				t.Fatalf("GetRolePolicy() error = %v, want provider error", err)
			}
		})
	}
}

func TestSDKBoundary_RejectsHostileResolverRebinding(t *testing.T) {
	targetHits := 0
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		targetHits++
		writeXML(w, `<GetCallerIdentityResponse/>`)
	}))
	defer target.Close()
	_, port, err := net.SplitHostPort(strings.TrimPrefix(target.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}

	originalLookup := lookupIPAddr
	defer func() { lookupIPAddr = originalLookup }()
	lookups := 0
	lookupIPAddr = func(context.Context, string) ([]net.IPAddr, error) {
		lookups++
		if lookups == 1 {
			return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
		}
		return []net.IPAddr{{IP: net.ParseIP("203.0.113.10")}}, nil
	}

	b, err := NewSDKBoundary(context.Background(), "http://proof.invalid:"+port, sourceNamespace, targetNamespace)
	if err != nil {
		t.Fatalf("NewSDKBoundary() error = %v", err)
	}
	if _, err := b.SourceIdentity(context.Background()); !errors.Is(err, errProvider) {
		t.Fatalf("SourceIdentity() error = %v, want provider rejection", err)
	}
	if lookups < 2 || targetHits != 0 {
		t.Fatalf("lookups = %d, target hits = %d; want rebinding rejected before dial", lookups, targetHits)
	}
}

func TestSDKBoundary_BypassesAmbientProxy(t *testing.T) {
	targetHits := 0
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		targetHits++
		writeXML(w, `<GetCallerIdentityResponse><GetCallerIdentityResult><Account>000000000041</Account><Arn>arn:aws:iam::000000000041:root</Arn><UserId>source-root</UserId></GetCallerIdentityResult></GetCallerIdentityResponse>`)
	}))
	defer target.Close()
	_, port, err := net.SplitHostPort(strings.TrimPrefix(target.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	proxyHits := 0
	proxy := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { proxyHits++ }))
	defer proxy.Close()
	t.Setenv("HTTP_PROXY", proxy.URL)
	t.Setenv("HTTPS_PROXY", proxy.URL)
	t.Setenv("ALL_PROXY", proxy.URL)
	t.Setenv("NO_PROXY", "")

	originalLookup := lookupIPAddr
	defer func() { lookupIPAddr = originalLookup }()
	lookupIPAddr = func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
	}
	b, err := NewSDKBoundary(context.Background(), "http://proof.invalid:"+port, sourceNamespace, targetNamespace)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.SourceIdentity(context.Background()); err != nil {
		t.Fatalf("SourceIdentity() error = %v", err)
	}
	if proxyHits != 0 || targetHits != 1 {
		t.Fatalf("proxy hits = %d, target hits = %d; want direct target request", proxyHits, targetHits)
	}
}

func TestSDKBoundary_RejectsWrongAccessKeyOwnerAndStatus(t *testing.T) {
	principal, _ := expectedSpecs(ProofOptions{Marker: "0123456789abcdef"})
	for _, tc := range []struct {
		name, user, status string
	}{
		{name: "wrong username", user: "foreign-user", status: "Active"},
		{name: "inactive", user: principal.Name, status: "Inactive"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				writeXML(w, `<CreateAccessKeyResponse><CreateAccessKeyResult><AccessKey><AccessKeyId>AKIA0123456789ABCDEF</AccessKeyId><SecretAccessKey>source-secret</SecretAccessKey><Status>`+tc.status+`</Status><UserName>`+tc.user+`</UserName></AccessKey></CreateAccessKeyResult></CreateAccessKeyResponse>`)
			}))
			defer server.Close()
			b, err := NewSDKBoundary(context.Background(), server.URL, sourceNamespace, targetNamespace)
			if err != nil {
				t.Fatal(err)
			}
			_, _, err = b.CreateAccessKey(context.Background(), principal.Name)
			var ambiguous ambiguousMutationError
			if !errors.As(err, &ambiguous) {
				t.Fatalf("CreateAccessKey() error = %v, want ambiguous provider response", err)
			}
		})
	}
}

func TestSDKBoundary_AssumedClientRetriesWithinBound(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempts++
		if attempts == 1 {
			writeError(w, http.StatusInternalServerError, "ServiceFailure", "retry")
			return
		}
		writeXML(w, `<GetCallerIdentityResponse><GetCallerIdentityResult><Account>000000000042</Account><Arn>arn:aws:sts::000000000042:assumed-role/role/session</Arn><UserId>role-id:session</UserId></GetCallerIdentityResult></GetCallerIdentityResponse>`)
	}))
	defer server.Close()
	b, err := NewSDKBoundary(context.Background(), server.URL, sourceNamespace, targetNamespace)
	if err != nil {
		t.Fatal(err)
	}
	delay, err := newReadRetryer().RetryDelay(1, errors.New("retry"))
	if err != nil || delay > 500*time.Millisecond {
		t.Fatalf("retry delay = %v, %v; want at most 500ms", delay, err)
	}
	if _, err := b.AssumedIdentity(context.Background(), AssumedSession{AccessKeyID: "ASIA0123456789ABCDEF", SecretAccessKey: "secret", SessionToken: "token"}); err != nil {
		t.Fatalf("AssumedIdentity() error = %v", err)
	}
	if attempts != 2 {
		t.Fatalf("assumed read attempts = %d, want 2", attempts)
	}
}

func TestSDKBoundary_PreservesDefinitiveStatusWhenBodyIsTooLarge(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "1048577")
		writeError(w, http.StatusInternalServerError, "ServiceFailure", "oversized")
	}))
	defer server.Close()
	b, err := NewSDKBoundary(context.Background(), server.URL, sourceNamespace, targetNamespace)
	if err != nil {
		t.Fatal(err)
	}
	principal, _ := expectedSpecs(ProofOptions{Marker: "0123456789abcdef"})
	_, err = b.CreatePrincipal(context.Background(), principal)
	var ambiguous ambiguousMutationError
	if !errors.Is(err, errProvider) || errors.As(err, &ambiguous) {
		t.Fatalf("CreatePrincipal() error = %v, want definitive provider error", err)
	}
}

func TestSDKBoundary_OverlargeSuccessIsAmbiguous(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "1048577")
		_, _ = io.WriteString(w, `<CreateUserResponse/>`)
	}))
	defer server.Close()
	b, err := NewSDKBoundary(context.Background(), server.URL, sourceNamespace, targetNamespace)
	if err != nil {
		t.Fatal(err)
	}
	principal, _ := expectedSpecs(ProofOptions{Marker: "0123456789abcdef"})
	_, err = b.CreatePrincipal(context.Background(), principal)
	var ambiguous ambiguousMutationError
	if !errors.As(err, &ambiguous) {
		t.Fatalf("CreatePrincipal() error = %v, want ambiguous mutation", err)
	}
}

func TestSDKBoundary_RunProofOverLoopback(t *testing.T) {
	for _, tc := range []struct {
		name        string
		enforceDeny bool
	}{
		{name: "allow plus enforced deny passes", enforceDeny: true},
		{name: "allow plus ignored deny fails proof", enforceDeny: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, err := runSDKProofOverLoopback(t, tc.enforceDeny)
			if tc.enforceDeny {
				if err != nil || result != (ProofResult{true, true, true, true, true, true}) {
					t.Fatalf("RunProof() = %#v, %v", result, err)
				}
				return
			}
			if !errors.Is(err, errAuthorization) || !result.Namespaces || !result.Assumed || !result.AllowedRead || result.ExplicitDeny || !result.Cleanup || !result.Audit {
				t.Fatalf("RunProof() with ignored Deny = %#v, %v; want authorization failure after allowed read with cleanup", result, err)
			}
		})
	}
}

func runSDKProofOverLoopback(t *testing.T, enforceDeny bool) (ProofResult, error) {
	t.Helper()
	marker := "0123456789abcdef"
	principal, role := expectedSpecs(ProofOptions{Marker: marker})
	var principalExists, roleExists, policyExists bool
	var storedPolicy string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		switch r.Form.Get("Action") {
		case "GetCallerIdentity":
			if strings.Contains(r.Header.Get("Authorization"), "Credential=ASIA") {
				writeXML(w, `<GetCallerIdentityResponse><GetCallerIdentityResult><Account>000000000042</Account><Arn>arn:aws:sts::000000000042:assumed-role/`+role.Name+`/`+proofPrefix(marker)+`-session</Arn><UserId>AROA0123456789ABCDEF:`+proofPrefix(marker)+`-session</UserId></GetCallerIdentityResult></GetCallerIdentityResponse>`)
			} else {
				writeXML(w, `<GetCallerIdentityResponse><GetCallerIdentityResult><Account>000000000041</Account><Arn>arn:aws:iam::000000000041:root</Arn><UserId>source-root</UserId></GetCallerIdentityResult></GetCallerIdentityResponse>`)
			}
		case "GetUser":
			if r.Form.Get("UserName") == "" {
				writeXML(w, `<GetUserResponse><GetUserResult><User><Path>/</Path><UserName>target-root</UserName><UserId>target-root</UserId><Arn>arn:aws:iam::000000000042:root</Arn></User></GetUserResult></GetUserResponse>`)
			} else {
				writeXML(w, userResponse("GetUser", principal, "AIDA0123456789ABCDEF"))
			}
		case "ListUsers":
			if r.Form.Get("PathPrefix") != "" {
				t.Fatalf("ListUsers PathPrefix = %q, want no path filter", r.Form.Get("PathPrefix"))
			}
			if principalExists {
				writeXML(w, `<ListUsersResponse><ListUsersResult><Users><member><Path>`+principal.Path+`</Path><UserName>`+principal.Name+`</UserName><UserId>AIDA0123456789ABCDEF</UserId><Arn>`+principal.ARN+`</Arn><Tags><member><Key>proof</Key><Value>`+marker+`</Value></member></Tags></member></Users></ListUsersResult></ListUsersResponse>`)
			} else {
				writeXML(w, `<ListUsersResponse><ListUsersResult><Users></Users></ListUsersResult></ListUsersResponse>`)
			}
		case "CreateUser":
			principalExists = true
			writeXML(w, userResponse("CreateUser", principal, "AIDA0123456789ABCDEF"))
		case "CreateAccessKey":
			writeXML(w, `<CreateAccessKeyResponse><CreateAccessKeyResult><AccessKey><AccessKeyId>AKIA0123456789ABCDEF</AccessKeyId><SecretAccessKey>source-secret</SecretAccessKey><Status>Active</Status><UserName>`+principal.Name+`</UserName></AccessKey></CreateAccessKeyResult></CreateAccessKeyResponse>`)
		case "ListAccessKeys":
			writeXML(w, `<ListAccessKeysResponse><ListAccessKeysResult><AccessKeyMetadata><member><UserName>`+principal.Name+`</UserName><AccessKeyId>AKIA0123456789ABCDEF</AccessKeyId><Status>Active</Status></member></AccessKeyMetadata></ListAccessKeysResult></ListAccessKeysResponse>`)
		case "ListRoles":
			if strings.Contains(r.Header.Get("Authorization"), "Credential=ASIA") {
				if evaluatorAllowsListRoles(t, storedPolicy, enforceDeny) {
					writeXML(w, `<ListRolesResponse><ListRolesResult><Roles></Roles></ListRolesResult></ListRolesResponse>`)
				} else {
					writeError(w, http.StatusForbidden, "AccessDenied", "policy evaluator denial")
				}
				return
			}
			if r.Form.Get("PathPrefix") != "" {
				t.Fatalf("ListRoles PathPrefix = %q, want no path filter", r.Form.Get("PathPrefix"))
			}
			if roleExists {
				writeXML(w, `<ListRolesResponse><ListRolesResult><Roles><member><Path>`+role.Path+`</Path><RoleName>`+role.Name+`</RoleName><RoleId>AROA0123456789ABCDEF</RoleId><Arn>`+role.ARN+`</Arn><AssumeRolePolicyDocument>`+xmlEscape(pinnedLocalStackPolicyFixture(role.TrustPolicy))+`</AssumeRolePolicyDocument><Description>`+role.Description+`</Description><Tags><member><Key>proof</Key><Value>`+marker+`</Value></member></Tags></member></Roles></ListRolesResult></ListRolesResponse>`)
			} else {
				writeXML(w, `<ListRolesResponse><ListRolesResult><Roles></Roles></ListRolesResult></ListRolesResponse>`)
			}
		case "CreateRole":
			roleExists = true
			writeXML(w, roleResponse("CreateRole", role, "AROA0123456789ABCDEF"))
		case "GetRole":
			writeXML(w, roleResponse("GetRole", role, "AROA0123456789ABCDEF"))
		case "PutRolePolicy":
			policyExists = true
			storedPolicy = r.Form.Get("PolicyDocument")
			writeXML(w, `<PutRolePolicyResponse/>`)
		case "GetRolePolicy":
			if !policyExists {
				writeError(w, http.StatusNotFound, "NoSuchEntity", "absent")
			} else {
				writeXML(w, `<GetRolePolicyResponse><GetRolePolicyResult><RoleName>`+role.Name+`</RoleName><PolicyName>`+role.PolicyName+`</PolicyName><PolicyDocument>`+xmlEscape(pinnedLocalStackPolicyFixture(storedPolicy))+`</PolicyDocument></GetRolePolicyResult></GetRolePolicyResponse>`)
			}
		case "AssumeRole":
			writeXML(w, `<AssumeRoleResponse><AssumeRoleResult><Credentials><AccessKeyId>ASIA0123456789ABCDEF</AccessKeyId><SecretAccessKey>assumed-secret</SecretAccessKey><SessionToken>assumed-token</SessionToken><Expiration>2030-01-01T00:00:00Z</Expiration></Credentials><AssumedRoleUser><Arn>arn:aws:sts::000000000042:assumed-role/`+role.Name+`/`+proofPrefix(marker)+`-session</Arn><AssumedRoleId>AROA0123456789ABCDEF:`+proofPrefix(marker)+`-session</AssumedRoleId></AssumedRoleUser><SourceIdentity>`+proofPrefix(marker)+`-source</SourceIdentity></AssumeRoleResult></AssumeRoleResponse>`)
		case "DeleteRolePolicy":
			policyExists = false
			writeXML(w, `<DeleteRolePolicyResponse/>`)
		case "DeleteAccessKey", "DeleteUser":
			principalExists = false
			writeXML(w, `<`+r.Form.Get("Action")+`Response/>`)
		case "DeleteRole":
			roleExists = false
			writeXML(w, `<DeleteRoleResponse/>`)
		default:
			t.Fatalf("unexpected Action %q", r.Form.Get("Action"))
		}
	}))
	defer server.Close()
	b, err := NewSDKBoundary(context.Background(), server.URL, sourceNamespace, targetNamespace)
	if err != nil {
		t.Fatal(err)
	}
	return RunProof(context.Background(), ProofOptions{Marker: marker, Endpoint: server.URL, SourceAccountID: sourceNamespace, TargetAccountID: targetNamespace, Boundary: b, CleanupTimeout: 100 * time.Millisecond, PollInterval: time.Millisecond, Now: func() time.Time { return time.Date(2029, 1, 1, 0, 0, 0, 0, time.UTC) }})
}

func evaluatorAllowsListRoles(t *testing.T, raw string, enforceDeny bool) bool {
	t.Helper()
	var document struct {
		Statement []struct {
			Effect, Action, Resource string
		} `json:"Statement"`
	}
	if err := json.Unmarshal([]byte(raw), &document); err != nil {
		t.Fatalf("stored policy is invalid: %v", err)
	}
	allow, deny := false, false
	for _, statement := range document.Statement {
		if statement.Action != "iam:ListRoles" || statement.Resource != "*" {
			continue
		}
		switch statement.Effect {
		case "Allow":
			allow = true
		case "Deny":
			deny = true
		}
	}
	if !allow || !deny {
		t.Fatalf("stored policy does not contain matching Allow and Deny: %s", raw)
	}
	return allow && !(enforceDeny && deny)
}

func assertForm(t *testing.T, r *http.Request, want map[string]string) {
	t.Helper()
	for key, value := range want {
		if got := r.Form.Get(key); got != value {
			t.Fatalf("%s %s = %q, want %q", r.Form.Get("Action"), key, got, value)
		}
	}
}
func assertExactForm(t *testing.T, r *http.Request, want map[string]string) {
	t.Helper()
	assertForm(t, r, want)
	if len(r.Form) != len(want) {
		t.Fatalf("%s fields = %#v, want exactly %#v", r.Form.Get("Action"), r.Form, want)
	}
	for key, values := range r.Form {
		if len(values) != 1 || values[0] != want[key] {
			t.Fatalf("%s %s values = %#v, want exactly %q", r.Form.Get("Action"), key, values, want[key])
		}
	}
}
func canonicalPolicyFixture(raw string) string {
	return strings.ReplaceAll(url.QueryEscape(raw), "+", "%20")
}
func pinnedLocalStackPolicyFixture(raw string) string {
	return strings.ReplaceAll(canonicalPolicyFixture(raw), "%2F", "/")
}
func invalidUTF8PolicyFixture(encodedBytes string) string {
	return `%7B%22Version%22%3A%222012-10-17%22%2C%22Statement%22%3A%5B%7B%22Condition%22%3A%22` + encodedBytes + `%22%7D%5D%7D`
}
func writeXML(w http.ResponseWriter, body string) {
	w.Header().Set("Content-Type", "text/xml")
	_, _ = io.WriteString(w, body)
}
func writeError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "text/xml")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, `<ErrorResponse><Error><Code>`+code+`</Code><Message>`+message+`</Message></Error></ErrorResponse>`)
}
func xmlEscape(raw string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;").Replace(raw)
}
func userResponse(action string, spec PrincipalSpec, id string) string {
	return `<` + action + `Response><` + action + `Result><User><Path>` + spec.Path + `</Path><UserName>` + spec.Name + `</UserName><UserId>` + id + `</UserId><Arn>` + spec.ARN + `</Arn><Tags><member><Key>proof</Key><Value>` + spec.Marker + `</Value></member></Tags></User></` + action + `Result></` + action + `Response>`
}
func roleResponse(action string, spec RoleSpec, id string) string {
	return `<` + action + `Response><` + action + `Result><Role><Path>` + spec.Path + `</Path><RoleName>` + spec.Name + `</RoleName><RoleId>` + id + `</RoleId><Arn>` + spec.ARN + `</Arn><AssumeRolePolicyDocument>` + xmlEscape(pinnedLocalStackPolicyFixture(spec.TrustPolicy)) + `</AssumeRolePolicyDocument><Description>` + spec.Description + `</Description><Tags><member><Key>proof</Key><Value>` + spec.Marker + `</Value></member></Tags></Role></` + action + `Result></` + action + `Response>`
}

var _ = time.Second
