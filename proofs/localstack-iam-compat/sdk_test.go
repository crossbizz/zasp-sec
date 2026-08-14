package main

import (
	"context"
	"errors"
	"io"
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
			if r.Form.Get("PathPrefix") != "/"+marker+"/" {
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
			writeXML(w, `<GetRolePolicyResponse><GetRolePolicyResult><RoleName>`+role.Name+`</RoleName><PolicyName>`+role.PolicyName+`</PolicyName><PolicyDocument>`+xmlEscape(url.QueryEscape(role.PermissionPolicy))+`</PolicyDocument></GetRolePolicyResult></GetRolePolicyResponse>`)
		case "AssumeRole":
			assertForm(t, r, map[string]string{"RoleArn": role.ARN, "RoleSessionName": "session", "ExternalId": "external", "SourceIdentity": "source", "Tags.member.1.Key": "proof", "Tags.member.1.Value": marker})
			writeXML(w, `<AssumeRoleResponse><AssumeRoleResult><Credentials><AccessKeyId>ASIA0123456789ABCDEF</AccessKeyId><SecretAccessKey>assumed-secret</SecretAccessKey><SessionToken>assumed-token</SessionToken><Expiration>2030-01-01T00:00:00Z</Expiration></Credentials><AssumedRoleUser><Arn>arn:aws:sts::000000000042:assumed-role/`+role.Name+`/session</Arn><AssumedRoleId>AROA0123456789ABCDEF:session</AssumedRoleId></AssumedRoleUser><SourceIdentity>source</SourceIdentity></AssumeRoleResult></AssumeRoleResponse>`)
		case "ListRoles":
			if strings.Contains(r.Header.Get("Authorization"), "Credential=000000000041/") {
				t.Fatal("assumed ListRoles used source credentials")
			}
			writeError(w, http.StatusForbidden, "AccessDenied", "explicit deny")
		case "DeleteRolePolicy", "DeleteRole", "DeleteAccessKey", "DeleteUser":
			writeXML(w, `<`+action+`Response><ResponseMetadata><RequestId>x</RequestId></ResponseMetadata></`+action+`Response>`)
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
	if got := strings.Join(actions, ","); !strings.Contains(got, "GetCallerIdentity,GetUser,ListUsers,CreateUser,GetUser,CreateAccessKey,ListAccessKeys,CreateRole,GetRole,PutRolePolicy,GetRolePolicy,AssumeRole,GetRole,ListRoles,DeleteRolePolicy,DeleteAccessKey,DeleteUser,DeleteRole") {
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
	if _, ok := decodeProviderPolicy(`{"Version":"2012-10-17","Statement":[{}]}`); !ok {
		t.Fatal("valid policy representation was rejected")
	}
	for _, raw := range []string{
		`null`,
		`{"Version":"2012-10-17"}`,
		`{"Version":"2012-10-17","Statement":[{}],"Unknown":true}`,
		`{"Version":"2012-10-17","Version":"2012-10-17","Statement":[{}]}`,
		`{"Version":"2012-10-17","Statement":[{}]} trailing`,
		url.QueryEscape(url.QueryEscape(`{"Version":"2012-10-17","Statement":[{}]}`)),
		strings.Repeat("x", maxBodySize+1),
	} {
		t.Run("invalid", func(t *testing.T) {
			if _, ok := decodeProviderPolicy(raw); ok {
				t.Fatalf("decodeProviderPolicy(%q) accepted an invalid policy representation", raw)
			}
		})
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

func assertForm(t *testing.T, r *http.Request, want map[string]string) {
	t.Helper()
	for key, value := range want {
		if got := r.Form.Get(key); got != value {
			t.Fatalf("%s %s = %q, want %q", r.Form.Get("Action"), key, got, value)
		}
	}
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
	return `<` + action + `Response><` + action + `Result><Role><Path>` + spec.Path + `</Path><RoleName>` + spec.Name + `</RoleName><RoleId>` + id + `</RoleId><Arn>` + spec.ARN + `</Arn><AssumeRolePolicyDocument>` + xmlEscape(url.QueryEscape(spec.TrustPolicy)) + `</AssumeRolePolicyDocument><Description>` + spec.Description + `</Description><Tags><member><Key>proof</Key><Value>` + spec.Marker + `</Value></member></Tags></Role></` + action + `Result></` + action + `Response>`
}

var _ = time.Second
