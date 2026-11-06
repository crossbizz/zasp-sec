package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"

	"github.com/zasp-ai/zasp-sec/services/platform/domain"
	"github.com/zasp-ai/zasp-sec/services/platform/migrations"
	"github.com/zasp-ai/zasp-sec/services/platform/optionalegress"
)

const optionalEgressInputEnvironment = "ZASP_OPTIONAL_EGRESS_CONFIGURATION_FILE"
const optionalEgressChecksumEnvironment = "ZASP_OPTIONAL_EGRESS_PROFILE_CHECKSUM"

func optionalEgressProfileCommand(command string) bool {
	return command == "up-optional-egress-profile" || command == "up-optional-egress-audit-profile"
}
func optionalEgressOperatorCommand(command string) bool {
	return command == "register-optional-egress-principals" || command == "configure-optional-egress-profile" || command == "activate-optional-egress-profile"
}

func writeOptionalEgressChecksums(w io.Writer) error {
	if w == nil {
		return errInvalidMigrationCommand
	}
	return json.NewEncoder(w).Encode(struct {
		Normal string `json:"normal"`
		Audit  string `json:"audit"`
	}{migrations.OptionalEgressProfileChecksum(), migrations.OptionalEgressAuditProfileChecksum()})
}

func (r *registeredReleaseMigrationRunner) UpProductionOptionalEgressProfile(ctx context.Context) error {
	if err := r.auditProfilePrincipal(ctx); err != nil {
		return err
	}
	extension, ok := r.releaseMigrationRunner.(interface{ UpProductionOptionalEgressProfile(context.Context) error })
	if !ok {
		return migrations.ErrInvalidState
	}
	return extension.UpProductionOptionalEgressProfile(ctx)
}
func (r *registeredReleaseMigrationRunner) UpProductionOptionalEgressAuditProfile(ctx context.Context) error {
	if err := r.auditProfilePrincipal(ctx); err != nil {
		return err
	}
	extension, ok := r.releaseMigrationRunner.(interface{ UpProductionOptionalEgressAuditProfile(context.Context) error })
	if !ok {
		return migrations.ErrInvalidState
	}
	return extension.UpProductionOptionalEgressAuditProfile(ctx)
}

func optionalEgressPostInstall(ctx context.Context, q principalQueryer, principal, command string) error {
	if ctx == nil || ctx.Err() != nil || q == nil || !databasePrincipalPattern.MatchString(principal) || !optionalEgressProfileCommand(command) {
		return errReleasePrincipalRegistration
	}
	pin := migrations.OptionalEgressProfileChecksum()
	if command == "up-optional-egress-audit-profile" {
		pin = migrations.OptionalEgressAuditProfileChecksum()
	}
	var ready bool
	if err := q.QueryRow(ctx, `SELECT session_user=$1 AND zasp_authorization79.operator() AND zasp_optional_egress_v1.catalog_ready($2)`, principal, pin).Scan(&ready); err != nil || !ready {
		return errReleasePrincipalRegistration
	}
	return nil
}

type optionalEgressPrincipalInput struct {
	Human      string `json:"human_principal"`
	Planner    string `json:"planner_principal"`
	Settlement string `json:"settlement_principal"`
}
type optionalEgressScopeInput struct {
	Organization string `json:"organization_id"`
	Workspace    string `json:"workspace_id"`
	Environment  string `json:"environment_id"`
}
type optionalEgressApprovedProfileInput struct {
	optionalEgressScopeInput
	Profile optionalegress.Profile `json:"profile"`
}
type optionalEgressActivationInput struct {
	optionalEgressScopeInput
	ProfileID       string `json:"profile_id"`
	ProfileVersion  int64  `json:"profile_version"`
	ExpectedVersion int64  `json:"expected_version"`
}
type optionalEgressOperatorInput struct {
	principal, checksum, command string
	principals                   optionalEgressPrincipalInput
	body                         json.RawMessage
}

func (optionalEgressOperatorInput) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("[optional egress operator input]"))
}

func optionalEgressProductID(s string) bool {
	id, err := domain.ParseProductID(s)
	return err == nil && id.String() == s
}
func optionalEgressScopeValid(s optionalEgressScopeInput) bool {
	return optionalEgressProductID(s.Organization) && optionalEgressProductID(s.Workspace) && optionalEgressProductID(s.Environment)
}

// Reject duplicate object members, nulls and excessive nesting before the
// typed closed DTO decoder; neither ambiguous approval fields nor extra secret
// fields can reach SQL. The whole input is already capped at sixteen KiB.
func optionalEgressJSONValue(d *json.Decoder, depth int) error {
	if depth > 8 {
		return errInvalidMigrationCommand
	}
	token, err := d.Token()
	if err != nil || token == nil {
		return errInvalidMigrationCommand
	}
	delimiter, compound := token.(json.Delim)
	if !compound {
		return nil
	}
	switch delimiter {
	case '{':
		seen := map[string]bool{}
		for d.More() {
			k, err := d.Token()
			name, ok := k.(string)
			if err != nil || !ok || seen[name] {
				return errInvalidMigrationCommand
			}
			seen[name] = true
			if err := optionalEgressJSONValue(d, depth+1); err != nil {
				return err
			}
		}
		end, err := d.Token()
		if err != nil || end != json.Delim('}') {
			return errInvalidMigrationCommand
		}
	case '[':
		for d.More() {
			if err := optionalEgressJSONValue(d, depth+1); err != nil {
				return err
			}
		}
		end, err := d.Token()
		if err != nil || end != json.Delim(']') {
			return errInvalidMigrationCommand
		}
	default:
		return errInvalidMigrationCommand
	}
	return nil
}
func decodeOptionalEgressInput(raw []byte, out any) error {
	if len(raw) < 2 || len(raw) > 16384 || !json.Valid(raw) {
		return errInvalidMigrationCommand
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if optionalEgressJSONValue(d, 0) != nil {
		return errInvalidMigrationCommand
	}
	if _, err := d.Token(); err != io.EOF {
		return errInvalidMigrationCommand
	}
	d = json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil || d.Decode(new(any)) != io.EOF {
		return errInvalidMigrationCommand
	}
	return nil
}

// encoding/json matches struct tags case-insensitively. Exact key sets keep
// aliases such as HUMAN_PRINCIPAL from shadowing an authenticated input field.
func optionalEgressClosedObject(raw []byte, names ...string) bool {
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || len(fields) != len(names) {
		return false
	}
	for _, name := range names {
		if _, ok := fields[name]; !ok {
			return false
		}
	}
	return true
}

func loadOptionalEgressOperator(args []string, getenv func(string) string) (*optionalEgressOperatorInput, error) {
	if len(args) != 1 || getenv == nil || !optionalEgressOperatorCommand(args[0]) {
		return nil, errInvalidMigrationCommand
	}
	r := &optionalEgressOperatorInput{principal: getenv(migrationPrincipalEnvironment), checksum: getenv(optionalEgressChecksumEnvironment), command: args[0]}
	if !databasePrincipalPattern.MatchString(r.principal) || !migrations.IsOptionalEgressProfileChecksum(r.checksum) {
		return nil, errInvalidMigrationCommand
	}
	path := getenv(optionalEgressInputEnvironment)
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errInvalidMigrationCommand
	}
	initial, err := os.Lstat(path)
	if err != nil || !initial.Mode().IsRegular() || (initial.Mode().Perm() != 0400 && initial.Mode().Perm() != 0600) || initial.Size() < 2 || initial.Size() > 16384 {
		return nil, errInvalidMigrationCommand
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, errInvalidMigrationCommand
	}
	defer f.Close()
	current, err := f.Stat()
	if err != nil || !current.Mode().IsRegular() || !os.SameFile(initial, current) || (current.Mode().Perm() != 0400 && current.Mode().Perm() != 0600) || current.Size() != initial.Size() || !current.ModTime().Equal(initial.ModTime()) {
		return nil, errInvalidMigrationCommand
	}
	raw, err := io.ReadAll(io.LimitReader(f, 16385))
	if err != nil {
		return nil, errInvalidMigrationCommand
	}
	defer clear(raw)
	after, statErr := os.Lstat(path)
	if statErr != nil || !after.Mode().IsRegular() || !os.SameFile(current, after) || after.Size() != initial.Size() || int64(len(raw)) != initial.Size() || after.Mode().Perm() != initial.Mode().Perm() || !after.ModTime().Equal(initial.ModTime()) {
		return nil, errInvalidMigrationCommand
	}
	switch r.command {
	case "register-optional-egress-principals":
		if !optionalEgressClosedObject(raw, "human_principal", "planner_principal", "settlement_principal") || decodeOptionalEgressInput(raw, &r.principals) != nil {
			return nil, errInvalidMigrationCommand
		}
		names := []string{r.principal, r.principals.Human, r.principals.Planner, r.principals.Settlement}
		seen := map[string]bool{}
		for _, name := range names {
			if !databasePrincipalPattern.MatchString(name) || seen[name] {
				return nil, errInvalidMigrationCommand
			}
			seen[name] = true
		}
	case "configure-optional-egress-profile":
		var input optionalEgressApprovedProfileInput
		if !optionalEgressClosedObject(raw, "organization_id", "workspace_id", "environment_id", "profile") || decodeOptionalEgressInput(raw, &input) != nil || !optionalEgressScopeValid(input.optionalEgressScopeInput) || !optionalEgressProductID(input.Profile.ProfileID) || input.Profile.ProfileVersion < 1 || input.Profile.ProfileVersion > 1000000 || input.Profile.Provider != "openrouter" || input.Profile.Purpose != optionalegress.Purpose {
			return nil, errInvalidMigrationCommand
		}
		var fields map[string]json.RawMessage
		if json.Unmarshal(raw, &fields) != nil || !optionalEgressClosedObject(fields["profile"], "profile_id", "profile_version", "profile_digest", "provider", "purpose", "model", "backend", "account_id", "credential_reference", "credential_digest", "capability_digest", "pricing_digest", "effective_at", "expires_at", "input_token_bound", "output_token_cap", "prompt_price_nano_credits_per_million", "completion_price_nano_credits_per_million", "cost_ceiling_nano_credits", "maximum_outstanding_nano_credits", "maximum_concurrency", "timeout_milliseconds", "policy_version") {
			return nil, errInvalidMigrationCommand
		}
		digest, err := optionalegress.ProfileDigest(input.Profile)
		if err != nil || digest != input.Profile.ProfileDigest {
			return nil, errInvalidMigrationCommand
		}
		prefix := "secret_ref_ai/" + input.Organization + "/" + input.Workspace + "/" + input.Environment + "/"
		suffix := strings.TrimPrefix(input.Profile.CredentialReference, prefix)
		if !strings.HasPrefix(input.Profile.CredentialReference, prefix) || !regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,95}$`).MatchString(suffix) {
			return nil, errInvalidMigrationCommand
		}
		r.body, err = json.Marshal(input)
		if err != nil {
			return nil, errInvalidMigrationCommand
		}
	case "activate-optional-egress-profile":
		var input optionalEgressActivationInput
		if !optionalEgressClosedObject(raw, "organization_id", "workspace_id", "environment_id", "profile_id", "profile_version", "expected_version") || decodeOptionalEgressInput(raw, &input) != nil || !optionalEgressScopeValid(input.optionalEgressScopeInput) || !optionalEgressProductID(input.ProfileID) || input.ProfileVersion < 1 || input.ProfileVersion > 1000000 || input.ExpectedVersion < 1 || input.ExpectedVersion > 100000000000000 {
			return nil, errInvalidMigrationCommand
		}
		r.body, err = json.Marshal(input)
		if err != nil {
			return nil, errInvalidMigrationCommand
		}
	}
	return r, nil
}

func runOptionalEgressOperator(ctx context.Context, q principalQueryer, r *optionalEgressOperatorInput) error {
	if ctx == nil || ctx.Err() != nil || q == nil || r == nil || !databasePrincipalPattern.MatchString(r.principal) || !migrations.IsOptionalEgressProfileChecksum(r.checksum) {
		return errReleasePrincipalRegistration
	}
	prefix := `SELECT CASE WHEN session_user=$1 AND zasp_authorization79.operator() AND zasp_optional_egress_v1.catalog_ready($2) THEN `
	var statement string
	args := []any{r.principal, r.checksum}
	switch r.command {
	case "register-optional-egress-principals":
		statement = prefix + `zasp_optional_egress_v1.register_principal($3,'human-forward') AND zasp_optional_egress_v1.register_principal($4,'planner-forward') AND zasp_optional_egress_v1.register_principal($5,'captured-settlement') ELSE false END`
		args = append(args, r.principals.Human, r.principals.Planner, r.principals.Settlement)
	case "configure-optional-egress-profile":
		statement = prefix + `zasp_optional_egress_v1.register_profile($3::jsonb) ELSE false END`
		args = append(args, r.body)
	case "activate-optional-egress-profile":
		statement = prefix + `zasp_optional_egress_v1.activate_profile($3::jsonb) IS NOT NULL ELSE false END`
		args = append(args, r.body)
	default:
		return errReleasePrincipalRegistration
	}
	var ready bool
	if err := q.QueryRow(ctx, statement, args...).Scan(&ready); err != nil || !ready {
		return errReleasePrincipalRegistration
	}
	return nil
}
