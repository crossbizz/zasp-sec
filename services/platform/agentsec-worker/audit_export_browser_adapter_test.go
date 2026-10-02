//go:build darwin || linux

package main

import (
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

const auditBrowserWorkerPolicy = `[{"schema":"audit-export-policy-v1","policy_id":"pid_7b000001-0000-4000-8000-000000000001","bucket":"owned-audit-browser-fixture","expected_bucket_owner":"123456789012","kms_key_arn":"arn:aws:kms:us-east-1:123456789012:key/7b000002-0000-4000-8000-000000000002","maximum_export_bytes":1073741824,"maximum_retained_bytes":10737418240,"maximum_inflight":2,"capture_timeout_seconds":120}]`

type auditBrowserWorkerPlan struct {
	values   map[string]string
	deadline time.Time
	s3Host   string
}

func auditExportProcessDestination(plan auditBrowserWorkerPlan, mode, network, destination string) error {
	host, port, err := net.SplitHostPort(destination)
	if network != "tcp" || err != nil || port != "443" || (host != "sts.us-east-1.amazonaws.com" && host != "sqs.us-east-1.amazonaws.com" && (mode != "audit-export" || host != plan.s3Host)) {
		return errors.New("unexpected process provider destination")
	}
	return nil
}

func TestAuditBrowserWorkerSelectedDestination(t *testing.T) {
	now := time.Now()
	plan, err := auditExportProcessPlan("audit-export", "audit-browser", auditBrowserWorkerPolicy, now.Add(time.Minute).Format(time.RFC3339Nano), now)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		mode, network, destination string
		allowed                    bool
	}{
		{"audit-export", "tcp", "owned-audit-browser-fixture.s3.us-east-1.amazonaws.com:443", true},
		{"audit-export-outbox", "tcp", "sqs.us-east-1.amazonaws.com:443", true},
		{"audit-export", "tcp", "sts.us-east-1.amazonaws.com:443", true},
		{"audit-export-outbox", "tcp", "owned-audit-browser-fixture.s3.us-east-1.amazonaws.com:443", false},
		{"audit-export", "tcp", "zasp-audit-export-fixture.s3.us-east-1.amazonaws.com:443", false},
		{"audit-export", "tcp", "owned-audit-browser-fixture.s3.us-east-1.amazonaws.com:444", false},
		{"audit-export", "udp", "sts.us-east-1.amazonaws.com:443", false},
	} {
		t.Run(c.mode+c.network+c.destination, func(t *testing.T) {
			if got := auditExportProcessDestination(plan, c.mode, c.network, c.destination); (got == nil) != c.allowed {
				t.Fatal("provider destination authority", c, got)
			}
		})
	}
	if _, err := auditExportProcessPlan("audit-export", "audit-browser", strings.Replace(auditBrowserWorkerPolicy, "owned-audit-browser-fixture", "foreign-bucket", 1), now.Add(time.Minute).Format(time.RFC3339Nano), now); err == nil {
		t.Fatal("foreign bucket admitted")
	}
}

func auditExportProcessPlan(mode, selection, policy, deadline string, now time.Time) (auditBrowserWorkerPlan, error) {
	if mode != "audit-export" && mode != "audit-export-outbox" {
		return auditBrowserWorkerPlan{}, errors.New("invalid worker mode")
	}
	plan := auditBrowserWorkerPlan{auditExportProductionEnvironment(mode), now.Add(90 * time.Second), "zasp-audit-export-fixture.s3.us-east-1.amazonaws.com"}
	if selection == "" && policy == "" && deadline == "" {
		return plan, nil
	}
	end, err := time.Parse(time.RFC3339Nano, deadline)
	if selection != "audit-browser" || policy != auditBrowserWorkerPolicy || err != nil || end.Sub(now) <= 20*time.Second || end.Sub(now) > 12*time.Minute {
		return auditBrowserWorkerPlan{}, errors.New("invalid selected worker mapping")
	}
	plan.deadline = end
	plan.s3Host = "owned-audit-browser-fixture.s3.us-east-1.amazonaws.com"
	if mode == "audit-export" {
		plan.values["ZASP_AUDIT_EXPORT_POLICIES_JSON"] = policy
	}
	return plan, nil
}

func TestAuditBrowserWorkerSelectedPolicyAndLifetime(t *testing.T) {
	now := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	for _, mode := range []string{"audit-export", "audit-export-outbox"} {
		plan, err := auditExportProcessPlan(mode, "audit-browser", auditBrowserWorkerPolicy, now.Add(10*time.Minute).Format(time.RFC3339Nano), now)
		if err != nil {
			t.Fatalf("actual selected worker mapping refused: %v", err)
		}
		config, err := loadWorkerRuntimeConfig(mapLookup(plan.values))
		if err != nil {
			t.Fatal("mapped production config refused", err)
		}
		if !plan.deadline.Equal(now.Add(10*time.Minute)) || plan.s3Host != "owned-audit-browser-fixture.s3.us-east-1.amazonaws.com" {
			t.Fatal("selected deadline/host changed", plan)
		}
		if mode == "audit-export" {
			if len(config.AuditExports.Policies) != 1 || config.AuditExports.Policies[0].PolicyID != "pid_7b000001-0000-4000-8000-000000000001" || config.AuditExports.Policies[0].Bucket != "owned-audit-browser-fixture" {
				t.Fatal("wrong browser storage policy")
			}
		}
	}
}

func TestAuditBrowserWorkerSelectedMappingRejectsDrift(t *testing.T) {
	now := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	for _, row := range []struct {
		name, mode, selection, policy string
		end                           time.Time
	}{
		{"unknown selector", "audit-export", "browser", auditBrowserWorkerPolicy, now.Add(time.Minute)},
		{"wrong mode", "other", "audit-browser", auditBrowserWorkerPolicy, now.Add(time.Minute)},
		{"default policy", "audit-export", "audit-browser", workerAuditExportPoliciesJSON, now.Add(time.Minute)},
		{"missing policy", "audit-export", "audit-browser", "", now.Add(time.Minute)},
		{"expired", "audit-export", "audit-browser", auditBrowserWorkerPolicy, now},
		{"no cleanup reserve", "audit-export", "audit-browser", auditBrowserWorkerPolicy, now.Add(20 * time.Second)},
		{"too long", "audit-export", "audit-browser", auditBrowserWorkerPolicy, now.Add(12*time.Minute + time.Nanosecond)},
		{"implicit selection", "audit-export", "", auditBrowserWorkerPolicy, now.Add(time.Minute)},
	} {
		t.Run(row.name, func(t *testing.T) {
			if _, err := auditExportProcessPlan(row.mode, row.selection, row.policy, row.end.Format(time.RFC3339Nano), now); err == nil {
				t.Fatal("unsafe selected mapping admitted")
			}
		})
	}
	plan, err := auditExportProcessPlan("audit-export", "", "", "", now)
	if err != nil || !plan.deadline.Equal(now.Add(90*time.Second)) || plan.values["ZASP_AUDIT_EXPORT_POLICIES_JSON"] != workerAuditExportPoliciesJSON || plan.s3Host != "zasp-audit-export-fixture.s3.us-east-1.amazonaws.com" {
		t.Fatal("existing worker default changed")
	}
}
