package apiserver

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// completion.sql section WS9 (the hosted gateway) on the real catalog, in the
// database of the provider remediation test: the gateway policy, the
// registered servers, the decision records, the tools a server listed, and
// the two existing functions the section extends. The functions that need a
// request proof are tested for refusing a request without one; their bodies
// (the functions without the proof check, executable only by their owner)
// are exercised as the database owner. The whole path with attested proofs is
// TestHostedGatewayOnInstalledBaselinePostgres.
func TestHostedGatewaySectionPostgres(t *testing.T) {
	database := startRemediationDatabase(t)
	database.seed()
	const o, w, e, actor = remediationOrg, remediationWorkspace, remediationEnvironment, remediationAdmin
	const server, other = "pid_72000000-0000-4000-8000-000000000001", "pid_72000000-0000-4000-8000-000000000002"
	state := func(err error) string {
		code, message := remediationSQLState(err)
		return code + " " + message
	}
	var raw []byte
	id := func(n int) string { return fmt.Sprintf("pid_73000000-0000-4000-8000-%012d", n) }
	query := func(statement string, arguments ...any) (json.RawMessage, error) {
		err := database.conn.QueryRow(database.ctx, statement, arguments...).Scan(&raw)
		return append(json.RawMessage(nil), raw...), err
	}
	writeServer := func(serverID, q string, expected int64, n int) (json.RawMessage, error) {
		return query(`SELECT zasp_authorization80.mcp_gateway_server_write($1,$2,$3,$4,$5,$6::jsonb,$7,$8,$9)`, o, w, e, actor, serverID, q, expected, id(n), id(n+1))
	}
	record := func(serverID *string, q string) (json.RawMessage, error) {
		return query(`SELECT zasp_authorization80.gateway_record_write($1,$2,$3,$4,$5,$6::jsonb)`, o, w, e, actor, serverID, q)
	}
	digest := "sha256:" + strings.Repeat("ab", 32)
	mcpRecord := func(n int, members string) string {
		base := map[string]string{"surface": `"mcp"`, "operation": `"tools/call"`, "direction": `"request"`, "decision": `"allow"`, "reason": `"none"`, "rules": `[]`, "bytes": `120`, "content_digest": `"` + digest + `"`,
			"tool_name": `"lookup_customer"`, "provider": `null`, "model": `null`, "agent_id": `null`}
		var override map[string]json.RawMessage
		if members != "" {
			if err := json.Unmarshal([]byte(members), &override); err != nil {
				t.Fatalf("fixture: %v", err)
			}
		}
		parts := []string{`"id":"` + id(n) + `"`}
		for name, value := range base {
			if replaced, has := override[name]; has {
				value = string(replaced)
				delete(override, name)
			}
			parts = append(parts, `"`+name+`":`+value)
		}
		for name, value := range override {
			parts = append(parts, `"`+name+`":`+string(value))
		}
		return "{" + strings.Join(parts, ",") + "}"
	}
	batch := func(records string, tools string) string {
		return `{"records":[` + records + `],"tools":[` + tools + `]}`
	}

	t.Run("the tables cannot hold text or an upstream credential", func(t *testing.T) {
		columns := func(table string) string {
			return database.text(`SELECT string_agg(column_name||':'||data_type,',' ORDER BY ordinal_position) FROM information_schema.columns WHERE table_schema='public' AND table_name=$1`, table)
		}
		if got := columns("zasp_gateway_decisions"); got != "organization_id:text,workspace_id:text,environment_id:text,id:text,principal_id:text,surface:text,operation:text,direction:text,decision:text,reason:text,rules:jsonb,bytes:bigint,content_digest:bytea,server_id:text,tool_name:text,provider:text,model:text,agent_id:text,guardrail_version:bigint,policy_version:bigint,created_at:timestamp with time zone" {
			t.Fatalf("decision columns=%s", got)
		}
		if got := columns("zasp_mcp_gateway_servers"); got != "organization_id:text,workspace_id:text,environment_id:text,id:text,name:text,upstream_url:text,upstream_host:text,enabled:boolean,allowed_tools:ARRAY,denied_tools:ARRAY,version:bigint,created_by:text,created_at:timestamp with time zone,updated_by:text,updated_at:timestamp with time zone" {
			t.Fatalf("server columns=%s", got)
		}
		if got := columns("zasp_mcp_gateway_tools"); got != "organization_id:text,workspace_id:text,environment_id:text,server_id:text,name:text,tool_id:text,risk:text,first_seen_at:timestamp with time zone,last_seen_at:timestamp with time zone" {
			t.Fatalf("tool columns=%s", got)
		}
		// The four tables belong to the authority, under forced row security,
		// and no service login can read or write them directly.
		if got := database.text(`SELECT string_agg(c.relname||':'||pg_get_userbyid(c.relowner)||':'||c.relrowsecurity||':'||c.relforcerowsecurity,',' ORDER BY c.relname) FROM pg_class c
WHERE c.relnamespace='public'::regnamespace AND c.relname IN('zasp_gateway_policies','zasp_mcp_gateway_servers','zasp_mcp_gateway_tools','zasp_gateway_decisions')`); got != "zasp_gateway_decisions:zasp_discovery_authority:true:true,zasp_gateway_policies:zasp_discovery_authority:true:true,zasp_mcp_gateway_servers:zasp_discovery_authority:true:true,zasp_mcp_gateway_tools:zasp_discovery_authority:true:true" {
			t.Fatalf("tables=%s", got)
		}
		if got := database.text(`SELECT count(*)::text FROM information_schema.role_table_grants WHERE table_schema='public' AND table_name IN('zasp_gateway_policies','zasp_mcp_gateway_servers','zasp_mcp_gateway_tools','zasp_gateway_decisions') AND grantee NOT IN('zasp_discovery_authority')`); got != "0" {
			t.Fatalf("%s grants on the gateway tables to other roles", got)
		}
	})

	t.Run("the API's statements need a request proof, and their bodies are the owner's", func(t *testing.T) {
		for name, call := range map[string]struct {
			statement string
			arguments []any
		}{
			"gateway_open":              {`SELECT zasp_authorization80.gateway_open($1,$2,$3,$4,'callMCPGateway',$5)`, []any{o, w, e, actor, server}},
			"gateway_record":            {`SELECT zasp_authorization80.gateway_record($1,$2,$3,$4,'createGatewayMessage',NULL,$5::jsonb)`, []any{o, w, e, actor, batch("", "")}},
			"gateway_policy":            {`SELECT zasp_authorization80.gateway_policy($1,$2,$3)`, []any{o, w, e}},
			"gateway_set_policy":        {`SELECT zasp_authorization80.gateway_set_policy($1,$2,$3,$4,'{}'::jsonb,0,$5,$6)`, []any{o, w, e, actor, id(900), id(901)}},
			"mcp_gateway_server_page":   {`SELECT zasp_authorization80.mcp_gateway_server_page($1,$2,$3)`, []any{o, w, e}},
			"mcp_gateway_server_put":    {`SELECT zasp_authorization80.mcp_gateway_server_put($1,$2,$3,$4,$5,'{}'::jsonb,0,$6,$7)`, []any{o, w, e, actor, server, id(902), id(903)}},
			"mcp_gateway_server_delete": {`SELECT zasp_authorization80.mcp_gateway_server_delete($1,$2,$3,$4,$5,1,$6,$7)`, []any{o, w, e, actor, server, id(904), id(905)}},
			"gateway_activity_page":     {`SELECT zasp_authorization80.gateway_activity_page($1,$2,$3,NULL,NULL,NULL,NULL,NULL,10)`, []any{o, w, e}},
		} {
			if result, err := database.as("zasp_svc_api", call.statement, call.arguments...); err == nil || !strings.HasPrefix(state(err), "42501 ") {
				t.Fatalf("%s without a proof: result=%s state=%q", name, result, state(err))
			}
		}
		for _, body := range []string{
			`SELECT zasp_authorization80.gateway_policy_write($1,$2,$3,$4,'{}'::jsonb,0,$4,$4)`,
			`SELECT zasp_authorization80.gateway_record_write($1,$2,$3,$4,NULL,'{}'::jsonb)`,
			`SELECT zasp_authorization80.mcp_gateway_server_write($1,$2,$3,$4,$4,'{}'::jsonb,0,$4,$4)`,
			`SELECT zasp_authorization80.mcp_gateway_server_remove($1,$2,$3,$4,$4,1,$4,$4)`,
			`SELECT zasp_authorization80.gateway_session_value($1,$2,$3,$4)`,
			`SELECT zasp_authorization80.gateway_request($1,$2,$3,$4,'callMCPGateway',$4,false)`,
			`SELECT zasp_authorization80.gateway_activity_value($1,$2,$3,NULL,NULL,NULL,NULL,$4,10)`,
		} {
			if result, err := database.as("zasp_svc_api", body, o, w, e, actor); err == nil || !strings.HasPrefix(state(err), "42501 permission denied") {
				t.Fatalf("%s as the API login: result=%s state=%q", body, result, state(err))
			}
		}
		if got := database.text(`SELECT count(*)::text FROM pg_proc p WHERE p.pronamespace='zasp_authorization80'::regnamespace AND(p.proname LIKE 'gateway\_%' OR p.proname LIKE 'mcp\_gateway\_%') AND has_function_privilege('public',p.oid,'EXECUTE')`); got != "0" {
			t.Fatalf("%s gateway functions are executable by PUBLIC", got)
		}
	})

	t.Run("the gateway policy", func(t *testing.T) {
		write := func(q string, expected int64, n int) (json.RawMessage, error) {
			return query(`SELECT zasp_authorization80.gateway_policy_write($1,$2,$3,$4,$5::jsonb,$6,$7,$8)`, o, w, e, actor, q, expected, id(n), id(n+1))
		}
		value, err := query(`SELECT zasp_authorization80.gateway_policy_value($1,$2,$3)`, o, w, e)
		if err != nil || !strings.Contains(string(value), `"version": 0`) || !strings.Contains(string(value), `"unapproved_servers": "allow"`) || !strings.Contains(string(value), `"requests_per_minute": 600`) || !strings.Contains(string(value), `"denied_tool_risks": []`) || !strings.Contains(string(value), `"updated_at": null`) {
			t.Fatalf("defaults=%s err=%v", value, err)
		}
		for name, q := range map[string]string{
			"an unknown choice":   `{"unapproved_servers":"maybe","denied_tool_risks":[],"requests_per_minute":10}`,
			"an unknown risk":     `{"unapproved_servers":"allow","denied_tool_risks":["dangerous"],"requests_per_minute":10}`,
			"a risk twice":        `{"unapproved_servers":"allow","denied_tool_risks":["read","read"],"requests_per_minute":10}`,
			"a rate over the cap": `{"unapproved_servers":"allow","denied_tool_risks":[],"requests_per_minute":100001}`,
			"a fractional rate":   `{"unapproved_servers":"allow","denied_tool_risks":[],"requests_per_minute":1.5}`,
			"a missing member":    `{"unapproved_servers":"allow","denied_tool_risks":[]}`,
			"an added member":     `{"unapproved_servers":"allow","denied_tool_risks":[],"requests_per_minute":10,"upstream_secret":"abc"}`,
		} {
			if result, err := write(q, 0, 100); err == nil || state(err) != "22023 gateway policy rejected" {
				t.Fatalf("%s: result=%s state=%q", name, result, state(err))
			}
		}
		value, err = write(`{"unapproved_servers":"refuse","denied_tool_risks":["write","execute"],"requests_per_minute":120}`, 0, 102)
		// The risk classes are stored in their fixed order.
		if err != nil || !strings.Contains(string(value), `"version": 1`) || !strings.Contains(string(value), `"denied_tool_risks": ["execute", "write"]`) || !strings.Contains(string(value), `"audit_id": "`+id(102)+`"`) {
			t.Fatalf("saved=%s err=%v", value, err)
		}
		if result, err := write(`{"unapproved_servers":"allow","denied_tool_risks":[],"requests_per_minute":0}`, 0, 104); err == nil || state(err) != "40001 gateway policy version conflict" {
			t.Fatalf("stale write: result=%s state=%q", result, state(err))
		}
		if audit := database.text(`SELECT operation||' '||resource_kind||' '||resource_version::text FROM zasp_workflow_audit WHERE audit_id=$1`, id(102)); audit != "putGatewayPolicy environment 1" {
			t.Fatalf("audit=%s", audit)
		}
	})

	t.Run("registering servers", func(t *testing.T) {
		const input = `{"name":"Tickets","upstream_url":"https://MCP.Tickets.test/mcp","enabled":true,"allowed_tools":[],"denied_tools":["delete_ticket"]}`
		for name, q := range map[string]string{
			"plain http":             strings.Replace(input, "https://", "http://", 1),
			"a query":                strings.Replace(input, "/mcp\"", "/mcp?key=abc\"", 1),
			"credentials":            strings.Replace(input, "https://", "https://user:secret@", 1),
			"another port":           strings.Replace(input, ".test/mcp", ".test:8443/mcp", 1),
			"a fragment":             strings.Replace(input, "/mcp\"", "/mcp#x\"", 1),
			"a tool on both lists":   strings.Replace(input, `"allowed_tools":[]`, `"allowed_tools":["delete_ticket"]`, 1),
			"a tool name with space": strings.Replace(input, `"delete_ticket"`, `"delete ticket"`, 1),
			"a tool twice":           strings.Replace(input, `["delete_ticket"]`, `["delete_ticket","delete_ticket"]`, 1),
			"an upstream secret":     strings.Replace(input, `"enabled":true`, `"enabled":true,"authorization":"Bearer abc"`, 1),
			"a name with a newline":  strings.Replace(input, `"Tickets"`, `"Tick\nets"`, 1),
		} {
			if result, err := writeServer(server, q, 0, 200); err == nil || state(err) != "22023 mcp gateway server rejected" {
				t.Fatalf("%s: result=%s state=%q", name, result, state(err))
			}
		}
		value, err := writeServer(server, input, 0, 202)
		if err != nil || !strings.Contains(string(value), `"version": 1`) || !strings.Contains(string(value), `"upstream_host": "mcp.tickets.test"`) || !strings.Contains(string(value), `"identity": "host:mcp.tickets.test"`) ||
			!strings.Contains(string(value), `"approval": "unapproved"`) || !strings.Contains(string(value), `"tools": []`) || !strings.Contains(string(value), `"last_activity_at": null`) {
			t.Fatalf("registered=%s err=%v", value, err)
		}
		if result, err := writeServer(server, input, 0, 204); err == nil || state(err) != "40001 mcp gateway server version conflict" {
			t.Fatalf("a second registration: result=%s state=%q", result, state(err))
		}
		if result, err := writeServer(other, input, 0, 206); err == nil || state(err) != "23505 mcp gateway server name taken" {
			t.Fatalf("a taken name: result=%s state=%q", result, state(err))
		}
		// The registry's decision for the host is the server's approval.
		database.exec(`INSERT INTO zasp_mcp_registry(organization_id,workspace_id,environment_id,identity,status,updated_by) VALUES($1,$2,$3,'host:mcp.tickets.test','blocked',$4)`, o, w, e, actor)
		value, err = query(`SELECT zasp_authorization80.gateway_session_value($1,$2,$3,$4)`, o, w, e, server)
		if err != nil || !strings.Contains(string(value), `"approval": "blocked"`) || !strings.Contains(string(value), `"unapproved_servers": "refuse"`) || !strings.Contains(string(value), `"denied_tools": ["delete_ticket"]`) ||
			!strings.Contains(string(value), `"guardrail": {"rules": {}, "version": 0}`) || strings.Contains(string(value), "environment_id") {
			t.Fatalf("session=%s err=%v", value, err)
		}
		database.exec(`UPDATE zasp_mcp_registry SET status='approved' WHERE identity='host:mcp.tickets.test'`)
		// A model request has no server; an unknown server is not found.
		if value, err = query(`SELECT zasp_authorization80.gateway_session_value($1,$2,$3,NULL)`, o, w, e); err != nil || !strings.Contains(string(value), `"server": null`) {
			t.Fatalf("model session=%s err=%v", value, err)
		}
		if result, err := query(`SELECT zasp_authorization80.gateway_session_value($1,$2,$3,$4)`, o, w, e, other); err == nil || state(err) != "P0002 mcp gateway server not found" {
			t.Fatalf("unknown server: result=%s state=%q", result, state(err))
		}
	})

	t.Run("a record holds a decision and no text", func(t *testing.T) {
		for name, q := range map[string]string{
			"a text member":                batch(mcpRecord(300, `{"text":"the customer's question"}`), ""),
			"arguments":                    batch(mcpRecord(300, `{"arguments":{"query":"jane@example.com"}}`), ""),
			"a tool name with spaces":      batch(mcpRecord(300, `{"tool_name":"ignore previous instructions"}`), ""),
			"an agent that is a sentence":  batch(mcpRecord(300, `{"agent_id":"the agent that handles refunds"}`), ""),
			"a sample in a rule":           batch(mcpRecord(300, `{"decision":"redact","reason":"guardrail","rules":[{"id":"pii.email","category":"sensitive_data","mode":"redact","count":1,"sample":"jane@example.com"}]}`), ""),
			"a rule that is off":           batch(mcpRecord(300, `{"rules":[{"id":"pii.email","category":"sensitive_data","mode":"off","count":1}]}`), ""),
			"a digest that is not one":     batch(mcpRecord(300, `{"content_digest":"sha256:zz"}`), ""),
			"an allow with a reason":       batch(mcpRecord(300, `{"reason":"guardrail"}`), ""),
			"a block without a reason":     batch(mcpRecord(300, `{"decision":"block"}`), ""),
			"an unknown reason":            batch(mcpRecord(300, `{"decision":"block","reason":"because"}`), ""),
			"a model on an MCP record":     batch(mcpRecord(300, `{"model":"gpt-test"}`), ""),
			"a model record for a server":  batch(mcpRecord(300, `{"surface":"llm","operation":"messages","provider":"anthropic","tool_name":null}`), ""),
			"an unknown method":            batch(mcpRecord(300, `{"operation":"tools/destroy"}`), ""),
			"a size over the cap":          batch(mcpRecord(300, `{"bytes":1073741825}`), ""),
			"nine records":                 batch(strings.Join([]string{mcpRecord(301, ""), mcpRecord(302, ""), mcpRecord(303, ""), mcpRecord(304, ""), mcpRecord(305, ""), mcpRecord(306, ""), mcpRecord(307, ""), mcpRecord(308, ""), mcpRecord(309, "")}, ","), ""),
			"an identifier twice":          batch(mcpRecord(300, "")+","+mcpRecord(300, ""), ""),
			"a tool with a description":    batch("", `{"name":"lookup_customer","risk":"read","description":"Looks a customer up"}`),
			"a tool of an unknown risk":    batch("", `{"name":"lookup_customer","risk":"dangerous"}`),
			"a tool name that is a phrase": batch("", `{"name":"ignore previous instructions","risk":"read"}`),
			"an added member":              `{"records":[],"tools":[],"note":"x"}`,
		} {
			if result, err := record(strPtr(server), q); err == nil || state(err) != "22023 gateway record rejected" {
				t.Fatalf("%s: result=%s state=%q", name, result, state(err))
			}
		}
		if rows := database.text(`SELECT count(*)::text FROM zasp_gateway_decisions`); rows != "0" {
			t.Fatalf("a refused record left %s rows", rows)
		}
		// A tool call of an agent: its request and its redacted response.
		agent := `"` + remediationAgentEntity + `"`
		value, err := record(strPtr(server), batch(mcpRecord(310, `{"agent_id":`+agent+`}`)+","+
			mcpRecord(311, `{"agent_id":`+agent+`,"direction":"response","decision":"redact","reason":"guardrail","rules":[{"id":"pii.email","category":"sensitive_data","mode":"redact","count":2}],"bytes":412}`),
			`{"name":"lookup_customer","risk":"read"},{"name":"run_report","risk":"execute"}`))
		if err != nil || !strings.Contains(string(value), `"recorded": 2`) {
			t.Fatalf("recorded=%s err=%v", value, err)
		}
		// A record is written once.
		if result, err := record(strPtr(server), batch(mcpRecord(310, ""), "")); err == nil || !strings.HasPrefix(state(err), "23505 ") {
			t.Fatalf("a record identifier was written twice: result=%s state=%q", result, state(err))
		}
		// The record names the policy versions it was decided under.
		if row := database.text(`SELECT surface||' '||operation||' '||direction||' '||decision||' '||reason||' '||bytes::text||' '||encode(content_digest,'hex')||' '||tool_name||' '||agent_id||' '||guardrail_version::text||' '||policy_version::text||' '||principal_id FROM zasp_gateway_decisions WHERE id=$1`, id(311)); row != "mcp tools/call response redact guardrail 412 "+strings.Repeat("ab", 32)+" lookup_customer "+remediationAgentEntity+" 0 1 "+actor {
			t.Fatalf("row=%s", row)
		}
		// A model request has no server and lists no tools.
		llm := `{"id":"` + id(320) + `","surface":"llm","operation":"chat.completions","direction":"request","decision":"block","reason":"guardrail","rules":[{"id":"injection.instruction_override","category":"prompt_injection","mode":"block","count":1}],"bytes":2048,"content_digest":"` + digest + `","tool_name":null,"provider":"openai","model":"gpt-test","agent_id":null}`
		if value, err = record(nil, batch(llm, "")); err != nil || !strings.Contains(string(value), `"recorded": 1`) {
			t.Fatalf("model record=%s err=%v", value, err)
		}
		if result, err := record(nil, batch("", `{"name":"lookup_customer","risk":"read"}`)); err == nil || state(err) != "22023 gateway record rejected" {
			t.Fatalf("tools without a server: result=%s state=%q", result, state(err))
		}
		if result, err := record(strPtr(other), batch(mcpRecord(330, ""), "")); err == nil || state(err) != "P0002 mcp gateway server not found" {
			t.Fatalf("a record of an unknown server: result=%s state=%q", result, state(err))
		}
	})

	t.Run("the tools a server listed", func(t *testing.T) {
		value, err := query(`SELECT zasp_authorization80.mcp_gateway_server_value($1,$2,$3,$4)`, o, w, e, server)
		// The most dangerous first; a name and a risk class, nothing else.
		if err != nil || !strings.Contains(string(value), `"tool_count": 2`) || strings.Index(string(value), `"run_report"`) > strings.Index(string(value), `"lookup_customer"`) || !strings.Contains(string(value), `"approval": "approved"`) || strings.Contains(string(value), `"last_activity_at": null`) {
			t.Fatalf("server=%s err=%v", value, err)
		}
		// A tool seen again keeps its identifier and takes the new risk class.
		before := database.text(`SELECT tool_id||' '||first_seen_at::text FROM zasp_mcp_gateway_tools WHERE server_id=$1 AND name='run_report'`, server)
		if _, err = record(strPtr(server), batch("", `{"name":"run_report","risk":"write"},{"name":"search_tickets","risk":"read"}`)); err != nil {
			t.Fatal(err)
		}
		if after := database.text(`SELECT tool_id||' '||first_seen_at::text FROM zasp_mcp_gateway_tools WHERE server_id=$1 AND name='run_report'`, server); after != before {
			t.Fatalf("a tool seen again was replaced: %s then %s", before, after)
		}
		if got := database.text(`SELECT string_agg(name||':'||risk,',' ORDER BY name) FROM zasp_mcp_gateway_tools WHERE server_id=$1`, server); got != "lookup_customer:read,run_report:write,search_tickets:read" {
			t.Fatalf("tools=%s", got)
		}
	})

	t.Run("tools seen through the gateway join the MCP tool inventory of the same host", func(t *testing.T) {
		// A discovered remote MCP server of the gateway server's host, with
		// one declared tool.
		const discovered, declared = "pid_74000000-0000-4000-8000-000000000001", "pid_74000000-0000-4000-8000-000000000002"
		database.exec(`SET session_replication_role=replica`)
		database.exec(`INSERT INTO zasp_inventory_entities(organization_id,workspace_id,environment_id,id,kind,display_name,stable_fields,first_seen_at,last_seen_at,product_kind,winning_integration_id,winning_provider,winning_source,winning_attributes)
VALUES($1,$2,$3,$4,'tool','tickets-mcp',jsonb_build_object('name','tickets-mcp'),now(),now(),'tool',$5,'aws','aws',jsonb_build_object('endpoint_host','mcp.tickets.test','transport','http')),
 ($1,$2,$3,$6,'tool','search_tickets',jsonb_build_object('name','search_tickets'),now(),now(),'tool',$5,'aws','aws',jsonb_build_object('risk','read'))`, o, w, e, discovered, remediationIntegration, declared)
		database.exec(`INSERT INTO zasp_inventory_source_observations(organization_id,workspace_id,environment_id,integration_id,source,entity_id,source_native_id,snapshot_id,source_state,first_seen_at,last_seen_at,provider,source_kind)
VALUES($1,$2,$3,$4,'aws',$5,'mcp:tickets','pid_a0000000-0000-4000-8000-000000000041','present',now(),now(),'aws','aws_mcp_server'),
 ($1,$2,$3,$4,'aws',$6,'mcp:tickets:search_tickets','pid_a0000000-0000-4000-8000-000000000041','present',now(),now(),'aws','aws_mcp_tool')`, o, w, e, remediationIntegration, discovered, declared)
		database.exec(`INSERT INTO zasp_inventory_relationships(organization_id,workspace_id,environment_id,id,integration_id,source,snapshot_id,from_entity_id,to_entity_id,kind,source_native_id,first_seen_at,last_seen_at)
VALUES($1,$2,$3,'pid_74000000-0000-4000-8000-000000000003',$4,'aws','pid_a0000000-0000-4000-8000-000000000041',$5,$6,'contains','mcp:tickets:contains:search_tickets',now(),now())`, o, w, e, remediationIntegration, discovered, declared)
		database.exec(`SET session_replication_role=origin`)
		if identity := database.text(`SELECT identity||' '||approval FROM zasp_mcp_servers($1,$2,$3) WHERE entity_id=$4`, o, w, e, discovered); identity != "host:mcp.tickets.test approved" {
			t.Fatalf("discovered server=%s", identity)
		}
		// The declared tool stays as it is; the two the gateway saw and the
		// inventory did not know are added, with the gateway's identifiers.
		tools := database.text(`SELECT string_agg(name||':'||risk||':'||(tool_id=$5)::text,',' ORDER BY name) FROM zasp_mcp_server_tools($1,$2,$3) WHERE server_id=$4`, o, w, e, discovered, declared)
		if tools != "lookup_customer:read:false,run_report:write:false,search_tickets:read:true" {
			t.Fatalf("inventory tools=%s", tools)
		}
		// The server's public shape lists them, the most dangerous first.
		shape := database.text(`SELECT (zasp_mcp_server_json($1,$2,$3,$4)->'tool_count')::text||' '||(zasp_mcp_server_json($1,$2,$3,$4)->'tools'->0->>'name')`, o, w, e, discovered)
		if shape != "3 run_report" {
			t.Fatalf("server shape=%s", shape)
		}
		// A gateway server of another host adds nothing to it.
		if _, err := writeServer(other, `{"name":"Other","upstream_url":"https://mcp.other.test/mcp","enabled":true,"allowed_tools":[],"denied_tools":[]}`, 0, 400); err != nil {
			t.Fatal(err)
		}
		if _, err := record(strPtr(other), batch("", `{"name":"wire_money","risk":"write"}`)); err != nil {
			t.Fatal(err)
		}
		if count := database.text(`SELECT count(*)::text FROM zasp_mcp_server_tools($1,$2,$3) WHERE server_id=$4`, o, w, e, discovered); count != "3" {
			t.Fatalf("inventory tools after another host=%s", count)
		}
		// Changing a gateway server's host drops the tools of the old one.
		if _, err := writeServer(other, `{"name":"Other","upstream_url":"https://mcp.elsewhere.test/mcp","enabled":false,"allowed_tools":[],"denied_tools":[]}`, 1, 402); err != nil {
			t.Fatal(err)
		}
		if count := database.text(`SELECT count(*)::text FROM zasp_mcp_gateway_tools WHERE server_id=$1`, other); count != "0" {
			t.Fatalf("tools of the old host=%s", count)
		}
	})

	t.Run("an agent's gateway traffic is its activity", func(t *testing.T) {
		// The agent had no activity source; its tool call through the
		// gateway, recorded above, now is one.
		activity := database.text(`SELECT zasp_inventory_agent_activity($1,$2,$3,$4,'agent','{}'::jsonb,NULL)::text`, o, w, e, remediationAgentEntity)
		if !strings.Contains(activity, `"activity_state": "active"`) || strings.Contains(activity, `"last_activity_at": null`) {
			t.Fatalf("activity=%s", activity)
		}
		if idle := database.text(`SELECT zasp_inventory_agent_activity($1,$2,$3,$4,'agent','{}'::jsonb,NULL)::text`, o, w, e, remediationLambdaEntity); !strings.Contains(idle, `"last_activity_at": null`) {
			t.Fatalf("another agent's activity=%s", idle)
		}
	})

	t.Run("the activity page", func(t *testing.T) {
		page := func(arguments ...any) (json.RawMessage, error) {
			return query(`SELECT zasp_authorization80.gateway_activity_value($1,$2,$3,$4,$5,$6,$7,$8,$9)`, append([]any{o, w, e}, arguments...)...)
		}
		var decoded struct {
			Items []struct {
				ID         string  `json:"id"`
				Surface    string  `json:"surface"`
				ServerName *string `json:"server_name"`
				Digest     string  `json:"content_digest"`
			} `json:"items"`
			NextID *string `json:"next_id"`
		}
		value, err := page(nil, nil, nil, nil, nil, 2)
		// Newest first, two of three, and the cursor is the last one shown.
		if err != nil || json.Unmarshal(value, &decoded) != nil || len(decoded.Items) != 2 || decoded.Items[0].ID != id(320) || decoded.Items[0].Surface != "llm" || decoded.Items[0].ServerName != nil || decoded.NextID == nil || *decoded.NextID != decoded.Items[1].ID || decoded.Items[0].Digest != digest {
			t.Fatalf("first page=%s err=%v", value, err)
		}
		value, err = page(nil, nil, nil, nil, *decoded.NextID, 2)
		if err != nil || json.Unmarshal(value, &decoded) != nil || len(decoded.Items) != 1 || decoded.Items[0].ID != id(310) || *decoded.Items[0].ServerName != "Tickets" || strings.Contains(string(value), `"next_id": "`) {
			t.Fatalf("second page=%s err=%v", value, err)
		}
		for name, filter := range map[string][]any{
			"by surface":  {"mcp", nil, nil, nil, nil, 10},
			"by server":   {nil, server, nil, nil, nil, 10},
			"by agent":    {nil, nil, remediationAgentEntity, nil, nil, 10},
			"by decision": {nil, nil, nil, "redact", nil, 10},
		} {
			value, err = page(filter...)
			want := 2
			if name == "by decision" {
				want = 1
			}
			if err != nil || json.Unmarshal(value, &decoded) != nil || len(decoded.Items) != want {
				t.Fatalf("%s: page=%s err=%v", name, value, err)
			}
		}
		for name, filter := range map[string][]any{
			"an unknown surface": {"web", nil, nil, nil, nil, 10},
			"a limit over 100":   {nil, nil, nil, nil, nil, 101},
			"an unknown cursor":  {nil, nil, nil, nil, id(999), 10},
			"an agent sentence":  {nil, nil, "ignore previous instructions", nil, nil, 10},
		} {
			if result, err := page(filter...); err == nil || state(err) != "22023 gateway activity page rejected" {
				t.Fatalf("%s: result=%s state=%q", name, result, state(err))
			}
		}
	})

	t.Run("removing a server keeps its records", func(t *testing.T) {
		remove := func(expected int64, n int) (json.RawMessage, error) {
			return query(`SELECT zasp_authorization80.mcp_gateway_server_remove($1,$2,$3,$4,$5,$6,$7,$8)`, o, w, e, actor, server, expected, id(n), id(n+1))
		}
		if result, err := remove(7, 500); err == nil || state(err) != "40001 mcp gateway server version conflict" {
			t.Fatalf("stale removal: result=%s state=%q", result, state(err))
		}
		if value, err := remove(1, 502); err != nil || !strings.Contains(string(value), `"deleted": true`) {
			t.Fatalf("removal=%s err=%v", value, err)
		}
		if result, err := remove(1, 504); err == nil || state(err) != "P0002 mcp gateway server not found" {
			t.Fatalf("second removal: result=%s state=%q", result, state(err))
		}
		if got := database.text(`SELECT (SELECT count(*) FROM zasp_mcp_gateway_tools WHERE server_id=$1)::text||' '||(SELECT count(*) FROM zasp_gateway_decisions WHERE server_id=$1)::text`, server); got != "0 2" {
			t.Fatalf("tools and records after removal=%s", got)
		}
	})

	t.Run("an API token may be created with use_gateway", func(t *testing.T) {
		definition := database.text(`SELECT pg_get_functiondef('zasp_authorization80_identity.create_pat(text,text,text,bytea,bytea,text,text,text,text,jsonb,timestamptz,text,text,timestamptz,bytea,bytea,bytea)'::regprocedure)`)
		if strings.Count(definition, "NOT IN('use_gateway','view',") != 1 || strings.Count(definition, "'run_tests','decide_guardrails'))") != 1 {
			t.Fatal("create_pat does not accept use_gateway exactly once")
		}
	})

	t.Run("the section left the catalog sealed", func(t *testing.T) {
		if intact := database.text(`SELECT zasp_baseline.intact()::text`); intact != "true" {
			t.Fatalf("intact=%s", intact)
		}
	})
}

func strPtr(value string) *string { return &value }
