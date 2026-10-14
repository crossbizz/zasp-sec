package apiserver

import (
	"context"
	"encoding/hex"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

var connectorCatalogKinds = [...]string{"namespace", "table", "view", "column", "constraint", "index", "policy", "trigger", "function"}

const connectorCatalogFingerprintSuffix = ") SELECT encode(public.digest(convert_to(COALESCE(jsonb_agg(jsonb_build_array(k,i,d) ORDER BY k,i)::text,'[]'),'UTF8'),'sha256'),'hex') FROM objects"
const connectorCatalogGUCQuery = `SELECT ARRAY[current_setting('TimeZone'),current_setting('DateStyle'),current_setting('quote_all_identifiers'),current_setting('standard_conforming_strings'),current_setting('extra_float_digits')]`

type connectorCatalogSnapshot struct {
	objects          map[string][]string
	kinds            map[string]int
	rows, duplicates int
	registered       bool
	ownerGUC, apiGUC []string
	valid            bool
}

// Diagnostics reuse the installed fingerprint's exact object CTE. Definitions,
// object identities, hashes and setting values never enter test output.
func connectorCatalogCapture(f *integrationClientFixture) (out connectorCatalogSnapshot) {
	ctx, cancel := context.WithTimeout(f.ctx, 10*time.Second)
	defer cancel()
	tx, err := f.owner.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return out
	}
	defer connectorProvenanceRollback(tx)
	if _, err = tx.Exec(ctx, `SET LOCAL statement_timeout='5s'; SET LOCAL lock_timeout='1s'; SET LOCAL ROLE zasp_discovery_authority; SET LOCAL search_path=pg_catalog,public`); err != nil {
		return out
	}
	var source string
	if tx.QueryRow(ctx, `SELECT prosrc FROM pg_proc WHERE oid='zasp_connector_maintenance.fingerprint()'::regprocedure`).Scan(&source) != nil {
		return out
	}
	source = strings.TrimSpace(source)
	if len(source) > 131072 || !strings.HasPrefix(source, "WITH objects AS (") || strings.Count(source, connectorCatalogFingerprintSuffix) != 1 || !strings.HasSuffix(source, connectorCatalogFingerprintSuffix) {
		return out
	}
	query := strings.TrimSuffix(source, connectorCatalogFingerprintSuffix) + `) SELECT k,i,encode(public.digest(convert_to(d::text,'UTF8'),'sha256'),'hex') FROM objects ORDER BY k,i LIMIT 4097`
	rows, err := tx.Query(ctx, query)
	if err != nil {
		return out
	}
	out.objects = make(map[string][]string)
	out.kinds = make(map[string]int)
	for rows.Next() {
		var kind, identity, hash string
		if rows.Scan(&kind, &identity, &hash) != nil || !stringIn(kind, connectorCatalogKinds[:]...) || len(identity) > 4096 || !connectorCatalogHash(hash) || out.rows >= 4096 {
			rows.Close()
			return connectorCatalogSnapshot{}
		}
		key := kind + "\x00" + identity
		if len(out.objects[key]) > 0 {
			out.duplicates++
		}
		out.objects[key] = append(out.objects[key], hash)
		out.kinds[kind]++
		out.rows++
	}
	if rows.Err() != nil {
		rows.Close()
		return connectorCatalogSnapshot{}
	}
	rows.Close()
	for _, hashes := range out.objects {
		sort.Strings(hashes)
	}
	if tx.QueryRow(ctx, `SELECT count(*)=1 AND bool_and(fingerprint=zasp_connector_maintenance.fingerprint()) FROM zasp_connector_maintenance.registration WHERE singleton`).Scan(&out.registered) != nil || tx.QueryRow(ctx, connectorCatalogGUCQuery).Scan(&out.ownerGUC) != nil {
		return connectorCatalogSnapshot{}
	}
	if tx.Commit(ctx) != nil || f.api.QueryRow(ctx, connectorCatalogGUCQuery).Scan(&out.apiGUC) != nil {
		return connectorCatalogSnapshot{}
	}
	out.valid = true
	return out
}

func connectorCatalogReport(t *testing.T, f *integrationClientFixture, before connectorCatalogSnapshot) {
	t.Helper()
	after := connectorCatalogCapture(f)
	if !before.valid || !after.valid {
		t.Log("connector catalog diagnostic=unavailable")
		return
	}
	t.Logf("connector catalog diagnostic=observed before_rows=%d after_rows=%d before_duplicates=%d after_duplicates=%d before_registered=%t after_registered=%t before_guc_equal=%t after_guc_equal=%t owner_guc_stable=%t api_guc_stable=%t", before.rows, after.rows, before.duplicates, after.duplicates, before.registered, after.registered, reflect.DeepEqual(before.ownerGUC, before.apiGUC), reflect.DeepEqual(after.ownerGUC, after.apiGUC), reflect.DeepEqual(before.ownerGUC, after.ownerGUC), reflect.DeepEqual(before.apiGUC, after.apiGUC))
	for _, kind := range connectorCatalogKinds {
		added, removed, changed := 0, 0, 0
		for key, hashes := range before.objects {
			if !strings.HasPrefix(key, kind+"\x00") {
				continue
			}
			other, ok := after.objects[key]
			if !ok {
				removed++
			} else if !reflect.DeepEqual(hashes, other) {
				changed++
			}
		}
		for key := range after.objects {
			if strings.HasPrefix(key, kind+"\x00") {
				if _, ok := before.objects[key]; !ok {
					added++
				}
			}
		}
		t.Logf("connector catalog kind=%s before=%d after=%d added=%d removed=%d changed=%d", kind, before.kinds[kind], after.kinds[kind], added, removed, changed)
	}
}

func connectorCatalogHash(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == 32 && hex.EncodeToString(decoded) == value
}
