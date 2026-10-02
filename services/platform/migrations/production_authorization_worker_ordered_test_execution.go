package migrations

import _ "embed"

//go:embed sql/0080_authorization_worker_ordered_test.sql
var authorizationWorkerOrderedTestSQL string
