# Hosted original connector native integration

This standalone workflow runs the existing original captured-INACTIVE connector fixture on an isolated hosted runner, using pinned PostgreSQL 18.3 and OpenFGA 1.21.0 tools. It requires one original top test, all nine exact subcases, no failures or skips, package PASS, real FGA authentication and listener ownership, and normally joined PG/FGA cleanup. Source pins and the original 256 MiB memory floor are checked throughout. It uses no deployment or provider credentials and does not change the existing 37-step release workflow.

Independent source and comment-only adoption reviews passed. Scoped ESLint, syntax and diff checks passed. No new application test cases were added. Actual hosted execution is still pending; source review alone does not verify the SQL behavior, native activation, production availability or launch completion. Earlier local setup, disk and memory refusals remain explicit evidence. The 728-row ledger is unchanged.
