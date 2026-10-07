# Preserved Test74 follow-up failures

These are whole original Go JSONL and stderr captures plus explicitly derived owner-result selections. Full original source closures and owner results remain at the referenced private paths. No failed test source was adopted.

`autonomous-diagnostic`: credential admission passed nine events. The genuine Test74 test still failed its original approval-origin assertion. Six bounded diagnostic scalars showed autonomous=true, queued=true, waiting_approval=false, approvals=0, notifications=0, origins=0. The diagnostic owner intentionally accepted that precise failure, not a positive test result. Independent actual review: `5377be9b8394f423f603ce761ef2a908ec3845d4023fca2be15b72d47ae03091`.

`supervised-create-failure`: credential admission passed nine events; the genuine supervised test failed before activation, run admission, human approval or effect. Its actual typed create returned `repository record not found`. The owner refused this run. Independent actual review: `fc4635d175ed3344ddbfc87d6c4ed3de9293dedbb85c9389928cee9865ce69e9`.

Both runs stopped their owned PostgreSQL and OpenFGA processes normally. No forced cleanup, owned-session survivors or unknown process census was reported. These are owned-process observations, not global process-absence proof. Neither run activated production or proves supervised Test74 acceptance.

Relevant original requirements remain M7A-10 (definition create/detail), M7A-14 (fresh-auth approval), M7A-48 (activation), and M7A-49 (budgets). No ledger classification changed. The original 728 requirements and deployed Stytch/provider proof remain mandatory.
