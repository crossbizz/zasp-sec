# Maintaining the framework reference index

The production service and offline scanner embed the reviewed JSON snapshots. Five commit-pinned upstream files are listed with their SHA-256 digests in [releases.json](releases.json). The OWASP sources are the published Agentic 2026 and LLM 2025 PDFs and the LLM 2026 project's final index. ATLAS uses MITRE's 6.1.0 distribution format and content release 2026.10. The Enterprise entry uses T1059 at ATT&CK 19.1.

To reproduce one release, download the exact source URL from its lock, keep it outside the repository and run the importer. The examples below assume the repository root. The importer reads local bytes and checks their digest before parsing. PDF extraction requires Poppler's pdftotext and ATLAS extraction requires PyYAML. The customer runtime requires neither.

```sh
python3 scripts/framework-catalog/catalog.py import mitre_atlas 2026.10 /tmp/ATLAS-2026.10.yaml --check
python3 scripts/framework-catalog/catalog.py diff services/platform/compliancemap/data/owasp_llm_top10-2025.json services/platform/compliancemap/data/owasp_llm_top10-2026.json
python3 -m unittest discover -s scripts/framework-catalog
go -C services/platform test ./compliancemap
```

To add an edition, review the upstream license and commit, add its source digest and teach the importer its reviewed format and expected counts. Import it as a new snapshot. Compare both editions and review changed IDs before adding qualified rule mappings. ATLAS UUID changes flag reassignment. OWASP ranks can change meaning, so title changes request a manual reassignment review. Retain previously shipped releases, historical titles and original exports.

The ATLAS file stores published technique, subtechnique and mitigation metadata. Its active denominator excludes the legacy-only AML.T0057 lookup. Product applicability and the scope of each reviewed association live in [reviews.go](../../services/platform/compliancemap/reviews.go). [Rule reviews](../../services/platform/compliancemap/rule_reviews.go) give the prerequisites and reason for each edition-specific link. Per-surface values remain unassessed until reviewed. An observed write, read, digest change or invocation alone cannot establish adversary behavior.

## Attribution

OWASP risk headings are reproduced and arranged by edition from the OWASP GenAI Security Project, under [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/). These derived OWASP indexes are available under the same license. The JSON snapshots and release locks identify the original work for each edition.

The ATLAS index uses MITRE ATLAS data, copyright 2021–2026 MITRE, under the [MITRE notice](../../services/platform/compliancemap/data/MITRE-ATLAS-NOTICE.txt) and [Apache License 2.0](../../services/platform/compliancemap/data/APACHE-2.0.txt). The transformation selects identifiers, UUIDs, titles and parent relationships and adds Zasp's retired-ID record.

© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation. The Enterprise index contains the T1059 reference only. [ATT&CK license](../../services/platform/compliancemap/data/MITRE-ATTACK-LICENSE.txt)

## Weekly upstream review

The read-only **Review upstream framework reference changes** workflow checks the five pinned file paths, published MITRE tags and official OWASP edition directories every Tuesday. Its job summary and 60-day JSON artifact identify changed file blob IDs, moved or removed tags and new editions requiring human review. For the single Enterprise T1059 entry it compares the published STIX heading and ID. For a new indexed LLM edition it reports per-rank title changes. New PDFs and large ATLAS distributions receive a file-level diff for review through the importer. Git blob IDs identify the changed repository objects. The checked-in SHA-256 values identify the exact reviewed source bytes.

Run `python3 scripts/framework-catalog/watch.py NEW_OUTPUT_DIR` for a local review. An unavailable upstream returns a failing status and a partial artifact. An observed upstream change never modifies a lock, rule, release or tenant record. Confirm publication, review the normalized diff, applicability and historical links before introducing another edition. The push/PR catalog fixture job covers renamed controls, changed tags, removed files and unavailable sources without network access.
