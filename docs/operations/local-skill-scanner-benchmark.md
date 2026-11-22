# Offline skill scanner benchmark

This experiment measures which review signals three local scanners surface on seven small, synthetic skill bundles. A capability label means a reviewer can point to the relevant file declaration, call or markup. Every fixture is benign. Use these results to choose detectors for a developer's first scan and to decide what to display separately as package hygiene or incomplete coverage.

## Inputs and reproducibility

| Engine | Version and execution profile | Distribution |
| --- | --- | --- |
| ZASP | `zasp-static.v1` through `zaspctl addons scan --local --json`. Built with Go 1.26.0 for Linux/amd64. | Repository implementation and its Go module. |
| Cisco Skill Scanner | `cisco-ai-skill-scanner==2.3.2` with the default local `scan` profile and SARIF output. No opt-in behavioral analyzer, OSV, model or cloud service. | Apache 2.0. [Tagged source and license](https://github.com/cisco-ai-defense/skill-scanner/tree/f7824651ffeb9b89f7682ddd97d6fba8fe9c10b1) |
| NVIDIA SkillSpector | `2.13.6` built from the pinned source below. Used `scan --no-llm` with SARIF output. The isolated network forces SC4's static fallback. | Apache 2.0. [Tagged source and license](https://github.com/NVIDIA/SkillSpector/tree/e2674da339b0bddc6e565d059c0577c6d9cd25da) |

The runner creates each bundle in a temporary directory and starts each scanner as a separate process under Linux Bubblewrap with an empty environment, a temporary home, a read-only host filesystem and a network namespace with no external route. The scanner can write its result to the fixture's separate scratch directory. No skill is loaded, imported or executed. Installing tools and dependencies precedes the offline scan.

Build ZASP at the repository root. On a Linux machine with working `bwrap --unshare-net`, run the local baseline. Add installed vendor binaries to use the same inputs and environment for all engines.

```sh
go build -C cmd/zaspctl -o /tmp/zaspctl .
python3 scripts/skill-benchmark/run.py --zasp /tmp/zaspctl --repeats 5

uv venv /tmp/zasp-scanner-bench
uv pip install --python /tmp/zasp-scanner-bench/bin/python \
  cisco-ai-skill-scanner==2.3.2 \
  'skillspector @ git+https://github.com/NVIDIA/SkillSpector.git@e2674da339b0bddc6e565d059c0577c6d9cd25da'
python3 scripts/skill-benchmark/run.py --zasp /tmp/zaspctl \
  --cisco /tmp/zasp-scanner-bench/bin/skill-scanner \
  --nvidia /tmp/zasp-scanner-bench/bin/skillspector --repeats 1
```

The reference run used CPython 3.12.14 and a single isolated virtual environment for the two vendor tools. Its shared 132-package installation occupied about 590 MiB. This is the installed size of this combination, including optional capabilities pulled into default vendor dependency trees. Third-party transitive dependencies can change between installations. The bundled corpus SHA-256 was `9c7dc7473918f49fd325514536dc5d792bf684a0173896ae4b0481c52dfc0a77`. [Labeled fixtures](../../scripts/skill-benchmark/corpus.json) · [Runner](../../scripts/skill-benchmark/run.py)

## Run results

Each time below includes fresh process startup and the network namespace on a shared Linux worker. The ZASP time is the median of five runs per fixture. Cisco and NVIDIA each ran once per fixture. Host load varied during the experiment. These measurements describe this run and are unsuitable as production latency estimates.

| Fixture and labeled fact | ZASP rule and median | Cisco additional signal and time | NVIDIA signal and time |
| --- | --- | --- | --- |
| Plain guide. No capability. | None · 104 ms | None · 21.5 s | None · 36.4 s |
| Exact dependency pin. No range. | None · 78 ms | None · 56.0 s | Offline advisory fallback · 60.0 s |
| Dependency range. Pin review warranted. | `dependency.unpinned` · 54 ms | `SUPPLY_CHAIN_UNPINNED_DEPENDENCY` · 42.8 s | `SC1` and offline advisory fallback · 44.0 s |
| Local subprocess used only to print a greeting. | `script.shell_execution` · 54 ms | None · 51.2 s | `AST4`, `LP3` · 43.8 s |
| Source comment naming the same subprocess API. No executable call. | `script.shell_execution` · 82 ms | None · 47.0 s | `LP3` · 42.9 s |
| Hidden editorial markup. No command or request. | `instruction.hidden_text` · 74 ms | None · 49.7 s | None · 41.8 s |
| Network client targeting an invalid example domain. | `script.network_access` · 64 ms | `DATA_EXFIL_NETWORK_REQUESTS`, `TOOL_ABUSE_UNDECLARED_NETWORK` · 41.6 s | `LP3` · 42.3 s |

Cisco also emitted `MANIFEST_MISSING_LICENSE` on all seven fixtures. Their manifests omit the license field. NVIDIA's `SC4` explicitly says its live advisory lookup was unavailable and that its 15-package fallback can be incomplete. Its `LP3` describes a missing permission declaration. Neither code independently establishes a vulnerable dependency or executed capability. [NVIDIA rule definitions](https://github.com/NVIDIA/SkillSpector/blob/e2674da339b0bddc6e565d059c0577c6d9cd25da/src/skillspector/nodes/analyzers/pattern_defaults.py)

The built-in pack surfaced the four labeled review signals and also flagged the comment-only process reference. That fifth warning is a false positive for an *executable call*, although the lexical pattern is present. NVIDIA's AST subprocess signal appeared only on the executable helper. Cisco surfaced useful manifest-hygiene and network-permission signals. These seven benign bundles measure capability hints and review noise. They cannot estimate malware recall, adversarial robustness, general false-positive rates or installed runtime effects.

**Decision.** Keep the small built-in pack on the offline developer path. Mark its lexical process finding as a reference requiring review. Evaluate syntax-aware parsing on a larger permissioned corpus before promoting an executable-call claim. An optional private worker can return normalized vendor findings with analyzer/version, exact rule ID and a separate coverage status. The laptop scan and the findings-only submission should remain usable with the built-in binary alone. A missing license, an offline advisory source and a request-capable helper each deserve a distinct explanation in the UI.
