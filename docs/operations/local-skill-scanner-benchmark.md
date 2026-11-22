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
