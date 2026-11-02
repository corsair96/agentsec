# agentsec

**Unified AI Agent Security Scanner** — local static scanning for AI agent stacks: MCP, agent code, skills, RAG pipelines, secrets and model endpoints.

`agentsec` is a single Rust binary with no telemetry and no LLM in the scanning loop. It produces an aggregated risk score (0-10), OWASP-mapped findings and a CI-friendly exit code.

## Installation

```bash
cargo build --release
./target/release/agentsec --help
```

## Usage

```bash
# Scan the current directory
agentsec scan

# Zero-config discovery (known MCP configs, skills, .env, CI, ...)
agentsec scan --auto

# Target a specific project
agentsec scan ./my-project --min-severity medium

# CI gate: fail if a finding >= high is present
agentsec scan --auto --fail-on high --format sarif --output agentsec.sarif
```

### Main options

| Option | Description |
|---|---|
| `[path]` | File or directory to scan (default: `.`) |
| `--auto` | Discover known MCP/skills/CI/.env configs on the machine |
| `--layer` | Filter: `mcp`, `agent`, `model`, `rag`, `secrets`, `skills` (or `all`) |
| `--min-severity` | Reporting threshold: `low`, `medium`, `high`, `critical` |
| `--format` | `terminal`, `json`, `sarif`, `markdown`, `html` |
| `--output` | Write the report to a file |
| `--fail-on` | Exit code 1 if a finding reaches this threshold |
| `--baseline` / `--baseline-save` | Drift detection / rug-pull |
| `--fix` / `--apply-fix` | Reserved for mechanical fixes (coming soon) |
| `--timeout` | Per-sub-scan timeout (reserved, local static scan) |
| `-v`, `--no-color` | Verbosity / disable colors |

### Subcommands

```bash
agentsec scan          # main scan
agentsec baseline save # save a baseline
agentsec baseline check --baseline agentsec-baseline.json
agentsec baseline diff  --baseline agentsec-baseline.json
agentsec list-rules    # list built-in rules
agentsec init          # generate agentsec.yaml
agentsec version
agentsec probe         # dynamic scan (stub, coming soon)
```

## Built-in rules (MVP)

| ID | Severity | Layer | Detection |
|---|---|---|---|
| MCP001 | high | mcp | Cleartext secret in an MCP server's `env`/`args` |
| MCP002 | critical | mcp | Tool poisoning / injection in tool descriptions |
| MCP003 | critical | mcp | Remote download piped into a shell |
| MCP004 | medium | mcp | MCP endpoint over cleartext HTTP |
| MCP005 | high | mcp | `npx -y` without a pinned version |
| MCP006 | high | mcp | Sensitive paths (`~/.ssh`, `~/.aws`, `/etc`, `.env`) |
| SEC001 | high | secrets | Known API keys / tokens (OpenAI, Anthropic, AWS, GitHub, ...) |
| SEC002 | critical | secrets | Committed private key |
| SEC003 | medium | secrets | Generic secret assignment |
| SKL001 | medium | skills | Unvalidated external URL |
| SKL002 | high | skills | Dangerous shell command |
| SKL003 | high | skills | Prompt injection pattern |
| SKL004 | high | skills | Access to sensitive paths |
| SKL005 | medium | skills | Invisible / bidirectional Unicode |
| AGT001 | medium | agent | Shell execution in agent code |
| AGT003 | high | agent | Unrestricted filesystem access |
| AGT004 | medium | agent | Auto-approval without human review |
| RAG001 | medium | rag | Network vector DB without authentication |
| RAG002 | medium | rag | RAG/embedding endpoint over cleartext HTTP |
| RAG003 | low | rag | Destructive index reset allowed |
| MOD001 | medium | model | Model endpoint over cleartext HTTP or bound to `0.0.0.0` |

## Risk score

```text
score = Σ (weight_severity × weight_layer × novelty_factor) / max_possible × 10
```

- `weight_severity`: critical=4, high=3, medium=2, low=1
- `weight_layer`: mcp=1.2, secrets=1.1, agent=1.0, model=1.0, rag=0.9, skills=0.8
- `novelty_factor`: 1.0 if new, 0.5 if already present in the baseline

## Architecture

```text
src/
  main.rs          CLI orchestration + exit code
  cli.rs           clap definitions
  discovery.rs     file collection + --auto
  finding.rs       Finding, Severity, Layer, OWASP
  rules.rs         rule registry
  score.rs         risk score computation
  baseline.rs      save/load/diff
  scanners/        mcp, secrets, skills, agent, rag, model
  report/          terminal, json, sarif, markdown, html
tests/cli.rs       end-to-end integration tests
```

## Roadmap

- Mechanical fixes (`--fix`, `--apply-fix`)
- Custom YAML rule loading (`~/.config/agentsec/rules/`, `agentsec.yaml`)
- Project config support in `scan`
- Actual per-sub-scan timeout enforcement
- Dynamic `probe` with optional LLM judge
- More AST-based rules (tree-sitter) for agent code
