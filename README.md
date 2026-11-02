# agentsec

**Unified AI Agent Security Scanner** — scan statique local des stacks d'agents IA : MCP, code agent, skills, pipelines RAG, secrets et endpoints de modèles.

`agentsec` est un binaire Rust unique, sans télémétrie et sans LLM dans la boucle de scan. Il produit un score de risque agrégé (0-10), des findings mappés OWASP et un code de sortie exploitable en CI.

## Installation

```bash
cargo build --release
./target/release/agentsec --help
```

## Utilisation

```bash
# Scan du répertoire courant
agentsec scan

# Découverte zero-config (configs MCP connues, skills, .env, CI, ...)
agentsec scan --auto

# Scan ciblé d'un projet
agentsec scan ./mon-projet --min-severity medium

# Gate CI : échoue si un finding >= high est présent
agentsec scan --auto --fail-on high --format sarif --output agentsec.sarif
```

### Options principales

| Option | Description |
|---|---|
| `[path]` | Fichier ou dossier à scanner (défaut : `.`) |
| `--auto` | Découvre les configs MCP/skills/CI/.env connues de la machine |
| `--layer` | Filtre : `mcp`, `agent`, `model`, `rag`, `secrets`, `skills` (ou `all`) |
| `--min-severity` | Seuil de rapport : `low`, `medium`, `high`, `critical` |
| `--format` | `terminal`, `json`, `sarif`, `markdown`, `html` |
| `--output` | Écrit le rapport dans un fichier |
| `--fail-on` | Code de sortie 1 si un finding atteint ce seuil |
| `--baseline` / `--baseline-save` | Détection de dérive / rug-pull |
| `--fix` / `--apply-fix` | Réservé aux correctifs mécaniques (à venir) |
| `--timeout` | Timeout par sous-scan (réservé, scan statique local) |
| `-v`, `--no-color` | Verbosité / désactivation des couleurs |

### Sous-commandes

```bash
agentsec scan          # scan principal
agentsec baseline save # sauvegarde un baseline
agentsec baseline check --baseline agentsec-baseline.json
agentsec baseline diff  --baseline agentsec-baseline.json
agentsec list-rules    # liste les règles intégrées
agentsec init          # génère agentsec.yaml
agentsec version
agentsec probe         # scan dynamique (stub, à venir)
```

## Règles intégrées (MVP)

| ID | Sévérité | Couche | Détection |
|---|---|---|---|
| MCP001 | high | mcp | Secret en clair dans `env`/`args` d'un serveur MCP |
| MCP002 | critical | mcp | Tool poisoning / injection dans les descriptions |
| MCP003 | critical | mcp | Téléchargement distant piped dans un shell |
| MCP004 | medium | mcp | Endpoint MCP en HTTP clair |
| MCP005 | high | mcp | `npx -y` sans version épinglée |
| MCP006 | high | mcp | Chemins sensibles (`~/.ssh`, `~/.aws`, `/etc`, `.env`) |
| SEC001 | high | secrets | Clés API / tokens connus (OpenAI, Anthropic, AWS, GitHub, ...) |
| SEC002 | critical | secrets | Clé privée commitée |
| SEC003 | medium | secrets | Affectation générique de secret |
| SKL001 | medium | skills | URL externe non validée |
| SKL002 | high | skills | Commande shell dangereuse |
| SKL003 | high | skills | Pattern de prompt injection |
| SKL004 | high | skills | Accès à des chemins sensibles |
| SKL005 | medium | skills | Unicode invisible / bidirectionnel |
| AGT001 | medium | agent | Exécution shell dans le code agent |
| AGT003 | high | agent | Accès filesystem non restreint |
| AGT004 | medium | agent | Auto-approbation sans revue humaine |
| RAG001 | medium | rag | Vector DB réseau sans authentification |
| RAG002 | medium | rag | Endpoint RAG/embedding en HTTP clair |
| RAG003 | low | rag | Reset destructif d'index autorisé |
| MOD001 | medium | model | Endpoint modèle en HTTP clair ou bind `0.0.0.0` |

## Score de risque

```text
score = Σ (weight_severity × weight_layer × novelty_factor) / max_possible × 10
```

- `weight_severity` : critical=4, high=3, medium=2, low=1
- `weight_layer` : mcp=1.2, secrets=1.1, agent=1.0, model=1.0, rag=0.9, skills=0.8
- `novelty_factor` : 1.0 si nouveau, 0.5 si déjà présent dans le baseline

## Architecture

```text
src/
  main.rs          orchestration CLI + code de sortie
  cli.rs           définition clap
  discovery.rs     collecte des fichiers + --auto
  finding.rs       Finding, Severity, Layer, OWASP
  rules.rs          registre des règles
  score.rs          calcul du risk score
  baseline.rs       save/load/diff
  scanners/         mcp, secrets, skills, agent, rag, model
  report/           terminal, json, sarif, markdown, html
tests/cli.rs       tests d'intégration bout-en-bout
```

## Roadmap

- Correctifs mécaniques (`--fix`, `--apply-fix`)
- Chargement de règles YAML custom (`~/.config/agentsec/rules/`, `agentsec.yaml`)
- Prise en compte de la config projet dans `scan`
- Timeout réel par sous-scan
- `probe` dynamique avec LLM judge optionnel
- Plus de règles AST (tree-sitter) pour le code agent
