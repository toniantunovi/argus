# Argus

Autonomous vulnerability discovery and exploit validation. Argus decomposes security research into structured stages that LLMs execute reliably: reconnaissance, hypothesis generation, triage, and proof-of-concept validation.

Argus doesn't review code for style or suggest improvements. It hunts for exploitable vulnerabilities and proves they're real.

| Domain | Capability | Example |
|--------|-----------|---------|
| Web application vulnerabilities | Full exploit PoC | Missing auth &rarr; HTTP request proving unauthorized access |
| Injection flaws | Full exploit PoC | SQL injection &rarr; crafted input extracting data |
| Business logic bugs | Full exploit PoC | API call sequence exercising invalid state transition |
| Memory safety (C/C++/Rust unsafe) | Crash confirmation via ASAN | Buffer overflow &rarr; crafted input triggering ASAN report |
| Concurrency bugs | Race demonstration | TOCTOU &rarr; concurrent requests proving the race window |
| Multi-finding chains | Chain identification + PoCs | SSRF + no internal auth &rarr; full internal network access |

Argus is not a replacement for SAST. Run both:

```bash
semgrep --config auto .    # SAST: known patterns, fast, deterministic
argus scan .               # Argus: reasoning-based vulnerability research
```

## Requirements

- Python 3.11+
- Docker (for Layer 3 PoC validation in sandboxed containers)
- An API key for at least one LLM provider (OpenAI, Anthropic, Google, or a local Ollama instance)
- [Claw Code](https://github.com/ultraworkers/claw-code) (auto-installed in Docker sandbox for Layer 3 PoC validation)

## Installation

```bash
# Clone and install with your preferred LLM provider
cd argus
pip install -e ".[dev,anthropic]"    # Anthropic (default)
pip install -e ".[dev,openai]"       # OpenAI
pip install -e ".[dev,google]"       # Google
pip install -e ".[dev,ollama]"       # Ollama (local models)
pip install -e ".[dev,all-llm]"      # All providers
```

If you cannot do an editable install (e.g., missing setuptools), set `PYTHONPATH` directly:

```bash
export PYTHONPATH=/path/to/argus/src
```

Verify the install:

```bash
python -m argus --help
```

## LLM Configuration

Set your API key as an environment variable:

```bash
export ANTHROPIC_API_KEY=your-key    # for Anthropic (default)
export OPENAI_API_KEY=your-key       # for OpenAI
export GOOGLE_API_KEY=your-key       # for Google
```

Configure the provider and model in `argus.yml`:

```yaml
llm:
  provider: anthropic                  # openai | anthropic | google | ollama
  model: claude-sonnet-4-20250514
  temperature: 0.0

  # Per-layer model overrides (optional)
  hypothesis:
    model: claude-haiku-4-5-20251001   # fast/cheap for high-volume Layer 1
  triage:
    model: claude-sonnet-4-20250514    # strong reasoning for Layer 2
  validation:
    model: claude-sonnet-4-20250514    # code generation for Layer 3
```

For local models via Ollama:

```yaml
llm:
  provider: ollama
  model: llama3
  base_url: http://localhost:11434
```

## How it works

```
Target codebase
    |
    v
RECONNAISSANCE (deterministic, no LLM)
    Tree-sitter parsing -> function extraction -> risk signal detection
    -> vulnerability scoring -> call graph -> taint tracking -> target ranking
    |
    v  (ranked target list)
LAYER 1: HYPOTHESIS (LLM)
    Context builder scopes each target function (~4K tokens)
    LLM hypothesizes vulnerabilities against detection rubrics
    Confidence gating: promote (>=0.7) / batch (0.4-0.7) / suppress (<0.4)
    |
    v  (confidence-gated hypotheses)
LAYER 2: TRIAGE + CHAIN ANALYSIS (LLM)
    Individual + batch triage: exploitable / mitigated / false_positive / uncertain
    Deterministic chain grouping + LLM chain evaluation
    Severity gating for Layer 3
    |
    v  (exploitable + uncertain findings)
LAYER 3: EXPLOIT VALIDATION (Claw Code + Docker sandbox)
    Claw Code agent autonomously writes/compiles/runs PoCs inside sandbox
    Per-vuln-class validation (HTTP requests, ASAN crashes, race conditions, etc.)
    Optional patch generation with compile + PoC + test validation
    |
    v
VULNERABILITY REPORT (text / JSON / SARIF / AI / Markdown format)
```

**Key property:** Reconnaissance is fully deterministic (tree-sitter, no LLM). Same codebase always produces the same target list. LLM layers are rubric-constrained and cached.

## Usage

### CLI

```bash
# Full scan on a project
argus scan /path/to/project

# Scan with verbose logging
argus -v scan /path/to/project

# Specific vulnerability categories only
argus scan --categories memory,auth,injection /path/to/project

# Output formats: text (default), json, sarif, ai, markdown
argus scan --format json /path/to/project
argus scan --format sarif /path/to/project > results.sarif
argus scan --format ai /path/to/project
argus scan --format markdown /path/to/project

# Write report to a file
argus scan --format markdown -o report.md /path/to/project
argus scan --format json -o results.json /path/to/project

# Generate patches for confirmed findings
argus scan --fix /path/to/project

# Resume an interrupted scan
argus scan --resume /path/to/project

# Force full rescan (ignore cache)
argus scan --no-cache /path/to/project

# Override PoC iteration budget
argus scan --iterations 8 /path/to/project
```

### Managing findings

```bash
# Check scan status
argus status

# List findings (from last scan)
argus findings
argus findings --severity critical,high
argus findings --category auth,injection

# Suppress a false positive
argus suppress argus-sqli-handler.py-84 --reason "input validated in middleware" --scope function

# Suppression scopes:
#   finding   - this exact finding
#   function  - all findings for this function (survives line changes)
#   rule      - all findings matching this rule in this file
#   project   - all findings matching this rule project-wide

# Report a vulnerability Argus missed
argus missed src/handlers/admin.py:47 --category auth --description "missing admin check on delete endpoint"

# Clean up persisted scan state
argus clean-state
```

## PoC validation via Claw Code

Layer 3 validation uses [Claw Code](https://github.com/ultraworkers/claw-code) as an autonomous agent inside the Docker sandbox. Instead of generating PoC code in a single LLM call, Claw autonomously writes, compiles, debugs, and runs PoCs using its own tool loop (bash, file read/write). It compiles against the actual target source and iterates on build errors without round-tripping through Argus.

```yaml
validation:
  claw_timeout_default: 120    # seconds per finding
  claw_timeout_memory: 180     # higher for memory bugs
  claw_max_turns: 30           # Claw agent turns per finding
  claw_api_key_env: null       # API key env var forwarded to container (auto-detected)
```

The Claw container needs network access for LLM API calls. See the [spec](argus.md) for the full security model.

## Configuration

Create `argus.yml` in your project root. All fields are optional -- defaults are shown below:

```yaml
scan:
  include: []                        # paths to scan (default: entire project)
  exclude: []                        # paths to skip
  languages: []                      # auto-detected if omitted
  project_type: "auto"               # "auto", "application", "library"
  detection_categories:              # all 9 enabled by default
    - auth
    - data_access
    - crypto
    - input
    - financial
    - privilege
    - memory
    - injection
    - concurrency

reconnaissance:
  min_likelihood_score: 1.0          # skip functions below this
  max_review_chunks: 100             # cap targets per scan
  interaction_targets: true          # detect shared-state interaction targets
  auto_exclude: true                 # auto-exclude generated/vendored code

scoring:
  hypothesis_confidence_threshold: 0.7
  batch_confidence_threshold: 0.4

triage:
  reachability: true
  chain_analysis: true
  patch: true                        # generate remediation patches
  patch_iterations: 3

validation:
  enabled: true
  severity_gate: "high"              # generate PoCs for high+ severity only
  max_exploits: 10                   # cap PoC attempts per scan
  max_iterations_simple: 3           # missing auth, basic injection
  max_iterations_medium: 5           # business logic, race conditions
  max_iterations_memory: 5           # ASAN crash confirmation
  max_iterations_chain: 8            # multi-finding chains
  instrumentation:
    - asan
    - ubsan
    - coverage
  # Claw Code PoC validation settings
  claw_timeout_default: 120          # wall-clock seconds per finding
  claw_timeout_memory: 180           # higher budget for memory bugs
  claw_max_turns: 30                 # Claw agent tool-use turns
  claw_api_key_env: null             # API key env var forwarded to container (auto-detected)

sandbox:
  runtime: docker
  timeout_default: 30                # seconds
  timeout_race_condition: 120
  timeout_max: 300
  mem_limit: "512m"
  cpu_quota: 200000                  # 2 CPU cores
  pids_limit: 256
  network: none                      # no network egress

concurrency:
  max_concurrent_hypotheses: 8
  max_concurrent_triage: 4
  max_concurrent_validations: 2

budget:
  max_tokens_per_scan: null          # null = unlimited
  max_cost_per_scan: null
  layer3_budget_fraction: 0.4

cache:
  enabled: true
  invalidation: "interface"          # "interface" (scoped) or "any_change"
  cross_cutting_invalidation: true

output:
  format: "markdown"                  # text, json, sarif, ai, markdown
  include_poc: true
  include_reasoning: false

resume:
  enabled: true
  state_dir: ".argus/scan-state"

llm:
  provider: "anthropic"              # openai | anthropic | google | ollama
  model: "claude-sonnet-4-20250514"
  api_key_env: null                  # auto-detected per provider
  base_url: null                     # for ollama/vLLM
  temperature: 0.0
  hypothesis:                        # per-layer overrides (all optional)
    model: null
  triage:
    model: null
  validation:
    model: null
```

### Custom rubrics

Add custom detection rules by placing YAML files in `.argus/rubrics/`:

```yaml
# .argus/rubrics/custom-ssrf.yml
category: injection
detection_rules:
  - name: internal_ssrf
    instruction: "Check if any URL parameter is used to make server-side HTTP
    requests without restricting the target to allowed hosts."

calibration:
  test_cases:
    - file: "tests/vulns/ssrf_vulnerable.py"
      function: "fetch_url"
      expected: true
    - file: "tests/vulns/ssrf_safe.py"
      function: "fetch_url"
      expected: false
```

Custom rubrics extend the built-in rubrics -- they don't replace them.

## Output formats

### Text (default)

Human-readable terminal output with severity-sorted findings, attack scenarios, and PoC validation status.

### JSON

Full structured report via `--format json`. Contains all finding fields, chain analysis, scan progress, and budget usage.

### SARIF 2.1.0

Standard static analysis format via `--format sarif`. Compatible with VS Code, GitHub Code Scanning, Defect Dojo, and other SARIF consumers. Each finding maps to a SARIF result with rule ID, severity level, locations, and PoC in properties.

### AI

Structured for consumption by downstream LLM agents via `--format ai`. Includes natural-language attack narratives and actionable remediation context per finding.

### Markdown

Detailed, self-contained report via `--format markdown`. Designed for sharing with security teams and for reproducibility. Each finding includes:

- Severity, classification, confidence, and location metadata
- Full description, attack scenario, and analysis reasoning
- **Complete PoC source code** in fenced code blocks with language highlighting
- **Step-by-step reproduction instructions** tailored to the vulnerability category (e.g. ASAN compilation flags for memory bugs)
- **Execution output** (stdout/stderr) from the sandbox validation run
- **Sanitizer output** with violation type and details (for memory safety bugs)
- **Suggested patches** when available
- Attack chain relationships between findings

Write to a file with `-o`:

```bash
argus scan --format markdown -o report.md /path/to/project
```

## Project state

Argus stores runtime state in `.argus/` in the project root:

| Path | Purpose | VCS |
|------|---------|-----|
| `.argus/suppressions.json` | Suppressed findings | Commit (shared across team) |
| `.argus/missed.json` | Reported false negatives | Commit (shared across team) |
| `.argus/cache/` | LLM result cache | Gitignore |
| `.argus/scan-state/` | In-progress scan state for resume | Gitignore |
| `.argus/calibration/` | Confidence calibration data | Gitignore |

## Vulnerability categories

| Category | Weight | What Argus looks for |
|----------|--------|---------------------|
| `auth` | 1.5 | Missing checks, broken access control, privilege escalation, session fixation |
| `data_access` | 1.0 | Unscoped queries, IDOR, SQL injection |
| `input` | 1.0 | Type confusion, missing validation, unsafe deserialization |
| `crypto` | 1.2 | Weak randomness, wrong algorithm, timing side-channels |
| `financial` | 1.3 | Invalid state transitions, double-spend, missing idempotency |
| `privilege` | 1.4 | Incomplete privilege drops, TOCTOU in privilege boundaries |
| `memory` | 1.5 | Buffer overflows, use-after-free, integer overflow, format strings |
| `injection` | 1.5 | Command injection, SSTI, LDAP injection, header injection |
| `concurrency` | 1.0 | Race conditions, TOCTOU, double-fetch |

## Supported languages

Argus uses tree-sitter for parsing and supports:

Python, JavaScript, TypeScript, TSX, Java, Go, Rust, C, C++, Ruby, PHP

Language is auto-detected from file extensions. Override with `scan.languages` in config.

## Development

### Running tests

```bash
# All tests (327 tests, ~1 second)
pytest tests/ -v

# Specific module
pytest tests/test_recon/ -v

# Single test class
pytest tests/test_recon/test_signals.py::TestSqlInjectionSignals -v

# With coverage
coverage run -m pytest tests/ && coverage report
```

### Linting

```bash
ruff check src/argus/
ruff check src/argus/ --fix    # auto-fix
```

### Project structure

```
src/argus/
    models/          # Pydantic v2 data models (core, scan, context, finding, etc.)
    recon/           # Reconnaissance: parsing, extraction, signals, scoring, call graph
    context_builder/ # Context assembly for each layer, framework/sanitizer detection
    rubrics/         # YAML detection/triage/exploit rubrics (28 files, 9 categories)
    hypothesis/      # Layer 1: parallel hypothesis generation + confidence gating
    triage/          # Layer 2: classification, chain analysis
    validation/      # Layer 3: Claw Code agentic PoC generation + sandbox execution
    sandbox/         # Docker container lifecycle, security policy, instrumentation
    llm/             # LangChain multi-provider LLM client, schema validation, retry, budget, calibration
    cache/           # Content-addressed cache with cross-cutting invalidation
    pipeline/        # Orchestrator, resume, concurrency management
    suppression/     # False positive/negative management
    output/          # Text, JSON, SARIF 2.1.0, AI, Markdown output formats
    cli.py           # Click CLI
    config.py        # argus.yml loading

tests/
    fixtures/        # Intentionally vulnerable codebases (Python, C, Node.js)
    test_recon/      # Parser, exclusions, extractor, signals, scorer, call graph
    test_context_builder/
    test_hypothesis/
    test_triage/
    test_cache/
    test_suppression/
    test_output/
    test_pipeline/   # Integration with mocked LLM + sandbox
    test_llm/        # LangChain client, provider routing, config
    test_integration/
```

## How Argus differs from SAST

SAST matches patterns. Argus reasons about what code is *supposed* to do, then proves it doesn't.

SAST finds `eval(user_input)`. Argus finds that a three-step API call sequence lets an unauthenticated user approve their own refund, then generates an HTTP request sequence that demonstrates it.

SAST is deterministic, fast, and free. Argus uses LLM reasoning, costs tokens, and takes minutes. They catch different classes of bugs. Run both.

## Limitations

- **No kernel-mode validation.** The Docker sandbox runs userspace code. Kernel bugs get Layer 1-2 analysis without PoC confirmation.
- **No cross-service chains.** Analysis operates within a single repository.
- **No cross-language taint tracking.** In multi-language projects (Python calling C via FFI), each language is analyzed independently.
- **Call graph is approximate.** Dynamic dispatch, callbacks, and metaprogramming create gaps. The LLM compensates using context, but precision varies by language.
- **Not a CI gate.** Argus is a research tool, not a linter. CI pipelines should use deterministic tools.

## Spec

The full specification is in [`argus.md`](argus.md). The implementation plan is in [`plan.md`](plan.md).
