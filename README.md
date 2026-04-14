# Prowl

> **Autonomous vulnerability discovery and exploit validation.** Prowl reads a codebase, generates hypotheses, and writes working proof-of-concept exploits inside a Docker sandbox — compiled against the real source, confirmed by ASAN crashes, injection markers, or brute-force success.

```bash
pip install "prowl-sec[anthropic]"
export ANTHROPIC_API_KEY=sk-ant-...        # https://console.anthropic.com/settings/keys
prowl scan /path/to/project
```

Prefer a `.env` file? Drop `ANTHROPIC_API_KEY=sk-ant-...` into `.env` in the directory you run `prowl scan` from — it's picked up automatically.

Reconnaissance is fully deterministic (tree-sitter, no LLM — same codebase always produces the same target list). The LLM layers are rubric-constrained, confidence-gated, and cached. PoC generation runs as an agent loop via [Claw Code](https://github.com/ultraworkers/claw-code) inside a hardened Docker sandbox.

## What it found

Running Prowl against five widely deployed open-source projects produced **16 validated exploit PoCs**. Full reports with PoC source, ASAN output, and reproduction steps: [`reports/`](reports/).

| Project | Commit | Findings | Validated PoCs | Report |
|---------|--------|----------|----------------|--------|
| ffmpeg  | `b09d57c41d` | 85 (10 HIGH) | 5 memory-corruption | [ffmpeg_b09d57c41d.md](reports/ffmpeg_b09d57c41d.md) |
| curl    | `ec445fc595` | 74 (5 HIGH)  | 4 (MITM, heap overflow, unbounded writes) | [curl_ec445fc595.md](reports/curl_ec445fc595.md) |
| OpenSSL | `53e349fae6` | 69 (7 HIGH)  | 2 (RSA OAEP OOB read, padding oracle) | [openssl_53e349fae6.md](reports/openssl_53e349fae6.md) |
| SQLite  | `f02d100e08` | 59 (4 HIGH)  | 3 (SQL injection, 2× signed/unsigned OOB) | [sqlite_f02d100e08.md](reports/sqlite_f02d100e08.md) |
| Django  | `7dc826b975` | 52 (2 HIGH)  | 2 (pickle RCE in DB cache, MD5 hasher)  | [django_7dc826b975.md](reports/django_7dc826b975.md) |

## Prowl vs. SAST

| Prowl | SAST (semgrep, CodeQL) |
|-------|------------------------|
| Reasons about *intent*, then proves exploitability | Matches syntactic patterns |
| Full PoCs — HTTP request, ASAN crash, race demo, brute-force | Source line flags |
| LLM reasoning; costs tokens, takes minutes | Deterministic, fast, free |
| Research workbench | Good for CI |

Run both. `semgrep --config auto .` catches known patterns at merge time; `prowl scan .` finds the three-step API call sequence that lets an unauthenticated user approve their own refund, then generates the HTTP request sequence that demonstrates it.

| Domain | What Prowl produces |
|--------|---------------------|
| Web app vulns | HTTP request sequence proving unauthorized access / invalid state transition |
| Injection | Crafted input extracting data through the exact sink |
| Memory safety (C/C++/Rust unsafe) | Crafted input triggering an ASAN report |
| Concurrency | TOCTOU — concurrent requests proving the race window |
| Multi-finding chains | Chain identification + end-to-end PoC (SSRF + no internal auth → internal network access) |

## Headline findings

Every finding below was confirmed with an executable PoC inside the Prowl Docker sandbox — ASAN crash for memory bugs, shell marker for injection, brute-force for crypto. No version is specifically claimed as unpatched; see each report for the exact commit scanned.

### ffmpeg — 5 validated memory-corruption PoCs

- **Opus parser integer underflow → heap OOB.** `libavcodec/opus/parse.c:84` `ff_opus_parse_packet` — a crafted 5-byte Opus packet wraps `frame_bytes` negative; ASAN reports a 4,294,967,294-byte read.
- **HLS IV stack overflow via malicious m3u8.** `libavformat/hls.c:785` `parse_playlist` — `ff_hex_to_data` writes past the 16-byte `iv[16]` stack buffer when the playlist supplies a long IV.
- **TDSC integer overflow → heap overflow.** `libavcodec/tdsc.c:523` `tdsc_decode_frame` — `width * height * 4` overflows int32, allocates a tiny buffer, then zlib-decompresses into it. UBSAN + ASAN confirm.
- **ATRAC9 band extension stack OOB.** `libavcodec/atrac9dec.c:545` `apply_band_extension` — `sf[6]` is indexed up to 8 when `q_unit_cnt == 13`.
- **WMA Voice pulse array OOB write.** `libavcodec/wmavoice.c:1318` `synth_block_fcb_acb` — `pulses[80]` is indexed up to 159; the guarding `av_assert0` compiles out in release builds. ASAN reports a write 300 bytes past the buffer end.

### curl — 4 validated findings

- **NTLMv2 integer-wrap → heap overflow (malicious server).** `lib/curl_ntlm_core.c:540` `Curl_ntlm_core_mk_ntlmv2_resp` — an attacker-controlled `target_info_len` near `UINT_MAX` wraps the allocation size to a single byte; subsequent writes at offsets 8/16/32/44 land in adjacent heap chunks.
- **SSH host-key verification bypass (MITM).** `lib/vssh/libssh.c:121` `myssh_is_known` — with no `CURLOPT_SSH_KNOWNHOSTS`, no MD5 fingerprint, and no callback, the function returns `SSH_OK` unconditionally on every server key.
- **`curl_msprintf` unbounded writes.** `lib/mprintf.c:938` and `lib/mprintf.c:699` — two paths produce ASAN-confirmed overflows when attacker-influenced data reaches fixed-size buffers.

### OpenSSL (4.1.0-dev master) — 2 validated findings

- **RSA OAEP negative-`plen` OOB read.** `crypto/rsa/rsa_oaep.c:168` `RSA_padding_check_PKCS1_OAEP_mgf1` — an integer truncation in the caller lets `plen` go negative; the PoC produces a SEGV at `rsa_oaep.c:268` under ASAN.
- **Bleichenbacher / Marvin-style padding oracle via `RSA_FLAG_EXT_PKEY`.** `crypto/rsa/rsa_ossl.c:519` `rsa_ossl_private_decrypt` — the HSM-key path lacks the implicit-rejection data needed for constant-time failure, leaving both an error and a timing oracle.

### SQLite — 3 validated findings

- **SQL injection via RBU vacuum.** `ext/rbu/sqlite3rbu.c:3694` `sqlite3rbu_step` — `rbuCreateTargetSchema` reads SQL strings from an attacker-supplied RBU database's `sqlite_schema` and passes them straight to `sqlite3_exec` on the target DB.
- **RBU delta-apply signed/unsigned bounds bypass.** `ext/rbu/sqlite3rbu.c:590` `rbuDeltaApply` — casting unsigned `cnt` to `int` flips values ≥ 2³¹ negative, bypassing the `(int)cnt > lenDelta` guard; the subsequent `memcpy` reads/writes gigabytes out of bounds.
- **Fossil-delta signed/unsigned promotion.** `ext/misc/fossildelta.c:539` `delta_apply` — the same bug class in the standalone fossil-delta extension.

### Django — 2 validated PoCs

- **Pickle RCE in `DatabaseCache.get_many`.** `django/core/cache/backends/db.py:96` — any attacker with write access to the cache table (e.g. via another SQLi, leaked creds, or a shared DB) achieves RCE through `pickle.loads`. Known-by-design but Prowl flagged and exploited it end-to-end.
- **`MD5PasswordHasher` still shipped.** `django/contrib/auth/hashers.py` — brute-force PoC against the hasher runs in the sandbox; only exploitable on deliberately misconfigured deployments, but demonstrates accurate rubric-matching on a legacy code path.

### Disclosure

Reports are published here for research reproducibility. The memory-corruption findings in ffmpeg, curl, and OpenSSL have also been submitted to the respective upstream security teams; follow the linked reports for status and CVE assignments as they become available.

## How it works

```
Target codebase
    │
    ▼
RECONNAISSANCE (deterministic, no LLM)
    Tree-sitter parsing → function extraction → risk signal detection
    → vulnerability scoring → call graph → taint tracking → target ranking
    │
    ▼  (ranked target list)
LAYER 1: HYPOTHESIS (LLM)
    Context builder scopes each target function (~4K tokens)
    LLM hypothesizes vulnerabilities against detection rubrics
    Confidence gating: promote (≥0.7) / batch (0.4–0.7) / suppress (<0.4)
    │
    ▼  (confidence-gated hypotheses)
LAYER 2: TRIAGE + CHAIN ANALYSIS (LLM)
    Individual + batch triage: exploitable / mitigated / false_positive / uncertain
    Deterministic chain grouping + LLM chain evaluation
    Severity gating for Layer 3
    │
    ▼  (exploitable + uncertain findings)
LAYER 3: EXPLOIT VALIDATION (Claw Code + Docker sandbox)
    Claw Code agent autonomously writes/compiles/runs PoCs inside sandbox
    Per-vuln-class validation (HTTP requests, ASAN crashes, race conditions, …)
    Optional patch generation with compile + PoC + test validation
    │
    ▼
VULNERABILITY REPORT (text / JSON / SARIF / AI / Markdown)
```

**Structured output enforcement** at every LLM hop: Pydantic schemas in the prompt, `model_validate_json` on the response, one retry with error context, skip the target on second failure. **Dependency injection** for the LLM client and sandbox manager, so the whole pipeline runs under `MockLLMClient` + `MockSandboxManager` in tests (348 tests, ~1 s). **Async with bounded parallelism** via `anyio.CapacityLimiter` — 8 concurrent hypotheses, 4 triage, 2 validations.

## Requirements

- Python 3.11+
- Docker (for Layer 3 PoC validation in sandboxed containers)
- An API key for at least one LLM provider (OpenAI, Anthropic, Google, or a local Ollama instance)
- [Claw Code](https://github.com/ultraworkers/claw-code) (auto-installed in Docker sandbox for Layer 3 PoC validation)

## Installation

From PyPI (published as `prowl-sec`; the CLI command and import name stay `prowl`):

```bash
pip install "prowl-sec[anthropic]"   # Anthropic (default)
pip install "prowl-sec[openai]"      # OpenAI
pip install "prowl-sec[google]"      # Google
pip install "prowl-sec[ollama]"      # Ollama (local models)
pip install "prowl-sec[all-llm]"     # All providers
```

From source (editable, for development):

```bash
cd prowl
pip install -e ".[dev,anthropic]"    # Anthropic (default)
pip install -e ".[dev,openai]"       # OpenAI
pip install -e ".[dev,google]"       # Google
pip install -e ".[dev,ollama]"       # Ollama (local models)
pip install -e ".[dev,all-llm]"      # All providers
```

If you cannot do an editable install (e.g., missing setuptools), set `PYTHONPATH` directly:

```bash
export PYTHONPATH=/path/to/prowl/src
```

Verify the install:

```bash
python -m prowl --help
```

## LLM Configuration

Set your API key as an environment variable:

```bash
export ANTHROPIC_API_KEY=your-key    # for Anthropic (default)
export OPENAI_API_KEY=your-key       # for OpenAI
export GOOGLE_API_KEY=your-key       # for Google
```

Configure the provider and model in `prowl.yml`:

```yaml
llm:
  provider: anthropic                  # openai | anthropic | google | ollama
  model: claude-opus-4-6
  temperature: 0.0

  # Per-layer model overrides (optional)
  hypothesis:
    model: claude-haiku-4-5-20251001   # fast/cheap for high-volume Layer 1
  triage:
    model: claude-opus-4-6             # strong reasoning for Layer 2
  validation:
    model: claude-opus-4-6             # code generation for Layer 3
```

For local models via Ollama:

```yaml
llm:
  provider: ollama
  model: llama3
  base_url: http://localhost:11434
```

## Usage

### CLI

```bash
# Full scan on a project
prowl scan /path/to/project

# Scan with verbose logging
prowl -v scan /path/to/project

# Specific vulnerability categories only
prowl scan --categories memory,auth,injection /path/to/project

# Output formats: text (default), json, sarif, ai, markdown
prowl scan --format json /path/to/project
prowl scan --format sarif /path/to/project > results.sarif
prowl scan --format ai /path/to/project
prowl scan --format markdown /path/to/project

# Write report to a file
prowl scan --format markdown -o report.md /path/to/project
prowl scan --format json -o results.json /path/to/project

# Generate patches for confirmed findings
prowl scan --fix /path/to/project

# Resume an interrupted scan
prowl scan --resume /path/to/project

# Force full rescan (ignore cache)
prowl scan --no-cache /path/to/project

# Override PoC iteration budget
prowl scan --iterations 8 /path/to/project
```

### Managing findings

```bash
# Check scan status
prowl status

# List findings (from last scan)
prowl findings
prowl findings --severity critical,high
prowl findings --category auth,injection

# Suppress a false positive
prowl suppress prowl-sqli-handler.py-84 --reason "input validated in middleware" --scope function

# Suppression scopes:
#   finding   - this exact finding
#   function  - all findings for this function (survives line changes)
#   rule      - all findings matching this rule in this file
#   project   - all findings matching this rule project-wide

# Report a vulnerability Prowl missed
prowl missed src/handlers/admin.py:47 --category auth --description "missing admin check on delete endpoint"

# Clean up persisted scan state
prowl clean-state
```

## PoC validation via Claw Code

Layer 3 validation uses [Claw Code](https://github.com/ultraworkers/claw-code) as an autonomous agent inside the Docker sandbox. Instead of generating PoC code in a single LLM call, Claw autonomously writes, compiles, debugs, and runs PoCs using its own tool loop (bash, file read/write). It compiles against the actual target source and iterates on build errors without round-tripping through Prowl.

```yaml
validation:
  claw_timeout_default: 720    # seconds per finding
  claw_timeout_memory: 1080    # higher for memory bugs
  claw_max_turns: 30           # Claw agent turns per finding
  claw_api_key_env: null       # API key env var forwarded to container (auto-detected)
```

The Claw container needs network access for LLM API calls. See the [spec](prowl.md) for the full security model.

## Configuration

Create `prowl.yml` in your project root. All fields are optional.

<details>
<summary><b>Full defaults (click to expand)</b></summary>

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
  auto_exclude_override: []          # paths to force-include despite auto-exclude

scoring:
  hypothesis_confidence_threshold: 0.7
  batch_confidence_threshold: 0.4
  max_promoted_findings: 100

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
  claw_timeout_default: 720          # wall-clock seconds per finding
  claw_timeout_memory: 1080          # higher budget for memory bugs
  claw_max_turns: 30                 # Claw agent tool-use turns
  claw_api_key_env: null             # API key env var forwarded to container (auto-detected)

sandbox:
  runtime: docker
  timeout_default: 180               # seconds
  timeout_race_condition: 720
  timeout_max: 1800
  timeout_startup: 180                # container startup budget
  mem_limit: "512m"
  cpu_quota: 200000                  # 2 CPU cores
  pids_limit: 256
  network: none                      # no network egress
  tier3_services: [postgres, mysql, redis]

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
  format: "text"                      # text, json, sarif, ai, markdown
  include_poc: true
  include_reasoning: false

resume:
  enabled: true
  state_dir: ".prowl/scan-state"

llm:
  provider: "anthropic"              # openai | anthropic | google | ollama
  model: "claude-opus-4-6"
  api_key_env: null                  # auto-detected per provider
  base_url: null                     # for ollama/vLLM
  temperature: 0.0
  hypothesis:                        # per-layer overrides (all optional)
    provider: null
    model: null
    temperature: null
    max_tokens: null
  triage:
    provider: null
    model: null
    temperature: null
    max_tokens: null
  validation:
    provider: null
    model: null
    temperature: null
    max_tokens: null
```

</details>

### Custom rubrics

Add custom detection rules by placing YAML files in `.prowl/rubrics/`:

```yaml
# .prowl/rubrics/custom-ssrf.yml
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
prowl scan --format markdown -o report.md /path/to/project
```

## Project state

Prowl stores runtime state in `.prowl/` in the project root:

| Path | Purpose | VCS |
|------|---------|-----|
| `.prowl/suppressions.json` | Suppressed findings | Commit (shared across team) |
| `.prowl/missed.json` | Reported false negatives | Commit (shared across team) |
| `.prowl/cache/` | LLM result cache | Gitignore |
| `.prowl/scan-state/` | In-progress scan state for resume | Gitignore |
| `.prowl/calibration/` | Confidence calibration data | Gitignore |

## Vulnerability categories

| Category | Weight | What Prowl looks for |
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

Prowl uses tree-sitter for parsing and supports:

Python, JavaScript, TypeScript, TSX, Java, Go, Rust, C, C++, Ruby, PHP

Language is auto-detected from file extensions. Override with `scan.languages` in config.

## Development

### Running tests

```bash
# All tests (348 tests, ~1 second)
pytest tests/ -v --ignore=tests/fixtures

# Specific module
pytest tests/test_recon/ -v

# Single test class
pytest tests/test_recon/test_signals.py::TestSqlInjectionSignals -v

# With coverage
coverage run -m pytest tests/ && coverage report
```

### Linting

```bash
ruff check src/prowl/
ruff check src/prowl/ --fix    # auto-fix
```

### Project structure

```
src/prowl/
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
    config.py        # prowl.yml loading

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
    test_sandbox/    # Docker sandbox manager, image build, instrumentation
    test_validation/ # Claw backend, result checking, patch generation
    test_integration/
```

## Limitations

- **No kernel-mode validation.** The Docker sandbox runs userspace code. Kernel bugs get Layer 1-2 analysis without PoC confirmation.
- **No cross-service chains.** Analysis operates within a single repository.
- **No cross-language taint tracking.** In multi-language projects (Python calling C via FFI), each language is analyzed independently.
- **Call graph is approximate.** Dynamic dispatch, callbacks, and metaprogramming create gaps. The LLM compensates using context, but precision varies by language.
- **Not a CI gate.** Prowl is a research tool, not a linter. CI pipelines should use deterministic tools.

## Spec

The full specification is in [`prowl.md`](prowl.md).
