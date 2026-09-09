# Smart Contract Auditor

Static analysis and risk scoring for Solidity contracts. Feed it `.sol` source
(or a whole directory) and it compiles the code, walks the real compiler AST,
runs 33 checks, and returns findings with file/line/column plus a 1–100 score.

**Status:** the engine, CLI, REST API, React UI and test suite are implemented
and verified. See [What is verified](#what-is-verified) for exactly what was
run, and [What is not verified](#what-is-not-verified) for the parts that were
written but could not be executed here.

---

## Quick start (no Docker)

```bash
# 1. Python environment
python3 -m venv .venv && . .venv/bin/activate
pip install -r backend/requirements.txt
pip install -e ./backend            # installs the `auditor` command

# 2. Solidity compiler (WASM, no native solc needed)
npm install solc@0.8.24

# 3. Audit something
auditor audit fixtures/vulnerable/ReentrantVault.sol
```

Real output:

```
solc: 0.8.24+commit.e11b9ed9.Emscripten.clang   compiled: yes   1061 ms
score: 27/100 (grade F)   findings: 7  Informational=4  Medium=1  High=2

findings:
  HIGH  reentrancy-eth                 ReentrantVault.sol:21  [ReentrantVault.withdraw]
        Reentrancy: ether sent before state update
  HIGH  unchecked-lowlevel-call        ReentrantVault.sol:26  [ReentrantVault.sync]
        Unchecked low-level call
  MED   reentrancy-no-eth              ReentrantVault.sol:27  [ReentrantVault.sync]
        Reentrancy: state written after external call
```

`auditor doctor` reports what the current environment can actually do, so you
are never guessing why a check did not run.

---

## The compiler

The engine drives **real `solc`** through its standard-JSON interface and
analyses the resulting AST — it does not regex your source. Two ways to get a
compiler:

- `npm install solc` in the repo root (WASM, self-contained, what CI uses), or
- a native `solc` on `PATH`, or set `AUDITOR_SOLC=/path/to/solc`.

Discovery order: `AUDITOR_SOLC` → `solc` on `PATH` → `node_modules/.bin/solcjs`.

Four compiler behaviours are handled explicitly, because each one silently
breaks analysis if you get it wrong (all pinned by `tests/test_solc.py`):

| Behaviour | Handling |
|---|---|
| Top-level `{"urls": [...]}` sources are rejected (`File import callback not supported`) | Every source is passed inline as `content` |
| `import "./X.sol"` still needs disk access | Sources are also written to a temp dir passed as `--base-path` |
| The AST is a **file-level** output | Requested as `{"*": {"": ["ast"]}}`, not under the per-contract `"*"` |
| `solcjs` prints a `>>> Cannot retry compilation with SMT…` banner | Output is sliced from its first `{` |

Two further traps found while building this:

- The third field of a node's `src` string (`"start:length:fileIndex"`) is a
  **file index, not the SourceUnit node id** — they differ (observed
  `id=43` with `src="32:308:0"`). Mapping them by id silently makes every line
  number wrong.
- Node writes to a **pipe** asynchronously and can exit before draining,
  truncating solc's JSON at a 64 KiB boundary — *intermittently*. Compiler
  stdout is therefore redirected to a regular file, where writes are
  synchronous.

---

## Checks

33 built-in checks, mapped to SWC/CWE where one applies. `auditor detectors`
lists them all with their metadata.

| Area | Checks |
|---|---|
| Reentrancy | `reentrancy-eth`, `reentrancy-no-eth` |
| Access control | `suicidal`, `unprotected-ether-withdrawal`, `unprotected-initializer`, `missing-access-control-setter`, `tx-origin-auth` |
| External calls | `unchecked-send`, `unchecked-lowlevel-call`, `calls-inside-loop`, `msg-value-in-loop`, `delegatecall-to-untrusted-input` |
| Arithmetic | `integer-overflow`, `unchecked-arithmetic`, `divide-before-multiply`, `unvalidated-divisor` |
| Hygiene | `floating-pragma`, `old-solc-version`, `timestamp-dependence`, `weak-randomness`, `inline-assembly`, `hardcoded-address`, `missing-zero-address-check`, `erc20-approve-race`, `deprecated-usage`, `long-function`, `compiler-diagnostic` |
| Source-level (no AST needed) | `missing-license`, `todo-comment`, `legacy-call-syntax`, `hardcoded-secret`, `uncompilable-source` |
| Gas | `external-function` |

Detectors are deliberately conservative about **false positives**, because an
auditor nobody trusts gets ignored:

- A `nonReentrant` mutex suppresses reentrancy findings.
- `owner = msg.sender` is an *assignment*, not an access-control guard — only
  `require`/`assert` or a reverting `if` counts.
- `address(0)` parses as a `typeConversion` over an `ElementaryTypeNameExpression`,
  not an `Identifier`; the zero-address check reads `typeName.name`.
- A `payable` function forwarding the caller's own `msg.value` is not draining
  the contract.
- Writes keyed by `msg.sender` (deposit/withdraw ledgers) are self-service, not
  privileged setters.
- Standard ERC-20 `approve` is not flagged when `increaseAllowance`/
  `decreaseAllowance` exist.

### Known limitations

Stated plainly rather than buried:

- Reentrancy analysis is **intra-procedural**. No call graph is built, so a
  call into another function that itself reaches out is not followed. That is
  what Mythril (below) is for.
- Ordering is derived from byte offsets in `src`, not a control-flow graph.
- No taint tracking: "caller-controlled" means a function parameter or a state
  variable, not a proven dataflow.
- Only Solidity **source** is analysed. Bytecode-only targets are out of scope.

---

## Risk score

100 minus a weighted penalty per finding, where repeats of the same severity
decay geometrically (0.85) so splitting one issue into ten cannot tank a score,
and adding a finding can never raise it.

| Score | Grade |
|---|---|
| 90–100 | A |
| 75–89 | B |
| 60–74 | C |
| 40–59 | D |
| <40 | F |

---

## REST API

```bash
auditor serve --host 0.0.0.0 --port 8000
```

```bash
# Multipart upload (the README's original contract)
curl -X POST -F "files=@Contract.sol" http://localhost:8000/audit

# Or JSON
curl -X POST http://localhost:8000/audit \
     -H 'Content-Type: application/json' \
     -d '{"source": "pragma solidity ^0.8.0; contract C {}"}'

curl http://localhost:8000/audits
curl http://localhost:8000/audits/<id>/report.md      # also .json / .html
curl http://localhost:8000/detectors
curl http://localhost:8000/health
curl http://localhost:8000/docs                       # OpenAPI UI
```

Both input styles are dispatched off the raw request content type — declaring a
`File` parameter in the handler signature makes FastAPI treat *every* request
as multipart and silently drop JSON bodies.

Security: HMAC-SHA256 tokens and API keys (`AUDITOR_API_KEYS`), plus per-client
token-bucket rate limiting. Auth is disabled unless keys are configured.

If `frontend/dist` exists, the API also serves the built UI, so one process
serves everything.

---

## Frontend

```bash
cd frontend
npm install
npm run dev      # http://localhost:5173, proxies /audit, /audits, /health to :8000
npm run build    # emits frontend/dist, which the backend then serves
```

Paste a contract, upload a `.sol`, or pull verified source from Etherscan.
Note: the Etherscan fetch runs in the browser and their API does not reliably
send CORS headers, so it may need a backend proxy.

---

## Tests

```bash
.venv/bin/python -m pytest
```

The suite asserts specific checks fire on specific lines of the fixtures, and —
just as importantly — that the two clean fixtures in `fixtures/safe/` produce
**zero** findings. `fixtures/vulnerable/` is deliberately broken; `fixtures/safe/`
is the false-positive tripwire.

---

## Optional external analysers

`backend/app/services/slither.py` and `mythril.py` merge those tools' findings
into the report when they are installed, and report their absence honestly when
they are not (`ToolRun.available = false` with an explanatory note). Neither is
required, and neither is in `requirements.txt` — both need a **native** solc and
pull heavy dependency trees.

---

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `AUDITOR_SOLC` | auto | Path to a solc-compatible binary |
| `AUDITOR_SOLC_TIMEOUT` | 120 | Per-compile timeout (s) |
| `AUDITOR_API_KEYS` | *(empty = auth off)* | Comma-separated keys |
| `AUDITOR_TOKEN_SECRET` | `change-me-in-production` | HMAC signing secret |
| `AUDITOR_RATE_CAPACITY` / `AUDITOR_RATE_REFILL` | 60 / 2.0 | Token bucket |
| `AUDITOR_DATABASE_URL` | `sqlite:///.data/audits.db` | Audit storage |
| `AUDITOR_REPORT_DIR` | `.data/reports` | Report output |
| `AUDITOR_ENABLE_SLITHER` / `AUDITOR_ENABLE_MYTHRIL` | true | Run them if present |
| `AUDITOR_BROKER_URL` | *(empty)* | Enables the Celery task runner |

`worker.py` runs audits on an in-process thread pool by default and switches to
Celery automatically when a broker is configured, so the service is deployable
with zero infrastructure.

---

## What is verified

Run in this environment (Debian 12, Python 3.11.2, Node v22.22.3):

- **145 tests pass** (`pytest`), covering the compiler adapter, every detector
  category, scoring, reports, the REST API through its real lifespan, auth,
  rate limiting, the worker and the CLI.
- `auditor audit`, `auditor detectors` and `auditor doctor` executed against the
  fixtures (output shown above).
- `npm run build` succeeds for the frontend.
- Both `fixtures/safe/` contracts score 100/A with zero findings.

## What is not verified

- **`docker-compose.yml` and both Dockerfiles were never built or run** — Docker
  is not installed here. They are provided for parity with the original design
  and should be treated as a starting point. The tested path is the venv one.
- **`foundry.toml` was never used** — `forge` could not be installed because
  `binaries.soliditylang.org` is unreachable from this sandbox (TLS EOF). The
  fixtures are still compiled and analysed, via the WASM solc.
- Slither and Mythril integrations are **not installed here**, so their output
  parsing is untested against real tool output. The "not installed" path is
  tested.
- The Etherscan source fetch is **not exercised by tests**.

---

## Project layout

```
backend/
  app/
    core/            config, security (tokens, rate limiting)
    models/audit.py  Finding, Severity, AuditResult — shared by every layer
    routers/audits.py REST endpoints
    services/
      solc.py            compiler adapter
      engine.py          orchestration
      risk.py            scoring
      report_generator.py JSON / Markdown / HTML
      store.py           persistence
      slither.py, mythril.py  optional integrations
      detectors/         33 checks + AST helpers
    templates/       HTML report template
    cli.py           `auditor` command
    worker.py        thread-pool / Celery task runner
frontend/            React + Vite UI
fixtures/            vulnerable/ and safe/ test contracts
tests/               pytest suite
```

---

## License

MIT © Pavel Nersisan

**This tool does not make your contract safe.** Static analysis cannot prove the
absence of bugs. Use it to prioritise review, and get real audits for anything
holding value.
