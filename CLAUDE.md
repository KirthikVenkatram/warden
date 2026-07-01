# CLAUDE.md — Warden

Security triage agent for the Slack Agent Builder Challenge. A **Rego policy is the
autonomy boundary for an AI agent**: per vulnerability finding, policy decides `auto`
(agent fixes it), `ask` (human approves in Slack), or `block` (hard stop). Deterministic
gate, agentic execution within it.

## Golden rules

- **One concern per session.** Do the current chunk from `BUILD_PLAN.md` and nothing else.
  Don't refactor unrelated files, don't scope-creep, don't build ahead.
- **Tests pass before done.** `pytest` green and, for policy work, `opa test policy/ -v` green.
- **Never break the data contract** below. It is shared by `core`, `mcp_server`, and
  `slack_app`. Change it only on explicit instruction, and update all three + tests together.
- **Determinism boundary:** the LLM NEVER decides `auto`/`ask`/`block`. Policy decides;
  the LLM reads, explains, and executes only what policy already permitted.
- **Secrets come from env, never code.** No tokens, keys, or repo names hardcoded.
- **Commit format:** `type(scope): summary` — types `feat|fix|test|chore|docs|refactor`,
  scope = component (`policy`, `core`, `mcp`, `slack`, `infra`). One chunk = one commit.

## Architecture — where things live

```
core/        Headless brain. NO slack, NO mcp, NO llm imports here.
  models.py    Finding, Decision, ScanSummary, PRResult
  enrich.py    EPSS client + CISA KEV catalog (cached); defaults on failure
  policy.py    opa eval subprocess wrapper -> list[Decision]
  scanner.py   Trivy JSON -> Finding; fixture loader
  store.py     SQLite: dedup (cve+package+repo), snooze state
  pipeline.py  ingest -> enrich -> gate -> decisions
policy/      gate.rego + gate_test.rego (the autonomy ladder)
mcp_server/  server.py — FastMCP, thin adapter over core/. 4 tools only.
slack_app/   app.py (Bolt Socket Mode, MCP client), blockkit.py, agent.py (Anthropic loop)
fixtures/    kev_blocking / high_epss / quiet_low + a vulnerable seed repo
tests/       mirror core/ and slack_app/
```

Rule of thumb: **all logic in `core/`; `mcp_server` and `slack_app` are thin.** If you're
writing business logic inside a Slack handler or an MCP tool, move it to `core/`.

## Data contract (canonical)

`Finding` (post-enrichment): `cve, package, installed_version, fixed_version, severity`
(`critical|high|medium|low`), `cvss` (float), `epss` (0..1), `kev` (bool), `scanner`, `repo`.
Enrichment MUST always set `kev` (default `false`) and `epss` (default `0.0`).

`Decision`: `cve, package, action` (`auto|ask|block|ignore`), `reasons` (list[str]),
`auto_fixable` (bool).

Ladder: `block` if any block-reason (on KEV, OR critical severity, OR `epss >= threshold`
at high/critical). Else if `fixed_version` present: `auto` when low-risk AND `tests_green`,
else `ask`. No fix → `ignore`.

## MCP tools (exact surface — do not add more)

```
scan_repo(repo) -> ScanSummary            # parse + enrich + gate + store
get_findings(repo, action=None) -> [Decision]
explain_finding(cve, repo) -> str
draft_fix_pr(cve, repo) -> PRResult       # branch, bump to fixed_version, open PR
```

## Commands

```bash
uv sync                        # or: pip install -e .
pytest                         # unit tests
opa test policy/ -v            # policy tests
opa eval -d policy/gate.rego -i fixtures/kev_blocking.json 'data.appsec.gate' --format pretty
python -m mcp_server.server    # run MCP server (stdio)
python -m slack_app.app        # run Bolt app (Socket Mode)
fly deploy -c fly.mcp.toml     # hosting (chunk 11)
```

## Tech / versions

Python 3.12 · slack-bolt (Socket Mode) · `mcp` (FastMCP) · anthropic · httpx · pydantic ·
SQLite (stdlib) · OPA binary (vendored, not pip) · pytest.

## Do NOT

- Do not build reachability analysis, multi-ecosystem patching, a GitHub App, or an OPA
  server. All explicitly de-scoped.
- Do not let a button override a `block` decision. That defeats the entire thesis.
- Do not put `core` logic in handlers/tools, or import slack/mcp/anthropic into `core/`.
- Do not add MCP tools beyond the four above without being asked.
- Do not commit fixtures containing real tokens or private repo data.

## Definition of done (every chunk)

Acceptance check from `BUILD_PLAN.md` passes · tests green · one clean commit in the
`type(scope): summary` format · no unrelated files touched.
