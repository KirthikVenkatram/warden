# Warden — Build Plan

> Slack Agent Builder Challenge. Deadline: **Jul 13, 2026, 5:00pm PDT**.
> Working name: **Warden** (rename freely — one grep).

## 0. Thesis (the sentence the whole build serves)

**A Rego policy is the autonomy boundary for an AI agent.** For every vulnerability
finding, policy-as-code decides what the agent may do on its own: `auto` (open + merge
the fix), `ask` (post to Slack for a human), or `block` (hard stop). The exploitability
brain (EPSS + CISA KEV + severity) feeds the policy; the policy bounds the agent. The
gate is deterministic; the LLM only narrates and acts *within* what policy allows.

This is the pitch for **Best Technological Implementation** and it is what makes this an
*agent* with a governance model, not a notification bot.

## 1. Tech stack

| Layer | Choice | Why |
|---|---|---|
| Language | Python 3.12 | Matches Bolt, your stack, the `opa eval` shell-out pattern |
| Slack | `slack-bolt` in **Socket Mode** | No public URL, no ngrok — runs from laptop on camera |
| Agent tooling | **Custom MCP server** (`mcp` / FastMCP) | The required "MCP server integration" — and the hero artifact |
| LLM | Anthropic Messages API (tool use) | Drives the agentic loop; binds to the MCP tools |
| Policy | OPA (`gate.rego`), called via `opa eval` subprocess | Deterministic gate; same pattern as CODEX |
| Enrichment | EPSS (FIRST.org API) + CISA KEV catalog JSON, cached | Plain HTTP — genuine, not forced through MCP |
| Scanner input | Trivy JSON (real) + seeded fixtures (demo) | Real proof, reliable demo |
| Storage | SQLite | Dedup + snooze state, low-effort, looks professional |
| Fix PRs | Fine-grained GitHub PAT + REST | Faster than a full GitHub App for a 12-day build |
| Hosting | **Fly.io**, OPA binary vendored in image | Minutes to deploy; Socket Mode = no inbound |

De-scoped on purpose (say these are "roadmap", do not build): reachability analysis,
multi-ecosystem PR patching (support **one** ecosystem well), a full GitHub App, an OPA
policy server (subprocess is fine).

## 2. Components & responsibilities

- `core/` — the headless brain. Models, enrichment, OPA wrapper, store, scanner parsing,
  and the pipeline that turns raw findings into policy decisions. **No Slack, no MCP, no
  LLM in here.** Must be fully testable on its own.
- `policy/` — `gate.rego` + `gate_test.rego`. The autonomy ladder lives here.
- `mcp_server/` — a real MCP server exposing `core/` as tools. Independently demoable
  (point Claude Desktop or the MCP inspector at it). This is the single source of truth
  for "security posture + actions."
- `slack_app/` — thin Bolt Socket Mode client. Triggers the pipeline via MCP, renders
  Block Kit, handles buttons, and runs the Anthropic tool-use loop for thread Q&A.

The Slack app is an **MCP client**. Everything security-related goes through the MCP
server so MCP is load-bearing, not decorative.

## 3. End-to-end flow

**Deterministic pipeline (event-driven, no LLM):**
1. Trigger: `/warden scan <repo>` slash command (or a scan webhook).
2. Slack app calls MCP `scan_repo(repo)` → server parses Trivy JSON / loads fixture.
3. Enrich: EPSS score + KEV membership attached to every finding (defaults if a feed is down).
4. `opa eval` against `gate.rego` → each finding tagged `auto` / `ask` / `block`.
5. Store findings (dedup by `cve+package+repo`), respect existing snoozes.
6. Slack app calls MCP `get_findings(repo)` → renders Block Kit digest, colored by action.

**Agentic layer (LLM + MCP, within policy):**
7. `block` findings render as hard stops — no button can override (this is the point).
8. `ask` findings render with **Approve / Snooze / Explain** buttons.
9. Approve → MCP `draft_fix_pr(cve, repo)` opens a PR; message updates with the PR link.
10. Thread question ("why is this blocking?") → Anthropic tool-use loop calls MCP
    `explain_finding(cve, repo)` and replies in-thread with repo context.
11. `auto` findings: agent opens (and, if `tests_green`, merges) the PR silently, then
    drops a one-line audit note in the channel.
12. Merged fix → next scan clears it. Loop closes.

**Determinism boundary (non-negotiable):** the LLM never decides `auto`/`ask`/`block`.
It reads the decision, explains it, and executes actions the policy already permitted.

## 4. Data contract (single source of truth — mirror in CLAUDE.md)

`Finding` (post-enrichment, into OPA):
```json
{
  "cve": "CVE-2024-3094",
  "package": "xz-utils",
  "installed_version": "5.6.0",
  "fixed_version": "5.6.2",
  "severity": "critical",
  "cvss": 10.0,
  "epss": 0.94,
  "kev": true,
  "scanner": "trivy",
  "repo": "ubixi/conductor"
}
```
Enrichment MUST always set `kev` (default `false`) and `epss` (default `0.0`) so a dead
feed never silently drops a finding.

`Decision` (out of OPA, per finding):
```json
{
  "cve": "CVE-2024-3094",
  "package": "xz-utils",
  "action": "block",            // auto | ask | block | ignore
  "reasons": ["on CISA KEV — known exploited in the wild"],
  "auto_fixable": true
}
```
Ladder: `block` if any block-reason (KEV, critical, or EPSS≥threshold at high/critical
severity). Else if a fix exists: `auto` when low-risk **and** `tests_green`, otherwise
`ask`. No fix → `ignore` (informational only).

## 5. MCP tool surface

```
scan_repo(repo: str) -> ScanSummary
    Parse scanner output (real or fixture), enrich, gate, store. Returns counts by action.

get_findings(repo: str, action: str | None = None) -> list[Decision]
    Return stored decisions, optionally filtered by action. Powers the Block Kit digest.

explain_finding(cve: str, repo: str) -> str
    Human-readable why: severity, EPSS, KEV status, the exact policy reason, remediation.

draft_fix_pr(cve: str, repo: str) -> PRResult
    Create branch, bump the dependency to fixed_version, open PR. Returns url + number.
```
Keep the surface this small. Each tool maps to a `core/` function — the MCP layer is a
thin adapter, all logic stays testable in `core/`.

## 6. Hosting

- **Local / demo:** Slack app spawns the MCP server over **stdio** (standard MCP local
  pattern). Socket Mode means Slack reaches you with no inbound URL. Dead reliable on camera.
- **Always-on (judges poke the sandbox):** two Fly apps — `warden-mcp` (HTTP/SSE) and
  `warden-slack` (Socket Mode client → MCP over Fly internal networking). OPA binary
  vendored in the image; no separate policy server.
- **Killer beat:** the same MCP server, pointed at Claude Desktop, calling the same tools.
  Proves "real MCP integration" beyond doubt.

Secrets (env, never in code): `SLACK_BOT_TOKEN`, `SLACK_APP_TOKEN`, `SLACK_SIGNING_SECRET`,
`ANTHROPIC_API_KEY`, `GITHUB_TOKEN`, `GITHUB_DEFAULT_REPO`.

## 7. Chunked build order

One concern per Claude Code run. `/clear` + commit between each. Do not start chunk N
until N−1's acceptance check passes.

| # | Chunk | Acceptance check | Day |
|---|---|---|---|
| 0 | Scaffold: `pyproject`, dirs, `CLAUDE.md`, `models.py`, empty fixtures | `pytest` runs (0 tests ok), package imports | 1 |
| 1 | Policy: `gate.rego` + `gate_test.rego` (auto/ask/block) + `policy.py` wrapper | `opa test policy/ -v` green; wrapper returns Decisions | 1–2 |
| 2 | Enrichment: `enrich.py` (EPSS client, KEV fetch+cache, membership) | Unit test w/ recorded responses; defaults on feed failure | 2–3 |
| 3 | Scanner + store: `scanner.py` (Trivy JSON→Finding), `store.py` (SQLite, dedup, snooze) | Fixture parses; re-ingest dedups; snooze persists | 3 |
| 4 | Pipeline glue: `core` ingest→enrich→gate→decisions, headless | End-to-end on 3 fixtures → correct actions, tested | 4 |
| 5 | MCP server: 4 tools over `core/` | MCP inspector / Claude Desktop calls all 4 | 4–5 |
| 6 | GitHub PR: `github_pr.py` wired into `draft_fix_pr` | PR opens against a throwaway repo | 5–6 |
| 7 | Block Kit: `blockkit.py` digest + detail builders | JSON validates in Block Kit Builder; unit test | 6–7 |
| 8 | Bolt skeleton: Socket Mode, slash cmd → MCP scan → digest | `/warden scan` posts a real digest | 7 |
| 9 | Button actions: Approve→`draft_fix_pr`, Snooze→store | Click opens PR; snooze hides finding | 8 |
| 10 | Agent Q&A: `agent.py` Anthropic tool-use loop ↔ MCP | Thread question triggers `explain_finding` reply | 8–9 |
| 11 | Hosting: Dockerfile(s), Fly deploy, secrets | Both apps up on Fly; sandbox reachable | 11 |
| 12 | Demo: seed fixtures, `demo.sh`, rehearse, record, submit | 3-min video; sandbox shared to judge emails; submitted early | 12–13 |

Day 10 and 13 are buffer. Submit early — PDT deadline is small hours in Chennai.

## 8. Demo script (~3 min — the autonomy ladder tells itself)

1. **Problem** (10s): scanners drown teams; some bugs are on fire, most are noise. Who
   decides what an agent fixes on its own?
2. **One policy file** (15s): show `gate.rego`. "This is the autonomy boundary."
3. **Scan** (30s): `/warden scan` → Block Kit digest, three findings, three colors.
4. **`block`** (30s): a KEV bug — merge refused on camera. Deterministic, no LLM guessing.
5. **`ask`** (40s): high-EPSS bug → Approve → PR appears in GitHub live.
6. **`auto`** (25s): quiet low-risk bug — agent already opened + merged it, audit note in channel.
7. **MCP proof** (20s): same server answering in Claude Desktop.
8. **Close** (10s): "Exploitability decides urgency. Policy decides autonomy. The agent
   acts inside the lines." Roadmap slide: reachability, more ecosystems, more verticals.

## 9. If you fall behind — cut in this order

1. Drop hosting; demo fully local via Socket Mode + stdio (still valid submission).
2. Drop `auto` auto-merge; keep `auto` = opens PR (human merges). Ladder intact.
3. Drop thread Q&A (chunk 10); keep buttons. Still an agent, less conversational.
4. Never cut: the policy gate, the MCP server, the Block Kit digest. That trio *is* the project.
