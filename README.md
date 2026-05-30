# AgentCheck

[![CI](https://github.com/Eshaank08/agent-check/actions/workflows/ci.yml/badge.svg)](https://github.com/Eshaank08/agent-check/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/@eshaank08/agentcheck)](https://www.npmjs.com/package/@eshaank08/agentcheck)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**The security auditor for AI agents.**

AgentCheck is an open-source CLI that scans your AI agent for security vulnerabilities, architectural risks, and cost inefficiencies — in under 60 seconds. No account required. Works offline.

```bash
npx @eshaank08/agentcheck audit
```

---

## What is AgentCheck?

When you build an AI agent — something that uses tools, makes decisions, and acts on the world — you introduce a new class of security risk that traditional code scanners don't understand.

An agent that can read emails and also delete files is a prompt injection waiting to happen. An agent with a `send_payment` tool and no human approval gate is a liability. A multi-agent system where sub-agents receive raw user input is an architectural flaw.

AgentCheck catches these before they reach production.

It runs two layers of analysis:

1. **Static analysis** — 19 rule-based checks based on the OWASP Agentic AI Top 10 (2026). Runs entirely offline, no API key needed.
2. **AI analysis** — Claude reasons about your agent's architecture and surfaces logical contradictions, workflow gaps, and the single most critical fix. Requires an Anthropic API key.

Both layers output a scored report with specific findings and actionable fixes.

---

## Quick Start

```bash
# Interactive mode — answer questions about your agent, no code needed
npx @eshaank08/agentcheck audit

# File scan mode — point it at your agent's source directory
npx @eshaank08/agentcheck audit --path ./my-agent

# Fully offline — static analysis only, no API key, no network
npx @eshaank08/agentcheck audit --path ./my-agent --no-ai

# Machine-readable output for CI pipelines
npx @eshaank08/agentcheck audit --path ./my-agent --json
```

---

## Two Modes

### Interactive Mode

No source code required. AgentCheck asks you a series of structured questions in the terminal and runs analysis based on your answers.

```bash
npx @eshaank08/agentcheck audit
```

You'll be asked about:
- Agent name and purpose
- Which model you're using and approximate daily call volume
- Tool names and their permissions (read / write / delete / execute)
- Whether you have sub-agents and how they're orchestrated
- Whether human approval gates exist for sensitive actions

Takes about 2 minutes. Useful when you want a quick sanity check or don't have the source code in front of you.

### File Scan Mode

Point AgentCheck at your agent's source directory. It recursively scans `.py`, `.ts`, `.js`, `.json`, `.yaml`, `.yml`, and `.env` files, extracts structural metadata, and runs the full analysis — without sending your source code anywhere.

```bash
npx @eshaank08/agentcheck audit --path ./my-agent
```

**What gets extracted from your code:**
- Tool function names and inferred permission levels
- Model identifiers (e.g. `claude-sonnet-4-6`, `gpt-4o`)
- Whether a system prompt is present (not its content)
- Sub-agent patterns and orchestration signals
- Error handling, rate limiting, timeout, and input validation signals
- Potential hardcoded credentials (flagged by file path and line number only — the value is never read)

**What never leaves your machine:**
- Source code
- System prompt content
- Tool implementation logic
- Customer or user data

---

## AI-Powered Analysis

For deeper analysis, set your Anthropic API key:

```bash
export ANTHROPIC_API_KEY=sk-ant-...
```

AgentCheck will automatically use the AI reasoning layer. Claude receives only the extracted metadata — tool names, permission flags, model name, and static findings — and returns:

- **Logical contradictions** — e.g. an agent described as "read-only" that has write tools
- **Sub-agent trust issues** — permission boundary violations in multi-agent setups
- **Workflow gaps** — what happens when a tool fails mid-execution
- **Permission analysis** — unjustified permission levels given the stated purpose
- **Model recommendations** — 3 alternatives with live pricing and monthly cost estimates
- **Most critical fix** — the single highest-priority issue to address immediately

Model pricing is fetched live from [OpenRouter's free public API](https://openrouter.ai/api/v1/models) (5-second timeout, falls back to static catalog if unavailable). No API key required for pricing.

---

## What AgentCheck Checks

### Static Rules (always run, no API key needed)

| Rule | Severity | What it catches |
|------|----------|-----------------|
| OAA-01 | CRITICAL | Prompt injection — external input tools combined with write/delete permissions |
| OAA-02 | HIGH | Over-permissioned tools — delete/execute/admin where read would suffice |
| OAA-03 | CRITICAL | Missing human approval on sensitive actions (email, payment, deploy, delete) |
| OAA-04 | CRITICAL | Hardcoded credentials — API keys, secrets, bearer tokens in source files |
| OAA-05 | MEDIUM | Tool scope creep — tools inconsistent with the agent's stated purpose |
| OAA-06 | MEDIUM | Missing error handling — no fallback strategy for tool failures |
| OAA-07 | HIGH | Unconstrained sub-agent permissions — raw user input passed to sub-agents |
| OAA-08 | MEDIUM | No output validation — agent outputs not checked before use |
| OAA-09 | HIGH | PII exposure — user/customer data tools with no output validation |
| OAA-10 | MEDIUM | Missing rate limiting on external API tools |
| OAA-11 | CRITICAL | Self-modifying agent — tools that can overwrite the system prompt |
| OAA-12 | HIGH | No audit logging on write/delete/execute operations |
| OAA-13 | MEDIUM | Missing input validation before data reaches tools |
| OAA-14 | HIGH | No tool timeout — external tools can hang indefinitely |
| OAA-15 | MEDIUM | Non-idempotent write operations — duplicate calls could corrupt data |
| OAA-16 | MEDIUM | Context window overflow risk from large tool surface |
| OAA-17 | LOW | No fallback model at high call volume |
| OAA-18 | HIGH | Missing session isolation — cross-tenant data access risk |
| OAA-19 | MEDIUM | Unconstrained memory retention — no TTL on agent memory or vector store |

Rules are based on the [OWASP Agentic AI Top 10 (2026)](https://owasp.org/www-project-top-10-for-large-language-model-applications/).

> **Note:** Static analysis uses heuristic pattern matching on tool names and code signals. It will catch real structural risks but may produce false positives — review each finding in the context of your agent's actual behaviour. The AI layer (`ANTHROPIC_API_KEY`) adds architectural reasoning that reduces noise significantly.

### Scoring

Each audit produces three scores:

- **Security Score (0–10)** — weighted by finding severity. CRITICAL findings are penalised 3×.
- **Performance Score (0–10)** — tracks reliability risk from HIGH findings (missing error handling, timeouts, etc.)
- **Cost Efficiency Score (0–10)** — provided by the AI layer based on model fit and call volume. Defaults to 5 in static-only mode.
- **Overall Score (0–100)** — weighted composite: security 50%, performance 30%, cost 20%.

---

## Sample Output

Real output from scanning a production multi-agent system (45 files, 11 sub-agents):

```
════════════════════════════════════════════════════════
                AgentCheck Audit Report
                     Agent: unnamed
            Scanned: 30/5/2026, 10:31:44 am
         Path: ./donna/backend
                       Files: 45
════════════════════════════════════════════════════════

STATIC ANALYSIS
────────────────────────────────────────────────────────
  ❌ CRITICAL  Prompt Injection Risk
             Agent reads external content (web/email/files) and has
             write/delete tools — high prompt injection risk.
             📍 Tools with external read + write/delete permissions

  ⚠️  MEDIUM    Context Window Overflow Risk
             Agent has 46 tools. At this scale, tool definitions alone
             can consume a significant portion of the context window.
             📍 46 tools registered

  ✅ PASSED   Over-permissioned Tools
  ✅ PASSED   Human Approval
  ✅ PASSED   Hardcoded Credentials
  ✅ PASSED   Tool Scope
  ✅ PASSED   Error Handling
  ✅ PASSED   Sub-agent Permissions
  ✅ PASSED   Output Validation
  ✅ PASSED   PII Exposure
  ✅ PASSED   Rate Limiting
  ✅ PASSED   Self-modification
  ✅ PASSED   Audit Logging
  ✅ PASSED   Input Validation
  ✅ PASSED   Tool Timeout
  ✅ PASSED   Idempotency
  ✅ PASSED   Fallback Model
  ✅ PASSED   Session Isolation
  ✅ PASSED   Memory Retention

SUMMARY
────────────────────────────────────────────────────────
  Security Score:     6.5/10  ⚠
  Performance Score:  9/10    ✓
  Cost Efficiency:    5/10    ⚠

  Overall Score:      70/100  ⚠
════════════════════════════════════════════════════════
```

---

## Flags

| Flag | Description |
|------|-------------|
| `--path <dir>` | Scan a specific source directory |
| `--interactive` | Force interactive mode — answer questions, no source code needed |
| `--no-ai` | Static analysis only — no API key, no network |
| `--json` | Output raw JSON — useful for CI pipelines and scripting |
| `--version` | Print version |
| `--help` | Show help |

---

## CI Integration

Use `--json` to pipe results into your pipeline:

```bash
npx @eshaank08/agentcheck audit --path ./agent --no-ai --json > audit-report.json
```

Or fail a build on any CRITICAL finding:

```bash
RESULT=$(npx @eshaank08/agentcheck audit --path ./agent --no-ai --json)
CRITICALS=$(echo "$RESULT" | jq '[.staticFindings[] | select(.severity == "CRITICAL" and .passed == false)] | length')
if [ "$CRITICALS" -gt 0 ]; then
  echo "Audit failed: $CRITICALS critical finding(s)"
  exit 1
fi
```

---

## Privacy

AgentCheck is designed to be privacy-safe by construction.

**Never sent anywhere:**
- Your source code
- System prompt content
- Tool implementation logic
- Customer or user data

**Sent to Anthropic only when `ANTHROPIC_API_KEY` is set and `--no-ai` is not passed:**
- Tool names and permission levels
- Agent description (from interactive input or package.json)
- Model name
- Boolean flags: error handling present, rate limiting present, etc.
- Static analysis findings (rule IDs and severity — not your code)

AgentCheck prints a privacy notice before running AI analysis. Use `--no-ai` to disable all external calls entirely, including model pricing.

---

## Requirements

- Node.js 18 or later
- No installation required — `npx` handles it

---

## Contributing

Issues and pull requests are welcome. The rules live in `src/rules/owasp.ts` and the checks in `src/layers/static.ts` — both are straightforward to extend.

```bash
git clone https://github.com/Eshaank08/agent-check.git
cd agent-check
npm install
npm run build
npm test
```

---

## Attribution

OWASP rules inspired by [HeadyZhang/agent-audit](https://github.com/HeadyZhang/agent-audit) (MIT License).

---

## License

MIT — see [LICENSE](LICENSE)

---

Built by [Eshaank08](https://github.com/Eshaank08)
