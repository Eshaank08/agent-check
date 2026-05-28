# AgentCheck

Open source CLI that audits AI agents for security vulnerabilities, performance issues, and model fit — in under 60 seconds.

## Quick Start

```bash
npx agentcheck audit
```

No API key required for static analysis.

---

## Two Audit Modes

### Mode 1 — Interactive (no code needed)

Answer a few structured questions about your agent in the terminal. No source code required.

```bash
npx agentcheck audit
```

AgentCheck will ask about:
- Agent name and purpose
- Which model you're using
- Tool names and their permissions (read / write / delete / execute)
- Sub-agents and how they're orchestrated
- Whether you have human approval gates
- Approximate daily call volume

### Mode 2 — File Scan

Point AgentCheck at your agent source directory. It recursively scans `.py`, `.ts`, `.js`, `.json`, `.yaml`, and `.env` files, extracts structural metadata, and runs analysis — without sending your code to any external service.

```bash
npx agentcheck audit --path ./my-agent
npx agentcheck audit --path /home/user/projects/crm-agent
```

**What gets extracted (never raw code):**
- Tool names and inferred permissions
- Model identifiers
- System prompt presence (not content)
- Sub-agent patterns
- Error handling and rate limiting signals
- Potential hardcoded credentials (file + line number flagged)

---

## Environment Setup

For AI-powered analysis (recommended), set your Anthropic API key:

```bash
export ANTHROPIC_API_KEY=sk-ant-...
```

Then run the audit as normal. AgentCheck will automatically use the AI reasoning layer.

To make this permanent, add it to your shell profile (`~/.zshrc`, `~/.bashrc`, etc.):

```bash
echo 'export ANTHROPIC_API_KEY=sk-ant-...' >> ~/.zshrc
source ~/.zshrc
```

---

## Flags

| Flag | Description |
|------|-------------|
| `--path <dir>` | Scan a directory instead of using interactive mode |
| `--no-ai` | Run static analysis only — no API key needed, no external calls |
| `--version` | Print version |
| `--help` | Show help |

### Offline / No-API mode

```bash
npx agentcheck audit --path ./my-agent --no-ai
```

Static analysis runs entirely locally, covering all 10 OWASP Agentic AI checks. No network connection needed.

---

## What AgentCheck Checks

### Static Analysis (always runs, no API key needed)

Based on the [OWASP Agentic AI Top 10 (2026)](https://owasp.org/www-project-top-10-for-large-language-model-applications/):

| Rule | Severity | Description |
|------|----------|-------------|
| OAA-01 | CRITICAL | Prompt injection vulnerability patterns |
| OAA-02 | HIGH | Over-permissioned tools (write/delete where read suffices) |
| OAA-03 | CRITICAL | Missing human approval on sensitive actions |
| OAA-04 | CRITICAL | Hardcoded secrets or API keys |
| OAA-05 | MEDIUM | Tool scope creep |
| OAA-06 | MEDIUM | Missing error handling for tool failures |
| OAA-07 | HIGH | Unconstrained sub-agent permissions |
| OAA-08 | MEDIUM | No output validation layer |
| OAA-09 | HIGH | PII exposure in tool outputs |
| OAA-10 | MEDIUM | Missing rate limiting on external API tools |

### AI Analysis (requires `ANTHROPIC_API_KEY`)

Claude reasons about your agent's architecture and provides:

- **Logical contradictions** — tools that conflict with stated purpose
- **Sub-agent trust issues** — orchestrator/sub-agent permission boundaries
- **Workflow gaps** — what happens when a tool fails mid-workflow
- **Permission logic** — unjustified permission levels
- **Model recommendations** — top 3 alternatives with monthly cost estimates
- **Most critical fix** — the one thing to address immediately

---

## Sample Output

```
════════════════════════════════════════════════════════
                AgentCheck Audit Report
                     Agent: crm-agent
             Scanned: 5/28/2026, 3:45:00 PM
════════════════════════════════════════════════════════

STATIC ANALYSIS
────────────────────────────────────────────────────────
  ❌ CRITICAL  No Human Approval on Sensitive Action
             Tool "send_email" performs a sensitive action without
             requiring human confirmation.

  ❌ HIGH      Over-permissioned Tool
             Tool "crm_records" has delete permission. Verify this
             is the minimum required for the task.

  ✅ PASSED   No hardcoded credentials detected

AI ANALYSIS
────────────────────────────────────────────────────────
  💡 Agent is described as read-only but has 3 write tools

MODEL RECOMMENDATION
────────────────────────────────────────────────────────
  Recommended
  claude-haiku-4-5 (Anthropic)  ~$18/month
  95% quality match — Simpler task type; Haiku handles it at 10x lower cost

SUMMARY
────────────────────────────────────────────────────────
  Security Score:     4/10  ✗
  Performance Score:  7/10  ⚠
  Cost Efficiency:    3/10  ✗

  Overall Score:      47/100  ✗
════════════════════════════════════════════════════════
```

---

## Privacy

**What is NOT sent to Anthropic:**
- Your source code
- System prompt content
- Tool implementation logic
- Any customer or user data

**What IS sent to Anthropic (AI layer only):**
- Tool names and permission levels
- Agent description (from interactive input or package.json)
- Model name
- Boolean flags: error handling present, rate limiting present, etc.
- Static analysis findings (rule IDs and severity levels)

AgentCheck prints a privacy notice before running AI analysis. Use `--no-ai` to disable all external calls entirely.

---

## Attribution

OWASP rules inspired by [HeadyZhang/agent-audit](https://github.com/HeadyZhang/agent-audit) (MIT License).

---

## License

MIT — see [LICENSE](LICENSE)

---

## Built by [Eshaank08](https://github.com/Eshaank08)
