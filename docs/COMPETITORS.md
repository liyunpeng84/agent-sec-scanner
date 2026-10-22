# Competitive landscape (researched 2026-10-21)

Sources were read on 2026-10-21; star counts and features change quickly. Only claims visible in each project's
README/docs are listed.

| Project | Lang / License | Mode | Notes from their docs | Overlap with us |
|---|---|---|---|---|
| **Snyk Agent Scan** (formerly Invariant `mcp-scan`; PyPI `mcp-scan` now redirects to `snyk-agent-scan`) — github.com/snyk/agent-scan | Python, Apache-2.0 | Discovers agents/MCP/skills, **connects to servers** to fetch tools, sends component info to the **Agent Scan API** (needs `SNYK_TOKEN`); proxy/guardrail mode, tool pinning, toxic-flow analysis | Market leader; broad client discovery (Claude, Cursor, Copilot, Windsurf, Gemini CLI, Codex, Kiro, OpenClaw …); output schema marked experimental | High on goals; differs on offline/no-account, no execution |
| **mcplint** — github.com/mcplint/mcplint | Rust, Apache-2.0 | Static analysis of MCP configs/tool defs, CWE/OWASP MCP mapping, `--fail-on` for CI | "semgrep for MCP" positioning | High (static + CI) |
| **mcp-fence** — github.com/DaoyuanLi2816/mcp-fence | Python, Apache-2.0 | Static scan + live inspection + **fuzzing** + Docker sandbox; SARIF/HTML; GitHub Action | ~37★ when checked | High; it goes further into dynamic testing |
| **mcpguard** (nbosa) | Go, MIT | Static + runtime probe + stdio guard proxy, entropy secrets, SARIF | very new | Medium-high |
| **明棱 MCPGuard** (ChenLaoshiYF) | Python | Static scan of MCP configs + skills; Chinese README; zh/ja/ko override phrases; MCP server mode | Closest Chinese-language project; regex-only by their own admission | Medium (no agent-posture, no China-cloud keys documented) |
| **MCPScan** (Ant Group) — github.com/antgroup/mcp-security | Python | Semgrep taint scan of **server source code** + optional LLM judging | Code-level, not client config | Low-medium |
| **sentinel-scan-cli** (Ventrova) | — | Offline manifest heuristics (10 OWASP-mapped) + jailbreak suite | | Medium |
| **mcp-tool-auditor** (perparimmjeku) | Python, MIT | Static + **behavioral** (calls tools), cross-server toxic flow, signed reports, also ships offensive tooling | Very feature-rich | Medium-high |

## Honest assessment

The "MCP static scanner" space is crowded; basic tool-poisoning regexes are table stakes. A v0.1 that only did that
would not be worth publishing. Defensible differentiation for this project:

1. **Zero execution, zero network, zero account** — safe to run on a developer laptop or in CI on untrusted PRs
   (scanners that launch configured servers can themselves trigger a malicious `npx`/`curl | sh`).
2. **Agent posture + MCP in one report** — Claude Code permissions, Codex approval/sandbox, Cline `alwaysAllow`,
   Gemini `trust`, combined with the toxic-combination heuristic.
3. **China ecosystem first-class** — Chinese injection phrases; Aliyun / Tencent / Volcengine / Baidu / Zhipu /
   `sk-` key formats; domestic clients (Trae, Qwen Code; more to verify: Cherry Studio, Tongyi Lingma, CodeBuddy).
4. **Actionable fixes** per finding, SARIF + `--fail-on` + ignore file for CI.

Gaps vs leaders (be upfront in README): no semantic/LLM detection, no runtime proxy, no rug-pull baseline yet.
