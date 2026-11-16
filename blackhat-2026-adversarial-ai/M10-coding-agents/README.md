# M10 · Coding and CI Agents

> **One-line premise:** the repository is the attacker. The agent your engineers run has a shell, credentials and untrusted text in one process.
> **OWASP:** LLM04:2026 Supply Chain · ASI04 · ASI05 · MCP09 · **Eiger layer:** none (off-spine) · **Model tier:** none

## Objectives

- **Core (everyone):** name the four ways a repository reaches a coding agent (content it reads, config it loads, things it installs, its own initiative), and know which controls contain each.
- **Stretch:** none. This is a bonus deck.

There is **no graded objective**: no `/validate/m10`, no `SEC_*` flag, no audit event.

## Run-of-show (~30–40 min)

| Act | Content | Slides |
|-----|---------|--------|
| 0 | Where this sits, what the session covers, the premise | 1–4 |
| 1 | Why a coding agent is different: shell, credentials, untrusted text | 5 |
| 2 | Field record: config files (TrustFall, Amazon Q, Miasma) and content (GitLost, Cortex Code CLI, Amazon Q extension, PocketOS) | 6–7 |
| 3 | Four ways in, and the anatomy of one chain | 8–9 |
| 4 | Vendor responses, why human approval fails | 10–11 |
| 5 | What holds, five things to check, the lesson | 12–14 |

Slide 15 is further reading.

## Slides

`slides/M10 - coding and CI agents.pptx`

## Further reading

Adversa AI (TrustFall, May 2026) · Wiz Research (CVE-2026-12957) · PromptArmor (Snowflake Cortex Code CLI, Mar 2026) · Noma Labs (GitLost, Jul 2026) · StepSecurity, Cloudsmith, OpenSourceMalware (Miasma, Jun 2026) · OWASP Agentic Top 10 · OWASP MCP Top 10
