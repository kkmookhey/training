# Adversarial AI — Red Teaming the AI Supply Chain

**Black Hat USA, August 2026 · 2-day hands-on course**

You attack and defend one target — **Halcyon**, an AI-first neobank whose assistant "Halo" grows new attack surface every module. Same company for two days. Every module runs the **Build → Break → Secure** loop.

> **Before you arrive:** complete the **[prerequisites and setup →](prereqs/)**. Day 1 is keyless (runs on a local model); Day 2 needs your own API key.

## The spine

We don't teach OWASP as a checklist. We follow the supply chain and the attacks land where they live:

```
model → RAG → tools/agents → MCP → multi-agent → production
```

## Modules

### Day 1 — The model and its data
| Module | Topic | OWASP | Model |
|--------|-------|-------|-------|
| [M0](M0-threat-model/) | Threat model + range check | — | Gandalf (hosted) |
| [M1](M1-prompt-injection/) | Prompt injection | LLM01 | Ollama (local) |
| [M2](M2-output-handling/) | Output handling & disclosure | LLM05/02 | Ollama (local) |
| [M3](M3-rag-attacks/) | RAG attacks | LLM08 | Ollama (local) |
| [M4](M4-ml-supply-chain/) | Poisoning & ML supply chain | LLM04/03 | none (artifact) |

### Day 2 — Agency and autonomy
| Module | Topic | OWASP | Model |
|--------|-------|-------|-------|
| [M5](M5-excessive-agency/) | Excessive agency & tool abuse | LLM06 | BYOK |
| [M6](M6-mcp-security/) | MCP security | — | BYOK |
| [M7](M7-multi-agent/) | Multi-agent | — | BYOK |
| [M8](M8-production-defense/) | Production, defense + capstone | — | BYOK |

## The lab: Halcyon

[`halcyon/`](halcyon/) — a deliberately-vulnerable single app you Build/Break/Secure across all modules. Deterministic, resettable, mechanism-validated (pass/fail comes from an audit log, never the model's words). Distributed on USB at the venue.

## Further reading

Curated links live in **[Basecamp](https://github.com/kkmookhey/basecamp-ai-sec)**; each module points to the relevant topic.
