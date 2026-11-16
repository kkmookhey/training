# Adversarial AI — Red Teaming the AI Supply Chain

**Black Hat USA, August 2026 · 2-day hands-on course**

You attack and defend one target — **Eiger**, an AI-first neobank whose assistant "Iggy" grows new attack surface every module. Same company for two days. Every module runs the **Build → Break → Secure** loop.

> **Before you arrive:** complete the **[prerequisites and setup →](prereqs/)**. Eiger is **hosted** — you attack it from your browser through Burp; no Docker, no downloads. Day 1 is keyless; Day 2 needs your own API key.

## The spine

We don't teach OWASP as a checklist. We follow the supply chain and the attacks land where they live:

```
model → RAG → tools/agents → MCP → multi-agent → production
```

## Modules

### Day 1 — The model and its data
| Module | Topic | OWASP (2026) | Model |
|--------|-------|-------|-------|
| [M0](M0-threat-model/) | Threat model + range check | — | Gandalf (hosted) |
| [M1](M1-prompt-injection/) | Prompt injection | LLM01 | Ollama (shared, keyless) |
| [M2](M2-output-handling/) | Output handling & disclosure | LLM10/02 | Ollama (shared, keyless) |
| [M3](M3-rag-attacks/) | RAG attacks | LLM09 | Ollama (shared, keyless) |
| [M4](M4-ml-supply-chain/) | Poisoning & ML supply chain | LLM05/04 | none (artifact) |

### Day 2 — Agency and autonomy
| Module | Topic | OWASP | Model |
|--------|-------|-------|-------|
| [M5](M5-excessive-agency/) | Excessive agency & tool abuse | LLM03 | BYOK |
| [M6](M6-mcp-security/) | MCP security | LLM03/01 · MCP03 | BYOK |
| [M7](M7-multi-agent/) | Multi-agent | LLM01/03 · ASI07/08 | BYOK |
| [M8](M8-production-defense/) | Production, defense + capstone | — | BYOK |

### Bonus — slides only
| Module | Topic | OWASP (2026) | Model |
|--------|-------|-------|-------|
| [M9](M9-training-data-extraction/) | Training-data extraction | LLM02/08/09 | none |
| [M10](M10-coding-agents/) | Coding and CI agents | LLM04 · ASI04/05 · MCP09 | none |

OWASP numbers follow the 2026 edition of the LLM Top 10. ASI = OWASP Agentic Top 10, MCP = OWASP MCP Top 10.

## The lab: Eiger

[`eiger/`](eiger/) — a deliberately-vulnerable single app you Build/Break/Secure across all modules. Deterministic, resettable, mechanism-validated (pass/fail comes from an audit log, never the model's words). **Hosted, container-per-participant**, reachable from your browser.

## Further reading

Curated links live in **[Basecamp](https://github.com/kkmookhey/basecamp-ai-sec)**; each module points to the relevant topic.
