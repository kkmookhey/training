# M7 · Multi-Agent

> **One-line premise:** agents trust each other — inject one and the fraud approves itself downstream.
> **OWASP:** — · **Eiger layer:** L4 · **Model tier:** BYOK

## Objectives
- **Core (everyone):** inject at the dispute-text surface → the action agent approves your fraudulent refund.
- **Stretch:** cascade — poison one agent to attack another, or get the supervisor to rubber-stamp.

## Run-of-show (~75 min)
| Phase | What happens |
|-------|--------------|
| Build | dispute pipeline (intake → risk → action → supervisor) passes messages with implicit trust (LangGraph) |
| Break | a payload injected at intake propagates and auto-approves a fraudulent dispute |
| Secure | flip `SEC_INTER_AGENT_AUTH`; signed inter-agent messages, trust boundaries, provenance checks |

## Demos
- `code/` — the pipeline graph; a cascading injection across agents.

## Validation
Events: `inter_agent_injection_propagated` + `unauthorized_approval`.

## Further reading
→ Basecamp: [Agentic AI Security](https://github.com/kkmookhey/basecamp-ai-sec/blob/main/docs/topics/06-agentic-security.md)
