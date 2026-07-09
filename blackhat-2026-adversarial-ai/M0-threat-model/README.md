# M0 · Threat Model + Range Check

> **One-line premise:** map the AI supply chain, get your machine green, and warm up on a hosted target.
> **OWASP:** — · **Halcyon layer:** — · **Model tier:** Gandalf (hosted)

## Objectives
- **Core (everyone):** reach-test green (reach the target · Burp proxy · cert trusted), draw the supply-chain attack map, and beat Gandalf levels 1–3.
- **Stretch:** push Gandalf to its later levels; try the Gandalf *agent* variant (Day-2 warm-up).

## Run-of-show (~45 min)
| Phase | What happens |
|-------|--------------|
| Build | run the reach-test (browser + Burp reaches the hosted target); tour Halcyon's architecture |
| Break | attacker mental model; Gandalf warm-up (browser-only) |
| Secure | frame the two-day supply-chain journey: model → RAG → tools → MCP → multi-agent → prod |

## Demos
- Gandalf (Lakera) — hosted, browser-only, absorbs setup chaos while stragglers finish install.

## Validation
Warm-up module — no audit event. Success = reach-test green + Gandalf progress (self-reported).

## Further reading
→ Basecamp: [Foundations](https://github.com/kkmookhey/basecamp-ai-sec/blob/main/docs/topics/01-foundations.md)
