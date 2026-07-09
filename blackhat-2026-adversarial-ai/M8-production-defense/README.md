# M8 · Production, Defense + Capstone

> **One-line premise:** guardrails you can bypass aren't guardrails — break them, then build ones that hold.
> **OWASP:** — · **Halcyon layer:** L5 + full stack · **Model tier:** BYOK

## Objectives
- **Core (everyone):** bypass the guardrail (encoding/obfuscation via P4RS3LT0NGV3) to re-land an earlier attack; then harden and re-test.
- **Stretch:** automate — point garak / PyRIT at Halcyon and produce a findings report.
- **Capstone:** full-stack red team in `vulnerable` mode → flip to `secure` → verify each exploit is blocked → document residual risk.

## Run-of-show (~90 min + capstone)
| Phase | What happens |
|-------|--------------|
| Build | Halo fronted by bypassable guardrails; incomplete logging |
| Break | bypass the filter to re-land an M1–M7 attack |
| Secure | turn `SEC_GUARDRAILS` (and all flags) ON across the stack and measure |

## Demos
- `code/` — a guardrail bypass; garak/PyRIT run against the hardened stack.

## Validation
Event: `guardrail_bypassed` before/after + tool-run completion.

## Further reading
→ Basecamp: [AI Red Teaming](https://github.com/kkmookhey/basecamp-ai-sec/blob/main/docs/topics/07-red-teaming.md) · [Tooling for Attacking AI](https://github.com/kkmookhey/basecamp-ai-sec/blob/main/docs/topics/08-attacking-ai-tooling.md)
