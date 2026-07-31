# M2 · Output Handling & Disclosure

> **One-line premise:** what Iggy *emits* is as dangerous as what it's told — land an XSS and leak its brain.
> **OWASP:** LLM05 / LLM02 · **Eiger layer:** L0/L1 · **Model tier:** Ollama (local)

## Objectives
- **Core (everyone):** land an XSS via a data field Iggy echoes into the chat UI.
- **Stretch:** chain disclosure — leak the full system prompt + tool schema, then use that map to craft a targeted injection.

## Run-of-show (~60 min)
| Phase | What happens |
|-------|--------------|
| Build | responses rendered as raw HTML; verbose errors; leaky prompt/tool schema |
| Break | inject a payload into an echoed field → XSS beacon fires; request-based disclosure |
| Secure | flip `SEC_OUTPUT_ENCODING` + `SEC_SYSTEM_PROMPT_HARDENING`; confirm encoded + canary held |

## Demos
- `code/` — the XSS beacon; context-aware encoding before/after.

## Validation
Event: `xss_beacon` (headless-browser beacon hit) + system-prompt canary.

## Further reading
→ Basecamp: [Prompt Injection](https://github.com/kkmookhey/basecamp-ai-sec/blob/main/docs/topics/04-prompt-injection.md) · [LLM Vulnerabilities](https://github.com/kkmookhey/basecamp-ai-sec/blob/main/docs/topics/05-llm-vulnerabilities.md)
