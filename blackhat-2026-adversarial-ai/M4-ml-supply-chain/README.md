# M4 · Poisoning & ML Supply Chain

> **One-line premise:** the model artifact itself is code — loading an untrusted one executes it.
> **OWASP:** LLM04 / LLM03 · **Halcyon layer:** L1 artifact · **Model tier:** none (no live LLM)

## Objectives
- **Core (participant):** detect the malicious artifact with the provided tooling (pickle-opcode / unsafe-globals scan).
- **Stretch:** craft a benign-looking poisoned artifact that passes a naive check.
- **Break:** instructor-led demo (destructive/slow) triggers the deserialization RCE.

## Run-of-show (~45 min)
| Phase | What happens |
|-------|--------------|
| Build | Halcyon loads an embedding model / pickled artifact from an untrusted hub |
| Break | *instructor demo:* deserialization RCE; participants scan artifacts for the badness |
| Secure | flip `SEC_ARTIFACT_VERIFICATION`; safetensors-only, hash pinning, no arbitrary pickle |

## Demos
- `code/` — pickle-opcode scanner; a poisoned vs clean artifact.

## Validation
Submitted hash/opcode finding checked against known-bad. *(Open: keep break as instructor-demo.)*

## Further reading
→ Basecamp: [LLM Vulnerabilities](https://github.com/kkmookhey/basecamp-ai-sec/blob/main/docs/topics/05-llm-vulnerabilities.md)
