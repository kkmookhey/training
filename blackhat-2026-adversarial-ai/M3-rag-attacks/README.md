# M3 · RAG Attacks

> **One-line premise:** poison the knowledge base so *another* user's innocent question runs your instruction.
> **OWASP:** LLM08 · **Halcyon layer:** L1 · **Model tier:** Ollama (local)

## Objectives
- **Core (everyone):** poison a doc so a *different* user's routine question triggers your injected instruction (indirect injection via retrieval).
- **Stretch:** exfiltrate an access-controlled chunk (restricted-doc retrieval / KB leakage).

## Run-of-show (~75 min — core differentiator)
| Phase | What happens |
|-------|--------------|
| Build | KB ingests user-submittable content into ChromaDB with no provenance separation |
| Break | submit a poisoned dispute/FAQ; watch it surface in another session's answer |
| Secure | flip `SEC_RAG_PROVENANCE`; trust-tag chunks, quarantine user content, treat retrieved text as data |

## Demos
- `code/` — the poisoned document; retrieval with vs without provenance tagging.

## Validation
Event: `poisoned_chunk_in_context` + target action fired, or `restricted_doc_retrieved`.

## Further reading
→ Basecamp: [Building LLM Apps](https://github.com/kkmookhey/basecamp-ai-sec/blob/main/docs/topics/02-building-llm-apps.md) · [LLM Vulnerabilities](https://github.com/kkmookhey/basecamp-ai-sec/blob/main/docs/topics/05-llm-vulnerabilities.md)
