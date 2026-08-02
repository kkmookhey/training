# Adversarial AI — Take It Home

*Black Hat USA 2026 · one-page field guide. Sourced from the live Eiger lab — the controls below are the exact flags you flipped.*

---

## The one thing to remember

> **The model cannot tell where any part of its context came from.** System prompt, user message, retrieved doc, tool description, another agent's output — all one flat stream of tokens. Every attack exploited that. Every defense is *you* drawing a trust boundary the model doesn't have, and enforcing it in code before the tokens arrive.

---

## What you broke, and what stopped it

| # | Layer | Attack | Control to apply at work | OWASP |
|---|---|---|---|---|
| M1 | Chatbot | Direct prompt injection → leak secrets in the prompt | Secrets **out** of the system prompt; input classifier; role separation | LLM01 |
| M2 | Chatbot | Stored XSS via echoed field; prompt-canary leak | Context-aware output encoding **+** CSP (two independent guards) | LLM05 |
| M3 | RAG | Poison the KB → indirect injection into another user | Provenance-tag chunks; quarantine user content as **data**; access scope | LLM08 |
| M4 | Supply chain | Pickle-RCE model file; known-vuln dependency | safetensors-only; hash-pin artifacts; ban untrusted pickle; scan deps | LLM04 / LLM03 |
| M5 | Agent | Confused deputy — act on an account you don't own | Per-action **ownership authz**; human-in-the-loop on money/data moves | LLM06 |
| M6 | MCP | Tool-description poisoning; rug pull; cross-server token theft | Hash-pin + sanitize tool descriptions; **per-server** credential isolation | LLM06/LLM01 |
| M7 | Multi-agent | Injection propagates the pipeline → fraudulent auto-approval | **Sign** inter-agent messages; re-verify trust at every hop | LLM01/LLM06 |
| M8 | Production | Guardrail bypass via leetspeak / homoglyph / unicode | **Canonicalize before** the blocklist; defense-in-depth; test the filter | LLM01 |

---

## Six reusable defense patterns

1. **Provenance / trust-tagging** — tag context by origin; never let attacker-controllable text act as instructions. *(M3, M6, M7)*
2. **Channel separation** — untrusted data goes in a labelled "data, not instructions" block. *(M1, M7)*
3. **Least privilege + per-action authz** — the deputy checks ownership before every sensitive action. *(M5, M6)*
4. **Signed provenance** — sign messages between components; re-establish trust at each hop. *(M7)*
5. **Verify before load** — hash-pin artifacts; safetensors-only; deserializing an untrusted file is RCE. *(M4)*
6. **Canonicalize before filter** — normalize obfuscation before any blocklist reads it. *(M8)*

---

## Monday-morning checklist

**Map**
- [ ] Inventory which layers you run — chatbot, RAG, agent, MCP, multi-agent. Each is attack surface you own.
- [ ] Anywhere model output is rendered (web/email/docs), assume XSS until proven encoded.

**Model & data**
- [ ] Secrets out of the system prompt (assume it's readable).
- [ ] Context-aware output encoding + CSP wherever output renders.
- [ ] Provenance-tag RAG chunks; quarantine user content; enforce access scope.
- [ ] Verify model artifacts (safetensors-only, hash-pin, no untrusted pickle); CVE-scan pinned deps.

**Agentic**
- [ ] Least-privilege tools; per-action ownership checks; **human-in-the-loop for irreversible actions**.
- [ ] Pin & sanitize MCP tool descriptions; isolate credentials per server.
- [ ] Sign inter-agent messages; never trust a peer agent implicitly.
- [ ] Canonicalize inputs before guardrails; red-team the filter with obfuscation.

**Prove it**
- [ ] Instrument an **audit log of security events** — detect on mechanism, not on chat text.
- [ ] Test the *secure* configuration; then **document the residual risk**. "Flags on" ≠ "safe."

---

## Five uncomfortable truths

1. The model can't tell trusted from untrusted — so you must, in code, before the tokens arrive.
2. Tool metadata is untrusted input — and almost nobody reads it.
3. Alignment is a layer, not *the* layer — frontier models refuse the naive attack and fall for the indirect one.
4. Grade the mechanism, never the words — build detection on events.
5. Agency multiplies everything — the more a model can *do*, the more an injection is worth.

---

## Keep learning

- **Your study guide** — every module with real payloads, exact guard code, glossary, OWASP map, payload cookbook.
- **Run Eiger locally** — flip the flags, read the one-line diffs at your own pace.
- **OWASP LLM Top 10** · **OWASP Agentic Security Initiative** · **MITRE ATLAS**.

*Break things responsibly — with authorization, and with residual-risk honesty. — KK & Venkat*
