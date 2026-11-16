<!-- ⚠ SOURCE OF TRUTH = the rendered .pptx deck, NOT this file. This .md is tracked in git ONLY for its presenter-note comments, reworded 2026-11-16 to read as spoken script to the room. Slide BODIES here have diverged from the deck, so DO NOT re-render the .pptx from this .md (it would clobber hand-edited slides). Use diff_deck_vs_source.py to compare. -->
<!--
Closing · Course wrap-up — recap, guardrails, takeaways, participant TODO — slide source
Render: paste this + _templates/slide-brief.md into Claude Design → closing.pptx
  or: .venv-slides/bin/python training/_templates/render_deck.py training/blackhat-2026-adversarial-ai/closing/slides/closing.md
Convention: each slide separated by `---`; speaker notes in <!-- Notes: ... -->.
Runs LAST, after M8 + the capstone/finale. Density: wrap-up tier — signpost slides + a few
substantive recap tables. Aim ~18 slides / ~15 min. Bookend with the BH title + END slides.
Every claim here is sourced from the live eiger codebase and the study guide (files 00, 01, 21).
-->

# You now know how to break it
## …and, more importantly, how to fix it
### Adversarial AI · Black Hat USA 2026 · closing

<!-- Notes: Two days ago, most of you had never landed a prompt injection. You've now cracked one target across six layers and hardened each one. This last stretch is the take-it-home: the mental model, the defense patterns, and a concrete Monday-morning checklist. -->

---

## What you just did

One fictional AI-first neobank — **Eiger** — and its assistant **Iggy**. You attacked it across **six layers that stacked on top of each other**:

```
L0 chatbot → L1 RAG → L2 agent → L3 MCP → L4 multi-agent → L5 production
```

For every layer: **Build** it · **Break** it · **Secure** it. Flip **one flag**, run the **same** attack, watch it die.

<!-- Notes: Let me re-state the whole idea one last time so it sticks: one coherent target, a growing attack surface, and the vulnerable-to-secure diff as the entire lesson. What you should carry out of this room is not "22 payloads" — it's a way of seeing AI systems as a stack of trust boundaries. -->

---

## The one idea under every attack

> The model cannot tell where any part of its context came from.

System prompt, your message, a retrieved document, a tool's description, another agent's output — by the time the model reads them, they are **one undifferentiated stream of tokens**. No hardware boundary. No "this part is trusted."

**Every attack this course was, at root, an exploitation of that fact.**

<!-- Notes: This is the intellectual spine. If you remember exactly one sentence six months from now, make it this one: every defense in this course is a variation on "we draw a trust boundary the model doesn't have, and we enforce it in code before the tokens ever reach the model." -->

---

## The whole course — Day 1 (the model & its data)

| Module | Layer | Attack you landed | Guard that killed it | Flag |
|---|---|---|---|---|
| **M1** | L0 chatbot | Direct injection → extract operator honeytoken | Prompt hardening + input classifier | `SEC_SYSTEM_PROMPT_HARDENING` / `SEC_INPUT_FILTER` |
| **M2** | L0 chatbot | Stored XSS via echoed field + prompt-canary leak | HTML-escape **+** nonce-CSP (two guards) | `SEC_OUTPUT_ENCODING` |
| **M3** | L1 RAG | KB poisoning → indirect injection into another user | Quarantine user chunks as data; access scope | `SEC_RAG_PROVENANCE` |
| **M4** | supply chain | Pickle-RCE model artifact; known-vuln dependency | safetensors-only + hash-pin | `SEC_ARTIFACT_VERIFICATION` |

<!-- Notes: Day 1 ran keyless on the shared model — the plumbing lessons don't need a frontier model. M3 was the pivot: the victim never typed anything malicious; the attacker's text arrived through retrieved context. And M4 is your reminder that "loading a model" can be RCE before a single token is ever generated. -->

---

## The whole course — Day 2 (the model with hands)

| Module | Layer | Attack you landed | Guard that killed it | Flag |
|---|---|---|---|---|
| **M5** | L2 agent | Confused deputy — refund/email-change on an unowned account | Per-action ownership authz | `SEC_TOOL_SCOPE_ENFORCEMENT` |
| **M6** | L3 MCP | Tool-description poisoning · rug pull · cross-server token theft | Hash-pin + quarantine descriptions; per-server token isolation | `SEC_MCP_DESC_PINNING` / `SEC_MCP_TOKEN_SCOPING` |
| **M7** | L4 multi-agent | Injection **propagates** the pipeline → auto-approved fraudulent refund | Sign/verify agent messages; quarantine untrusted text | `SEC_INTER_AGENT_AUTH` |
| **M8** | L5 production | Guardrail obfuscation bypass (leetspeak / homoglyph) | Canonicalize input **before** the blocklist | `SEC_GUARDRAILS` |

<!-- Notes: Day 2 was bring-your-own-key — you need a frontier model to reliably chain tool calls. And remember the gotcha we hit live: the same class of attack behaves differently by model. Frontier models refuse the naive direct attacks in M5 and M7, but they faithfully follow the indirect poison in M6. That split is itself a defensive insight: alignment is a layer, not the layer. -->

---

## Where it lands on OWASP LLM Top 10

| Module | OWASP category |
|---|---|
| M1 | **LLM01** Prompt Injection |
| M2 | **LLM05** Improper Output Handling (+ LLM02, LLM07) |
| M3 | **LLM08** Vector & Embedding Weaknesses (+ LLM01 indirect) |
| M4 | **LLM04** Data & Model Poisoning + **LLM03** Supply Chain |
| M5 | **LLM06** Excessive Agency |
| M6 | **LLM06 + LLM01** — agentic, via tool metadata |
| M7 | **LLM01 + LLM06** — cascading, agentic |
| M8 | **LLM01 defenses** + the whole-stack picture |

<!-- Notes: Take a photo of this slide — it maps your two days onto the OWASP framework your org already uses for reporting. The "interesting" modern risk isn't a new category; it's the agentic combination. LLM06 excessive agency multiplies the blast radius of LLM01 injection. -->

---

## M5 · M6 · M7 are one old bug

> **Confused deputy** — a privileged program is tricked by a less-privileged party into misusing its authority.

- **M5:** you ask the agent to move money → it does (it has the privilege; you don't).
- **M6:** a poisoned **tool description** asks it for you — untrusted metadata as instructions.
- **M7:** an injected **dispute text** asks it, laundered through four trusting agents.

Same bug, three delivery mechanisms. Older than AI.

<!-- Notes: Naming it "confused deputy" collapses three modules into one durable idea, and it connects AI security to the classic security you already know. The agent has authority, the attacker doesn't, and the attacker persuades the deputy. The AI twist is only how the persuasion arrives — direct, via metadata, or via a trusted peer. -->

---

## The defense patterns that repeated

| Pattern | Where you saw it | The move |
|---|---|---|
| **Provenance / trust-tagging** | M3, M6, M7 | Tag context by origin; never let attacker-controllable text act as instructions |
| **Channel separation** | M1, M7 | Untrusted data in a labelled "data, not instructions" block |
| **Least privilege + per-action authz** | M5, M6 | The deputy checks *ownership* before every sensitive action |
| **Signed provenance** | M7 | Sign inter-agent messages; re-establish trust at every hop |
| **Verification before load** | M4 | Hash-pin artifacts; safetensors-only; never deserialize untrusted pickles |
| **Canonicalize before filter** | M8 | Normalize obfuscation *before* the blocklist reads it |

<!-- Notes: This is the real deliverable — six reusable controls, not eight one-off tricks. Every one is the same move: draw a trust boundary and enforce it in code. Internalise this table and you can defend a stack this course never showed you. -->

---

## Guardrails are not a checkbox

- M2 shipped **two** independent guards (escape **and** CSP) — either alone stops the XSS. That's **defense in depth**, on purpose.
- M8's guardrail **deliberately** misses homoglyphs. A blocklist matches the literal string; the model understands meaning.
- Flipping every flag to `secure` blocks **your** exploits — it does **not** make the system "safe."

> **"We turned the flags on" ≠ "we're safe."** The gap between those is the **residual risk** — and documenting it is the job.

<!-- Notes: Here's the note I want to end on. Guardrails give you false comfort if you never tested them against obfuscation. The honest posture a real engagement produces isn't "secured" — it's "these controls hold against these attacks, and here's the residual gap." Make that your professional standard. -->

---

## The uncomfortable truths to take home

1. **The model can't tell trusted from untrusted** — so *you* must, in code, before the tokens arrive.
2. **Tool metadata is untrusted input** — and almost nobody reads it.
3. **Alignment is a layer, not the layer** — frontier models refuse the naive attack and fall for the indirect one.
4. **Grade the mechanism, never the words** — build detection on *events*, not on what the model said.
5. **Agency multiplies everything** — the more the model can *do*, the more an injection is worth.

<!-- Notes: Number four is the transferable engineering lesson from the whole lab design: the append-only audit log is how a room full of people reliably graded a non-deterministic model — and it's how you should instrument your own AI systems for detection. Number five is the forward-looking one, as everyone races to give models more tools. -->

---

## → Your Monday morning — the checklist

**Map it first**
- [ ] Inventory which of the six layers you actually run (chatbot? RAG? agent? MCP? multi-agent?). Each layer you added is attack surface you own.
- [ ] For every place model output is **rendered** (web, email, docs), assume XSS until proven encoded.

**Fix the model & its data**
- [ ] Get **secrets out of the system prompt**; treat the prompt as readable by anyone.
- [ ] **Encode model output** context-aware + ship a CSP anywhere it renders.
- [ ] **Tag RAG chunks by provenance**; quarantine user-submitted content as *data*, enforce access scope.
- [ ] **Verify model artifacts** — safetensors-only, hash-pin, ban untrusted pickle. Scan pinned deps for CVEs.

<!-- Notes: This is the slide you'll actually act on: the same six controls you flipped today, now against your own stack. The checklist maps one-to-one to the flags you toggled. Go run your own vulnerable-to-secure diff internally. -->

---

## → Your Monday morning — the agentic half

**Fix the model with hands**
- [ ] **Least privilege for tools** — per-action ownership/authorization checks; human-in-the-loop for anything that moves money or data.
- [ ] **Pin & sanitize MCP tool descriptions**; isolate credentials **per server** — no shared token vault.
- [ ] **Sign inter-agent messages**; re-establish trust at every hop — never trust a peer agent implicitly.
- [ ] **Canonicalize inputs before guardrails**; red-team your filter with leetspeak/unicode/homoglyphs.

**Prove it, don't assume it**
- [ ] **Instrument an audit log of security events** — detect on mechanism, not on chat text.
- [ ] **Test the *secure* config**, then **document the residual risk**. "Flags on" is a start, not a finish.

<!-- Notes: The second half of this list is where most orgs are weakest, because agentic AI is new. The single highest-leverage item is human-in-the-loop on irreversible actions — it's your backstop when every model-side control fails. And I'll push the audit-log point hard: it's the difference between "we think we're fine" and "we can see when we're not." -->

---

## Keep going

- **The study guide** — every module, real payloads, the exact guard code, glossary, OWASP map, payload cookbook. It's yours.
- **Run Eiger locally** — the whole lab is a one-page setup; flip flags and read the diffs at your own pace.
- **OWASP LLM Top 10** · **OWASP Agentic Security Initiative** · **MITRE ATLAS** — the frameworks your reports will cite.

<!-- Notes: You've got the offline study guide — use it, and run the lab locally after the con. The vulnerable-to-secure if branch is literally one line to read per guard. And lean on the frameworks by name, so your write-ups have a taxonomy. -->

---

## Thank you — go break things responsibly

You attacked one target across six layers and hardened every one. Now do it to systems that matter — **with authorization**, and with the residual-risk honesty this course ended on.

**KK Mookhey** · `linkedin.com/in/kkmookhey` · Transilience AI
**Venkat Pothamsetty** · `linkedin.com/in/venkatpothamsetty`

<!-- Notes: Stay in touch, and send me the cleverer attacks you build — the ones that out-attacked the grader. Thank you for two days of breaking things. -->
