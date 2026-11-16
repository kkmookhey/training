<!-- ⚠ SOURCE OF TRUTH = the rendered .pptx deck, NOT this file. This .md is tracked in git ONLY for its presenter-note comments, reworded 2026-11-16 to read as spoken script to the room. Slide BODIES here have diverged from the deck, so DO NOT re-render the .pptx from this .md (it would clobber hand-edited slides). Use diff_deck_vs_source.py to compare. -->
<!--
Opener · Course intro + instructor bios + caveats — slide source
Render: paste this + _templates/slide-brief.md into Claude Design → opener.pptx
Convention: each slide separated by `---`; speaker notes in <!-- Notes: ... -->.
Runs FIRST, before M0. Keep it tight (~12 min) — the room wants to start breaking things.
Batch-2 revision: adds the "Two ways to play" lane slide, the five-beat rhythm, and the "Meet Anna" intro.
Venkat bio backfilled 2026-08-06 from the rendered Opener.pptx (it had been filled in
PowerPoint only, so a re-render would have put the unfilled placeholders back on stage).
-->

# Adversarial AI
## Red-Teaming the AI Stack, Layer by Layer
### Black Hat USA 2026 · two days, hands-on · KK Mookhey & Venkat Pothamsetty

<!-- Notes: For the next two days, you're going to attack one AI application across every layer it's built from — and then secure each one. This is a lab, not a lecture. You'll spend most of your time in the browser, breaking things. -->

---

## One target. Two days. Three verbs.

You attack **one** fictional AI-first neobank — **Eiger** — and its assistant **Iggy**.

Its attack surface **grows each module**, layer by layer:

```
L0 chatbot → L1 RAG → L2 agent → L3 MCP → L4 multi-agent → L5 production
```

For every layer you **Build** it, **Break** it, then **Secure** it.

<!-- Notes: We do this against one target the whole way through — not eight disconnected toys, but one coherent story that grows a new attack surface each module. The rhythm never changes: Build, Break, Secure. You'll hear those three words all day. -->

---

## The two-day arc

| Day 1 — the model & its data *(keyless)* | Day 2 — the model with hands *(BYOK)* |
|---|---|
| **F0** understanding LLMs | **L3** MCP · tool poisoning |
| **L0** chatbot · prompt injection, output handling | **L4** multi-agent · cascading trust |
| **L1** RAG · knowledge-base poisoning | **L5** production · guardrails + capstone |
| **L2** agent · excessive agency + supply chain | |

Warm up on **Gandalf**, then Day 1 runs **keyless** on a shared model. Day 2 is **BYOK** — bring your own key.

<!-- Notes: Here's the shape of the two days. Day 1 is the model and its data — we start with foundations, then the L0 chatbot: prompt injection and output handling. Then L1, where retrieval gets poisoned, and L2, where the model gets tools: supply chain and excessive agency. All of Day 1 runs keyless on a shared model, so there's nothing for you to set up. Day 2 is the model with hands — MCP, multi-agent systems, production defense, and an AI-versus-AI finale. For Day 2 you'll use your own API key, because a frontier model chains tool calls far more reliably; if you don't have one, pair up with someone who does. -->

<!-- Notes(cont.): Note L2 (agent) is on Day 1 and runs keyless — M5 is a simple single tool-call the shared model handles. The BYOK line is really about M6 and the finale. -->


---

## Two ways to play — pick your lane

| 🗡 **Attacker** | 🔧 **Builder** |
|---|---|
| Hit the **hosted** Eiger from your browser | **Clone** the repo, run the module's code on your laptop |
| Zero setup — the default | Build → Break → Secure the **real guard code** yourself |
| Fast: just attack | Flip the `SEC_*` flag in the source, watch the attack die locally |

Switch lanes **any module**. Builders: setup is one page in `prereqs/`.

<!-- Notes: One choice worth naming up front. Most of you will attack the hosted app directly. But if you'd rather walk away with a methodology you can take home, you can run the code locally and read the actual security guard behind each fix. That builder lane is the same "point Claude Code at real code" method you'll watch later — and it's the honest answer to "can I use this in my own environment?" -->

---

## Build → Break → Secure — the five beats

Every module, the **same five beats** — so you're never lost about where we are:

**① Concept** → **② Worked example** → **③ Break** → **④ Secure** → **⑤ Reality check**

- **① Concept** — the layer + the attack, in two slides.
- **② Worked example** — the mechanism in ~20 lines you can run.
- **③ Break** — land the attack on Eiger. Objective + pass-when are on your lab card.
- **④ Secure** — flip **one** flag, run the **same** attack, watch it die. *The diff is the lesson.*
- **⑤ Reality check** — is this real in production? We test it live against **Anna**.

**You pass by mechanism, not the model's words** — grading queries an append-only audit log, never a string match. Core + stretch per module.

<!-- Notes: Every module runs on the same five beats, so you always know where we are. The middle two — Break and Secure — are the hands-on core, and we never cut Secure for time. One idea sits under all of it: we grade on mechanism, not on words. That's how a room full of people attacking a non-deterministic model still grades reliably — and it's exactly how you should instrument your own AI to detect these attacks. -->

---

## Meet Anna — the real app

Eiger is the lab. **Anna is a real production AI agent** — HubSpot, email, Slack, on Bedrock, with an autonomous planner→reviewer loop.

At **four points** across the two days we don't just theorise — we **drive Claude Code against Anna's real code, live**, and deliver a verdict: *is this attack real, or theater?*

> **Everything you break in the lab, we test against a real app. That's the method you take home.**

<!-- Notes: There's a through-line across both days: Anna. You raise the hypotheses, and we investigate live — at the chatbot and RAG layers, then again at MCP and multi-agent. This is the direct answer to the question I get every single time: "can I actually use this on my own systems?" Yes — and this is how. -->

---

## Your instructors — KK Mookhey

- **Transilience AI** · Los Altos, CA · ~25 years in cybersecurity.
- Focus: **AI security & adversarial AI**, cloud security (AWS/Azure), compliance & audit.
- **CISSP · CISA · PCI QSA · Azure Security Engineer.**
- Builds open security tooling (e.g. Project Shasta, AWS/Azure compliance).
- `linkedin.com/in/kkmookhey`

<!-- Notes: Thirty seconds on who's in front of you, then we start — you came here to break things, not to hear a résumé. -->

---

## Your instructors — Venkat Pothamsetty

- **Founder, Transilience AI** — building at the intersection of generative AI, cloud and security.
- Two decades in security engineering and product: **Cisco** (product manager, Infrastructure Security Services Group), **Threat Stack**, **Cofense**.
- Builds **autonomous security agents** — Transilience ships agentic pentest, vulnerability and compliance agents in production.
- Writes and speaks on LLM agent architectures, RAG for security, and the economics of agentic security work.
- **MBA**, The University of Texas at Austin.
- `linkedin.com/in/venkatpothamsetty`

<!-- Notes: And Venkat builds the agentic systems you're about to attack. The failure modes you'll hit on Day 2 aren't theoretical to him — he's seen them in production. -->

---

## To get the most out of today

- **Be patient with the shared lab.** It's one hosted instance for the whole room — under load, a reply may take a few seconds. That's queueing, **not** a failure. Re-run if needed.
- **Pick a lane.** Attack the hosted lab (zero setup) or take the **builder lane** — run the code on your laptop and build-break-secure it yourself. Switch anytime; setup is one page in `prereqs/`.
- **Day 2: bring a key.** OpenAI or Anthropic. Frontier models chain tool calls reliably; the keyless model demonstrates the mechanism but won't.
- **Use the sanctioned payloads for the graded run.** A cleverer attack can be *better* and still not score — grading checks a mechanism. Improvise after you've passed, and show us.

<!-- Notes: A few things to set your expectations. Responses can be slow — the model is shared, so give it a moment before you decide something's broken. And some of the payloads we hand you are sanctioned: if an attack works, you succeeded, you didn't out-smart a broken grader. Keep these in mind and you'll save yourself a lot of false alarms. -->

---

## Rules of the range

- Everything here is a **deliberately-vulnerable teaching lab**. These techniques are for **authorized testing only** — the skills are real, the consent is what makes them legal.
- Work at your own pace; instructors circulate — **raise a hand** anytime.
- Stuck on reach or a slow response? Flag it early; we fix it while the room warms up.

<!-- Notes: One line on ethics, and I'll say it plainly because this is Black Hat: everything here is for systems you're authorized to test. That's the line. Now — the reach-test and M0 are next. -->

---

## → Let's get on the range

Next: **M0 — Threat Model + Reach-Test**, then the **Gandalf** warm-up (a hosted game — self-serve link coming). Get green, then we start breaking things.

<!-- Notes: We go straight into M0. Gandalf is your self-serve warm-up — prompt injection and guardrail evasion in miniature, a preview of M1 and M8. Crack it early and there are harder Lakera games and Prompt Airlines waiting. The first fifteen minutes are all about momentum, so get your hands dirty. -->
