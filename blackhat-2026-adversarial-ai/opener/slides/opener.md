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

<!-- Notes: Warm open. One sentence: for two days you will attack one AI application across every layer it's built from, then secure each one. Set the tone now — this is a lab, not a lecture; you'll spend most of your time in the browser breaking things. -->

---

## One target. Two days. Three verbs.

You attack **one** fictional AI-first neobank — **Eiger** — and its assistant **Iggy**.

Its attack surface **grows each module**, layer by layer:

```
L0 chatbot → L1 RAG → L2 agent → L3 MCP → L4 multi-agent → L5 production
```

For every layer you **Build** it, **Break** it, then **Secure** it.

<!-- Notes: The single-target, growing-surface design is the whole pedagogy — one coherent story instead of eight disconnected toys. "Build/Break/Secure" is the rhythm of every module. Say it once here and they'll recognise it all day. -->

---

## The two-day arc

| Day 1 — the model & its data *(keyless)* | Day 2 — the model with hands *(BYOK)* |
|---|---|
| **F0** understanding LLMs | **L3** MCP · tool poisoning |
| **L0** chatbot · prompt injection, output handling | **L4** multi-agent · cascading trust |
| **L1** RAG · knowledge-base poisoning | **L5** production · guardrails + capstone |
| **L2** agent · excessive agency + supply chain | |

Warm up on **Gandalf**, then Day 1 runs **keyless** on a shared model. Day 2 is **BYOK** — bring your own key.

<!-- Notes: This mirrors the run of show exactly. Day 1 is the model and its data — F0 foundations, then L0 chatbot (M1 injection, M2 output), L1 RAG (M3), L2 agent (M4 supply chain, M5 excessive agency) — all keyless on the shared model. Day 2 is the model with hands — L3 MCP (M6), L4 multi-agent (M7), L5 production + the AI-vs-AI finale (M8). Set BYOK loudly: M6's poisoning and the finale need a frontier key to chain tool calls reliably; keyless llama shows the plumbing and is actually the more reliable choice for M5/M7. Anyone without a key: pair up. -->

<!-- Notes(cont.): Note L2 (agent) is on Day 1 and runs keyless — M5 is a simple single tool-call the shared model handles. The BYOK line is really about M6 and the finale. -->


---

## Two ways to play — pick your lane

| 🗡 **Attacker** | 🔧 **Builder** |
|---|---|
| Hit the **hosted** Eiger from your browser | **Clone** the repo, run the module's code on your laptop |
| Zero setup — the default | Build → Break → Secure the **real guard code** yourself |
| Fast: just attack | Flip the `SEC_*` flag in the source, watch the attack die locally |

Switch lanes **any module**. Builders: setup is one page in `prereqs/`.

<!-- Notes: New for this cohort — name the builder lane as a real choice, not a footnote. Most will attack the hosted app; the ~third who want a methodology to take home run the code locally and read the actual guard. The builder lane is the on-ramp to the same Claude-Code-against-real-code method you'll watch with Anna — the direct answer to "can I use this in my own environment?" -->

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

<!-- Notes: This is the spine of the rebuilt flow — same five beats every module, so nobody's lost about where we are. ③/④ are the hands-on core; ④ (Secure) is never sacrificed for time. ⑤ (Anna) lands at four points across the two days. "Mechanism not words" is why 32 people attacking a non-deterministic model grades reliably — and it's how they should instrument their own AI for detection. -->

---

## Meet Anna — the real app

Eiger is the lab. **Anna is a real production AI agent** — HubSpot, email, Slack, on Bedrock, with an autonomous planner→reviewer loop.

At **four points** across the two days we don't just theorise — we **drive Claude Code against Anna's real code, live**, and deliver a verdict: *is this attack real, or theater?*

> **Everything you break in the lab, we test against a real app. That's the method you take home.**

<!-- Notes: The through-line and the energiser — introduce Anna now (Anchor 1). The room raises hypotheses and we investigate live at L0/L1, then L3 (MCP) and L4 (multi-agent). This is the direct answer to the recurring ask — "can I use this in my own environment?" — yes, and this is exactly how. Keep the intro to a minute; the payoff is the live investigations. -->

---

## Your instructors — KK Mookhey

- **Transilience AI** · Los Altos, CA · ~25 years in cybersecurity.
- Focus: **AI security & adversarial AI**, cloud security (AWS/Azure), compliance & audit.
- **CISSP · CISA · PCI QSA · Azure Security Engineer.**
- Builds open security tooling (e.g. Project Shasta, AWS/Azure compliance).
- `linkedin.com/in/kkmookhey`

<!-- Notes: [KK — verified from your LinkedIn; add any career/founding highlights you want here, e.g. earlier ventures.] Keep it to 30 seconds; the room cares more about what they'll do today than your CV. -->

---

## Your instructors — Venkat Pothamsetty

- **Founder, Transilience AI** — building at the intersection of generative AI, cloud and security.
- Two decades in security engineering and product: **Cisco** (product manager, Infrastructure Security Services Group), **Threat Stack**, **Cofense**.
- Builds **autonomous security agents** — Transilience ships agentic pentest, vulnerability and compliance agents in production.
- Writes and speaks on LLM agent architectures, RAG for security, and the economics of agentic security work.
- **MBA**, The University of Texas at Austin.
- `linkedin.com/in/venkatpothamsetty`

<!-- Notes: Venkat: 30 seconds, same as KK. Frame the credibility that matters for this room — you build the agentic systems the class is about to attack, so the failure modes in Day 2 are ones you have hit in production. -->

---

## To get the most out of today

- **Be patient with the shared lab.** It's one hosted instance for the whole room — under load, a reply may take a few seconds. That's queueing, **not** a failure. Re-run if needed.
- **Pick a lane.** Attack the hosted lab (zero setup) or take the **builder lane** — run the code on your laptop and build-break-secure it yourself. Switch anytime; setup is one page in `prereqs/`.
- **Day 2: bring a key.** OpenAI or Anthropic. Frontier models chain tool calls reliably; the keyless model demonstrates the mechanism but won't.
- **Use the sanctioned payloads for the graded run.** A cleverer attack can be *better* and still not score — grading checks a mechanism. Improvise after you've passed, and show us.

<!-- Notes: These four set expectations that prevent 80% of "is it broken?" moments. The patience point especially — name it before the first slow response, not after. The sanctioned-payload point saves people from concluding they failed when they actually out-attacked the grader. -->

---

## Rules of the range

- Everything here is a **deliberately-vulnerable teaching lab**. These techniques are for **authorized testing only** — the skills are real, the consent is what makes them legal.
- Work at your own pace; instructors circulate — **raise a hand** anytime.
- Stuck on reach or a slow response? Flag it early; we fix it while the room warms up.

<!-- Notes: The ethics line matters at Black Hat — say it plainly. Then get out of the way: the reach-test and M0 are next. -->

---

## → Let's get on the range

Next: **M0 — Threat Model + Reach-Test**, then the **Gandalf** warm-up (a hosted game — self-serve link coming). Get green, then we start breaking things.

<!-- Notes: Hard cut to M0. Gandalf is the self-serve warm-up — prompt injection + guardrail evasion in miniature, foreshadowing M1 and M8; anyone who cracks it early moves to the other Lakera games or Prompt Airlines. Momentum is everything in the first 15 minutes. -->
