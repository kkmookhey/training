<!--
Opener · Course intro + instructor bios + caveats — slide source
Render: paste this + _templates/slide-brief.md into Claude Design → opener.pptx
Convention: each slide separated by `---`; speaker notes in <!-- Notes: ... -->.
Runs FIRST, before M0. Keep it tight (~10 min) — the room wants to start breaking things.
TODO(KK): fill the Venkat bio slide (his LinkedIn 404'd; nothing was auto-filled).
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

| Day 1 — the model & its data | Day 2 — the model with hands |
|---|---|
| **L0** chatbot · prompt injection, output handling | **L2** agent · excessive agency + supply chain |
| **L1** RAG · knowledge-base poisoning | **L3** MCP · tool poisoning |
| (keyless — shared model) | **L4** multi-agent · cascading trust |
| | **L5** production · guardrails + capstone |

Day 1 runs **keyless** on a shared model. Day 2 is **BYOK** — bring your own key.

<!-- Notes: Set the BYOK expectation loudly and early — Day 2's agent/MCP/multi-agent labs need a frontier model to reliably chain tool calls; the keyless model shows the plumbing but won't autonomously follow a poisoned tool description. Anyone without a key: pair up or use the keyless floor to watch the mechanism. -->

---

## How every module works

- **Hosted lab** — nothing to install; reach-test is screen 1.
- **Build → Break → Secure**, each module.
- Two levels per module: **L1 = vulnerable**, **L2 = secure**. Flip one flag, run the *same* attack, watch it die.
- **You pass by mechanism, not by the model's words** — grading queries an append-only audit log, never a string match on the reply. Each module has a **core** objective and a **stretch**.

<!-- Notes: The "mechanism, not words" point is the intellectual spine — say it now and repeat it whenever a model phrases something oddly. It's *why* the labs are reproducible despite a non-deterministic model, and it's a real lesson for how to build test/detection for AI systems. -->

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

- **[Role / company — TODO]**
- **[Areas of expertise — TODO]**
- **[Notable credentials / accomplishments — TODO]**
- `linkedin.com/in/venkatpothamsetty`

<!-- Notes: TODO(KK): paste Venkat's bio — his LinkedIn URL 404'd so nothing was auto-filled. Nothing here is invented. -->

---

## To get the most out of today

- **Be patient with the shared lab.** It's one hosted instance for the whole room — under load, a reply may take a few seconds. That's queueing, **not** a failure. Re-run if needed.
- **Run it locally if you can.** For the snappiest experience, run Eiger and/or the concept demos on your laptop — one-page setup in the repo README (link on the reach-test screen).
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

Next: **M0 — Threat Model + Reach-Test.** Get green, then we start breaking things.

<!-- Notes: Hard cut to M0. Momentum is everything in the first 15 minutes. -->
