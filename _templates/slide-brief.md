# Slide house-style brief

Paste this into Claude Design **alongside a module's `slides/mN.md`** to render `mN.pptx`. Goal: 8 decks that look like one course, and stay light.

## Delivery

- Bookend every deck with the **Black Hat trainer title + end slides** (KK has the `USA26-Trainer Template …TITLE AND END SLIDE ONLY.pptx`). The module content sits between them.
- Export `.pptx` (Black Hat accepts pptx or PDF — either is fine).

## Typography

- **Display / titles:** `BlackHatDrukTT-Medium` (installed locally on KK's machine; **not shipped in this public repo** — it's a licensed Black Hat asset).
- **Body:** a clean sans (Inter / Helvetica Neue / Arial). Only the Druk **Medium** weight exists — use it for display only, never body.

## Palette

- Background: near-black `#0B0B0B`.
- Primary text: off-white `#F2F2F2`.
- Accent: Black Hat green `#8CC63F` (or the exact green from the trainer template). Use sparingly — one accent per slide.
- Danger/attacker highlight: red `#E5484D` for exploit payloads / "compromised" states.

## Layout rules (light + demo-first)

- **One idea per slide.** If a slide has more than ~15 words of body text, split it.
- Prefer a big statement + one supporting line over bullet lists. Max 3 bullets if you must.
- Every hands-on beat gets a **`→ DEMO`** divider slide (accent color, big label) so KK knows to leave the deck.
- Code/payloads: monospace, red accent, only the lines that matter.
- Diagrams only when they carry meaning (e.g. the supply-chain layer stack, an agent/tool call flow). No decorative clip-art.
- Speaker notes carry the detail — keep them in the `.md` so the on-screen slide stays sparse.

## Layout types to support

1. **Title** (BH template) — course/module name.
2. **Section divider** — module number + title, accent bar.
3. **Concept** — one statement, one support line, optional small diagram.
4. **Demo callout** — `→ DEMO` + what to watch for.
5. **Payload** — monospace attacker input, red accent.
6. **End** (BH template) — thanks / contact.
