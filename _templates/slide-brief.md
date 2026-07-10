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

## Density: two tiers

Match density to the module's job — this is the calibration that matters:

- **Framing / warm-up modules (M0):** *light.* One idea per slide, big statement + one support line, `→ DEMO` dividers. Slides are signposts; detail lives in notes.
- **Technical modules (M1–M8):** *dense and technical.* The on-slide content must carry real substance — definitions, taxonomies, **actual payloads/code**, defense scorecards, named research, and concrete mechanism. Aim for ~25–35 slides per 90-min module. Speaker notes still add colour, but a participant reading only the slides should get the technical meat. (Rule of thumb: 2–3× the density of a framing deck.)

Both tiers stay **demo-first** — every hands-on beat gets a `→ DEMO` divider so KK knows to leave the deck.

## Layout rules

- **One idea per slide** still holds — "dense" means substantive tables/code/taxonomies, not walls of prose. Split when a slide does two jobs.
- Code/payloads: monospace, red accent, only the lines that matter.
- Prefer **tables and labelled diagrams** to carry technical content (taxonomy, defense scorecard, attack→bypass, layer stack, call flow). No decorative clip-art.
- **Cite real sources on-slide** where a claim leans on research (author + year), and add a Basecamp reference line on the key slides.
- Close every technical module with a **Further reading** slide linking the matching Basecamp topic page.

## Layout types to support

1. **Title** (BH template) — course/module name.
2. **Section divider** — module number + title, accent bar.
3. **Concept** — one statement, one support line, optional small diagram.
4. **Taxonomy / scorecard** — a table carrying technical content (attack types, defense→bypass). Core to technical decks.
5. **Demo callout** — `→ DEMO` + what to watch for.
6. **Payload** — monospace attacker input, red accent.
7. **Mechanism diagram** — labelled boxes/flow (e.g. the flat token stream, a call graph).
8. **Further reading** — Basecamp topic link + must-read sources.
9. **End** (BH template) — thanks / contact.
