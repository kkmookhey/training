# M9 · Training-Data Extraction

> **One-line premise:** the model remembers what you trained it on — but the data you are liable for is in the corpus, not the weights.
> **OWASP:** LLM02 / LLM08 · **Eiger layer:** none (off-spine) · **Model tier:** none

## Why this module exists

Participant feedback from both Aug 2026 batches said extracting training data was never covered.
That was correct. **M8 covers *model extraction* and *membership inference*** — different attacks
with different outputs:

| Attack | Question | Returns | Covered in |
|---|---|---|---|
| Model extraction | can I rebuild your model? | a copy of the model | M8 |
| Membership inference | was record X in training? | one bit | M8 |
| **Training-data extraction** | **what was in training?** | **the data, verbatim** | **M9** |

## Objectives

- **Core (everyone):** distinguish the three attacks above, and know which extraction risk is
  the vendor's and which is yours.
- **Stretch:** none. This is a bonus deck.

There is **no graded objective** — no `/validate/m9`, no `SEC_*` flag, no audit event.

## Run-of-show (~35–45 min)

| Act | Beat | Slides |
|-----|------|--------|
| 0 | Hook + disambiguating the three attacks | 1–4 |
| 1 | Foundation-model memorisation — Carlini 2021, Nasr 2023 | 5–8 |
| — | **The turn** — none of that is yours to fix | 9 |
| 2 | Your fine-tune set — Secret Sharer, canaries, exposure | 10–11 |
| 3 | Your retrieval corpus — extraction without memorisation | 12–15 |
| 4 | Defences by layer, erasure, the lesson to name | 16–19 |

Slide 20 is further reading. **Do not reorder — the thesis only lands because the room spends
ten minutes on the famous version first.**

## Demos

None. This deck is slides only, deliberately:

- the Nasr divergence attack is **patched** in production
- demonstrating foundation-model memorisation needs a model that already memorised something
  you can legally show on stage

Compensated with **reproduced outputs from the papers** on slides 6–7.

## Validation

Not applicable — no lab. The M3 callback on slide 15 reuses an attack participants already ran.

## Further reading

- Carlini et al., *Extracting Training Data from LLMs*, USENIX Security 2021 (arXiv 2012.07805)
- Nasr, Carlini et al., *Scalable Extraction of Training Data from (Production) LMs* (arXiv 2311.17035)
- Carlini et al., *The Secret Sharer*, USENIX Security 2019 (arXiv 1802.08232)
- Carlini et al., *Quantifying Memorization* (arXiv 2202.07646) · Lee et al., *Deduplicating Training Data* (arXiv 2107.06499)
- Qi et al., *Follow My Instruction and Spill the Beans* — RAG datastore extraction (arXiv 2402.17840)
