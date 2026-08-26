# M9 · Training-Data Extraction

> **One-line premise:** the model remembers what you trained it on — but the data you are liable for is in the corpus, not the weights.
> **OWASP:** LLM02 / LLM08 · **Eiger layer:** none (off-spine) · **Model tier:** none


## Objectives

- **Core (everyone):** distinguish the three attacks above, and know which extraction risk is
  the vendor's and which is yours.
- **Stretch:** none. This is a bonus deck.

There is **no graded objective** — no `/validate/m9`, no `SEC_*` flag, no audit event.

## Demos

None. This deck is slides only, deliberately

## Validation

Not applicable — no lab. The M3 callback on slide 15 reuses an attack participants already ran.

## Further reading

- Carlini et al., *Extracting Training Data from LLMs*, USENIX Security 2021 (arXiv 2012.07805)
- Nasr, Carlini et al., *Scalable Extraction of Training Data from (Production) LMs* (arXiv 2311.17035)
- Carlini et al., *The Secret Sharer*, USENIX Security 2019 (arXiv 1802.08232)
- Carlini et al., *Quantifying Memorization* (arXiv 2202.07646) · Lee et al., *Deduplicating Training Data* (arXiv 2107.06499)
- Qi et al., *Follow My Instruction and Spill the Beans* — RAG datastore extraction (arXiv 2402.17840)
