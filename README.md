# Training

Hands-on security training materials by [KK Mookhey](https://github.com/kkmookhey). One folder per training; each training breaks into modules with slides, code, and demos.

> **Philosophy:** hands-on and demo-first. Slides are light signposts — the code and live demos carry the teaching.

## Trainings

| Training | When | Description |
|----------|------|-------------|
| [Adversarial AI — Red Teaming the AI Supply Chain](blackhat-2026-adversarial-ai/) | Black Hat USA, Aug 2026 | 2-day course: attacking and defending the LLM supply chain — model → RAG → agents → MCP → multi-agent → production. |

## How this repo is organized

```
<training-name>/
├── README.md          # overview, schedule, prereqs
├── prereqs/           # what participants install/bring before day 1
└── M<n>-<topic>/
    ├── README.md      # objectives, run-of-show, further reading
    ├── slides/        # <module>.md (source) + <module>.pptx (rendered)
    └── code/          # runnable demos and exploits
```

`_templates/` holds reusable scaffolding (slide house-style brief, module README skeleton).

## Curated reading

Links and further reading live in **[Basecamp](https://github.com/kkmookhey/basecamp-ai-sec)** — a curated map of the AI + cybersecurity intersection. Modules point into Basecamp topics rather than duplicating link lists.
