# Eiger — the lab platform

Deliberately-vulnerable single app that participants Build/Break/Secure across all modules. **Eiger** is an AI-first neobank; its assistant **Iggy** grows attack surface each module (L0 chatbot → L1 RAG → L2 agent → L3 MCP → L4 multi-agent → L5 production).

**Deployment:** hosted, **container-per-participant**, with a **shared Ollama** backend and an **external progress store**; the same images **dual-deploy to cloud (primary) and a local-LAN server (fallback)**. Not on participant laptops.

**Status:** M1–M8, the Treasury Heist capstone, and the learner-guided UI are built. The current app provides stable sessions, per-module **Vulnerable/Hardened** controls, objectives, validation/reset, learner progress, and a human-readable class attack board. Active engineering status lives in the app repo's `docs/STATUS.md`; historical design context remains in `halcyon-lab-spec.md` and the versioned specs/plans.

**Design doctrine (load-bearing):**
1. Validate the *mechanism*, not the model's words — pass/fail is a query against an append-only audit log.
2. One build + `SEC_*` security flags — `vulnerable` vs `secure` is a config flag; the diff is the lesson.
3. Ollama floor (Day 1, keyless, shared backend) · BYOK ceiling (Day 2). Both days online.
4. Deterministic + resettable + self-service — `/validate/{module}`, `/reset/{module}`, readiness on screen 1.

**Current learner flow:** readiness → guided M1–M8 panels → per-module defence retest → `/progress`; the separate **Capstone — Treasury desk** challenge closes the course. M8 remains as a compact 25–35 minute **Production Guardrails & Evasion** exercise, with hardened bypasses treated as an ungraded residual-risk bonus.

**Connectivity is the single point of total failure** — hence dual-deploy (cloud → local-LAN → hotspot). See `OPERATIONS.md` for the operator runbook.
