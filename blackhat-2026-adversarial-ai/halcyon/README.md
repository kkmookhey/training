# Halcyon — the lab platform

Deliberately-vulnerable single app that participants Build/Break/Secure across all modules. **Halcyon** is an AI-first neobank; its assistant **Halo** grows attack surface each module (L0 chatbot → L1 RAG → L2 agent → L3 MCP → L4 multi-agent → L5 guardrails).

**Status:** not built yet. Full build spec lives in the planning workspace (`halcyon-lab-spec.md`). Built last, after module content (Phase 3).

**Design doctrine (load-bearing):**
1. Validate the *mechanism*, not the model's words — pass/fail is a query against an append-only audit log.
2. One build + `SEC_*` security flags — `vulnerable` vs `secure` is a config flag; the diff is the lesson.
3. Ollama floor (Day 1, keyless) · BYOK ceiling (Day 2).
4. Deterministic + resettable + self-service — `/validate/{module}`, `/reset/{module}`, pre-flight checker on screen 1.

Distributed on **USB at the venue** — never depends on conference WiFi.
