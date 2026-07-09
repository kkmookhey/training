# Pre-read email — draft

> Draft for KK to send to registered participants. Swap the `[bracketed]` bits. The setup link only works once this branch is merged to `main`.

---

**Subject:** Your Black Hat course — 20 minutes of setup before we start

Hi [first name],

Looking forward to having you in **Adversarial AI — Red Teaming the AI Supply Chain** at Black Hat next month. This is a hands-on course — we spend most of the two days attacking and defending a live target, not sitting through slides — so a little setup ahead of time keeps us hacking instead of installing on day one.

**Please do this before you arrive** (≈20 minutes, plus one download):

👉 **Setup guide:** https://github.com/kkmookhey/training/tree/main/blackhat-2026-adversarial-ai/prereqs

Two things to sort out:

1. **Day 1 runs on your own machine, offline and keyless.** You'll install Docker and a small local model (a one-time ~5 GB download — do it on home WiFi, not the conference network).
2. **Day 2 uses your own LLM API key** (OpenAI or Anthropic) with **$10–20** of credit. Instructions and the exact models are in the guide.

**Two things that trip people up — check them early:**

- **Corporate laptops** often block Docker. If yours might, sort it now or bring a personal machine.
- **Do the model download at home.** Don't count on Black Hat WiFi for 5 GB.

You don't need to download the lab itself — you'll get it on a **USB drive at the venue**, and the very first screen checks your setup is green in about a minute.

If you hit a wall, reply to this email and we'll get you sorted before the class starts.

See you in Vegas,
KK

[KK Mookhey · signature]

---

## Checklist for KK before sending
- [ ] Merge the `restructure/blackhat-2026` PR so the setup link resolves on `main`.
- [ ] Confirm the venue/date line if you want it in the email.
- [ ] Confirm both API providers are acceptable (guide currently lists OpenAI + Anthropic).
