# Pre-read email — draft (revised for hosted model)

> Draft for KK to send to registered participants. Swap the `[bracketed]` bits. The setup + reach-test links only work once the branch is merged to `main` and the hosted instance is live.

---

**Subject:** Your Black Hat course — 15 minutes of setup before we start

Hi [first name],

Looking forward to having you in **Adversarial AI — Red Teaming the AI Supply Chain** at Black Hat next month. This is a hands-on course — we spend most of the two days attacking and defending a live target, not sitting through slides — so a little setup ahead of time keeps us hacking instead of installing on day one.

Good news: **nothing heavy to install, nothing to download in advance.** The target runs on our infrastructure — you reach it from your browser. You just need a laptop you fully control and one free tool.

**Please do this before you arrive** (~15 minutes):

👉 **Setup guide:** https://github.com/kkmookhey/training/tree/main/blackhat-2026-adversarial-ai/prereqs

1. **Bring a laptop you can install software on — and add a CA certificate to.** This is the one that matters. We intercept and modify web traffic throughout the course, which needs Burp's certificate trusted in your browser. Locked-down corporate laptops often block that. If yours might, **bring a personal machine.**
2. **Install Burp Suite Community Edition** (free) and route your browser through it. The guide walks you through the proxy setup and the CA certificate — the same setup powers the warm-up labs.
3. **Day 2 only: bring your own LLM API key** (OpenAI or Anthropic) with **$10–20** of credit. Day 1 needs no key. Exact models are in the guide.
4. **Reach-test before you arrive.** The guide has a link that confirms you can reach the target and that your proxy is working — green in about a minute. Do it at home so any cert/proxy issue surfaces before class, not during it.

**What trips people up:**

- **Admin rights.** Installing Burp and trusting its certificate needs a machine you control. Sort this now.
- **The proxy/cert step.** Run the reach-test early — it's the one thing worth checking twice.

You'll need **internet in the room** (the venue provides it; a phone hotspot is a fine backup). **No Docker, no big downloads, no USB** — just a browser, Burp, and on Day 2 your key.

If you hit a wall, reply to this email and we'll get you sorted before the class starts.

See you in Vegas,
KK

[KK Mookhey · signature]

---

## Checklist for KK before sending
- [ ] Merge the `restructure/blackhat-2026` PR so the setup + reach-test links resolve on `main`.
- [ ] Confirm the hosted instance + reach-test endpoint are live.
- [ ] Confirm venue/date line if you want it in the email.
- [ ] Confirm both API providers are acceptable (guide currently lists OpenAI + Anthropic).
