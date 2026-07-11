# Prerequisites & Setup

> **This page is a living document.** It will keep changing as we get closer to the course — check back before you travel. Training materials (slides, lab code, walkthroughs) will also land in **this same repo** as we build them out.

This is a hands-on course. You won't just *attack* Halcyon (our deliberately-vulnerable AI neobank) — you'll **read its code, break it, and then modify the code to secure it.** That "Build → Break → Secure" loop is the whole course, and it means you need to be able to edit and run the app, not just point a browser at it.

Here's everything to bring. One list — sort it all before you arrive.

---

## What to bring

1. **A laptop you fully control — with admin rights.** You'll install tools and **trust a CA certificate**, which locked-down corporate machines often block. If yours might, **bring a personal laptop.** This is the #1 blocker.

2. **Burp Suite Community Edition** (free) — with your browser proxied through it and its **CA certificate trusted.** We intercept and modify web traffic throughout the course. Setup steps below.

3. **An AI coding environment you're comfortable in** — **Claude Code**, **Cursor**, Windsurf, VS Code + Copilot, or whatever you prefer — signed in with whatever subscription or API key it needs. You'll use it to modify Halcyon's code during the Secure phase of each module, so bring the setup you're fastest in.

4. **Somewhere to run and deploy Halcyon as we go.** In order of preference:
   - **Your own cloud account** (AWS / GCP / Azure / DigitalOcean — anything you can spin small instances up on). Preferred: you'll deploy your modified app as we progress, which mirrors real work.
   - **Or run the Halcyon container we provide locally** — needs a container runtime (Docker Desktop or Podman).
   - A hosted fallback will be available if neither works on the day, but plan to run your own.

5. **An LLM API key — OpenAI or Anthropic — with $10–20 of credit.** Used once we reach the agent labs (reliable tool-calling). This can be the same key your AI coding environment uses. A rate-limited backup key pool is available in class for the occasional dead key, but bring your own.

6. **Run the reach-test before you arrive** (link below) to confirm you can reach the target and that your proxy + certificate work — so any issue surfaces at home, not in class.

7. **Recommended AI red-teaming tools** *(optional — pre-install for a head start on the later automation/defense labs; follow each project's README for install).* We'll point these at the hardened stack:
   - **PyRIT** (Microsoft) — automated red-team orchestration — <https://github.com/Azure/PyRIT>
   - **Promptfoo** — prompt & red-team evals at scale — <https://github.com/promptfoo/promptfoo>
   - **DeepTeam** (optional) — LLM red-teaming framework — <https://github.com/confident-ai/deepteam>
   - **P4RS3LT0NGV3** — payload obfuscation; **provided in class**, browser-based, nothing to install.
   - Fuller curated list → Basecamp [08 · Attacking-AI Tooling](https://github.com/kkmookhey/basecamp-ai-sec/blob/main/docs/topics/08-attacking-ai-tooling.md).

---

## Setup details

### Burp: install, proxy, trust the cert

1. **Install** Burp Suite Community from <https://portswigger.net/burp/communitydownload>. Launch it and start a temporary project with defaults. Confirm the proxy listener is on `127.0.0.1:8080` (Proxy → Proxy settings).
2. **Proxy your browser** at `127.0.0.1:8080`:
   - *Firefox (recommended):* Settings → Network Settings → Manual proxy → `127.0.0.1` port `8080`, tick "Also use this proxy for HTTPS."
   - *System proxy (Chrome/Edge/Safari):* set the system HTTP/HTTPS proxy to `127.0.0.1:8080`.
3. **Trust Burp's CA cert:** with the proxy on, browse to <http://burp>, download `cacert.der`, then install it as a trusted authority:
   - *Firefox:* Settings → Privacy & Security → Certificates → View Certificates → Authorities → Import → tick "Trust this CA to identify websites."
   - *macOS (system):* open the cert in Keychain Access → System keychain → "Always Trust."
   - *Windows (system):* import into "Trusted Root Certification Authorities" (Local Machine).
   - *Verify:* browse to any `https://` site with the proxy on — no certificate warning, and the request shows in Burp's **Proxy → HTTP history.**

### Reach-test

👉 **Reach-test link:** `[INSTRUCTOR: paste hosted reach-test URL]`

Open it with your browser proxied through Burp. Green means you can reach Halcyon, your traffic is flowing through Burp, and the certificate is trusted. Red is almost always the proxy or cert step above — fix it now, not in class.

### LLM API key

- **OpenAI** — key at <https://platform.openai.com/api-keys>, ~$20 credit. Models: `gpt-4o-mini` (default) / `gpt-4o` (upgrade).
- **Anthropic** — key at <https://console.anthropic.com/>, ~$20 credit. A current Haiku-class model by default, Sonnet-class as the upgrade.
- **Never** paste your key into a shared chat or commit it anywhere.

---

## Trouble?

- **Can't trust the CA cert / can't install tools:** almost always corporate device management. Sort it before you travel, or bring a personal laptop.
- **No cloud account:** you'll be able to run the provided container locally (needs Docker/Podman), and there's a hosted fallback — but your own cloud is the smoothest experience.
- **Reach-test red:** re-check the proxy listener and that HTTPS traffic shows in Burp's HTTP history.
- Stuck? Bring it to the pre-class setup window — we'll get you sorted before we start.
