# Prerequisites & Setup

Complete this **before Day 1**. It's light — the target runs on our infrastructure, so there's **nothing heavy to install and nothing to download in advance.** You reach Halcyon from your browser.

The one thing that matters: a laptop you fully control, with a browser proxied through **Burp** and Burp's **CA certificate trusted.** We intercept and modify web traffic throughout the course, so this has to work.

- **Day 1** — keyless. You attack a hosted target through your browser + Burp. No API key.
- **Day 2** — bring your own LLM API key (agent labs need reliable tool-calling).

---

## Laptop requirements

- **OS:** macOS, Windows 10/11, or Linux.
- **Admin rights** — you must be able to install Burp and **trust a CA certificate** in your browser. This is the real gate. Locked-down corporate laptops often block certificate trust; if yours might, **bring a personal machine.**
- A modern browser (Firefox is easiest for a dedicated proxy profile; Chrome/Edge are fine).
- **Internet in the room** — the venue provides it; a phone hotspot is a fine backup (and is all Day-2 BYOK needs).
- **Gone from the old prereqs:** Docker, the local model download, the USB drive.

---

## Step 1 — Install Burp Suite Community Edition (free)

Download from <https://portswigger.net/burp/communitydownload> and install. Launch it, and start a temporary project with the default settings. Confirm the proxy listener is running on `127.0.0.1:8080` (Proxy → Proxy settings).

## Step 2 — Route your browser through Burp

Point your browser's HTTP/HTTPS proxy at `127.0.0.1:8080`.

- **Firefox (recommended):** Settings → Network Settings → Manual proxy → `127.0.0.1` port `8080`, tick "Also use this proxy for HTTPS."
- **System proxy (Chrome/Edge/Safari):** set the system HTTP/HTTPS proxy to `127.0.0.1:8080`.

## Step 3 — Trust Burp's CA certificate

With the proxy on, browse to **<http://burp>** and download the CA certificate (`cacert.der`). Then install it as a trusted authority:

- **Firefox:** Settings → Privacy & Security → Certificates → View Certificates → Authorities → Import → tick "Trust this CA to identify websites."
- **macOS (system):** open the cert in Keychain Access → System keychain → set to "Always Trust."
- **Windows (system):** import into "Trusted Root Certification Authorities" (Local Machine).

Verify: browse to any `https://` site with the proxy on and confirm **no certificate warning** and that the request appears in Burp's **Proxy → HTTP history.** If you see it in Burp with no browser warning, you're set.

---

## Step 4 — Reach-test (do this at home)

Confirm you can reach the target and that your proxy + cert are working, **before** you arrive:

👉 **Reach-test link:** `[INSTRUCTOR: paste hosted reach-test URL]`

Open it with your browser proxied through Burp. Green means: you can reach Halcyon, your traffic is flowing through Burp, and the certificate is trusted. If it's red, the fix is almost always the proxy or cert step above — sort it now, not in class.

---

## Day 2 — LLM API key

Day 2 labs (agents, MCP, multi-agent) use **your own API key** for reliable tool-calling. Budget **$10–20** of credit — the labs are cheap; this is a comfortable ceiling.

Use **either** provider:

- **OpenAI** — key at <https://platform.openai.com/api-keys>, ~$20 credit. Models: `gpt-4o-mini` (default) / `gpt-4o` (upgrade).
- **Anthropic** — key at <https://console.anthropic.com/>, ~$20 credit. A current Haiku-class model by default, Sonnet-class as the upgrade.

**Never paste your key into a shared chat or commit it anywhere.** A rate-limited backup key pool is available in class for the occasional dead key — but bring your own.

---

## Trouble?

- **Can't trust the CA cert:** almost always corporate device management. Sort it before you travel, or bring a personal laptop. This is the #1 blocker now.
- **Reach-test red:** re-check the proxy listener (Step 1) and that HTTPS traffic shows in Burp's HTTP history (Step 3).
- Stuck? Bring it to the pre-class setup window — we'll get you green before we start.
