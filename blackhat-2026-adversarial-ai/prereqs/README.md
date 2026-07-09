# Prerequisites & Setup

Complete this **before Day 1**. Do the downloads on your home/office network — **do not rely on conference WiFi.**

Two setup tasks:

- **Task A (required for Day 1):** Docker + a local model. Day 1 is fully **keyless and offline**.
- **Task B (required for Day 2):** your own LLM API key. Day 2's agent labs need reliable function-calling.

You can do the course even if your API key isn't sorted by Day 1 morning — Day 1 doesn't use it. But please have both done before you arrive.

---

## Laptop requirements

- **OS:** macOS, Windows 10/11 (with WSL2), or Linux.
- **RAM:** 16 GB minimum (8 GB will struggle to run the local model + Docker together).
- **Disk:** ~20 GB free.
- **Admin rights** to install software.
- Ability to run Docker (corporate-locked laptops are the #1 problem — check this early).

---

## Task A — Docker + local model (Day 1)

### 1. Install Docker Desktop
Download and install from <https://www.docker.com/products/docker-desktop/>. Launch it once and confirm it runs:
```bash
docker --version
```

### 2. Install Ollama
Download from <https://ollama.com/download> and install. Confirm:
```bash
ollama --version
```

### 3. Pull the course model (~5 GB download)
```bash
ollama pull llama3.1:8b-instruct-q4_K_M
```
Verify it runs and responds:
```bash
ollama run llama3.1:8b-instruct-q4_K_M "Say hello in one word."
```
You should get a one-word reply. Type `/bye` to exit.

> The lab itself (Halcyon) is handed out on **USB at the venue** — you don't need to download it now. This step just makes sure your machine can run the local model it uses.

---

## Task B — LLM API key (Day 2)

Day 2 labs (agents, MCP, multi-agent) need reliable tool-calling, so they use **your own API key**. Budget **$10–20** of credit — the labs are cheap, this is a comfortable ceiling.

Use **either** provider:

- **OpenAI** — create a key at <https://platform.openai.com/api-keys>, add ~$20 credit. Models used: `gpt-4o-mini` (default) / `gpt-4o` (if a lab needs more muscle).
- **Anthropic** — create a key at <https://console.anthropic.com/>, add ~$20 credit. A current Haiku-class model by default, Sonnet-class as the upgrade.

Keep the key handy for Day 2. **Never paste your key into a shared chat or commit it anywhere.**

---

## Pre-flight check

When you receive Halcyon at the venue, **Screen 1 is a pre-flight checker** — it verifies Docker, your model, and (Day 2) your key in ~60 seconds, green or red. If it's red, grab an instructor.

To sanity-check your machine *now*, before the venue:
```bash
docker --version        # prints a version
ollama run llama3.1:8b-instruct-q4_K_M "hi"   # prints a reply
```

If both work, you're ready for Day 1.

---

## Trouble?

- **Docker won't install / is blocked:** almost always corporate device management. Sort it before you travel, or bring a personal laptop.
- **Model download slow:** it's a one-time ~5 GB pull — do it on good WiFi ahead of time.
- Stuck? Bring it to the pre-class setup window; we'll get you green before we start.
