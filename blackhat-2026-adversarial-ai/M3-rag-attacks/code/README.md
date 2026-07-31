# M3 RAG - Concept Demo Runbook

The build-first companion for M3. You run this **before** the Eiger lab to show,
under the hood, what a RAG pipeline is and how a poisoned document hijacks it.

**Run mode:** command line only. No Streamlit, no Claude Desktop, no MCP Inspector.
**API key:** none. Embeddings run locally; the LLM runs on the shared Ollama.
**Status:** verified end-to-end on 2026-07-30 (llama3.1:8b) — clean answer + poison
break both confirmed. Deps in `requirements.txt` are pinned to the tested versions.

> Note: `bot.py` assembles the RAG prompt by hand (retrieve → build prompt →
> generate) rather than using the deck slide's `RetrievalQA` chain, which was
> removed from LangChain 1.x. The manual version is more robust *and* prints the
> exact prompt the model sees — which reinforces the slide's own point.

---

## 0. One-time setup (do this before the session, not on stage)

```bash
cd M3-rag-attacks/code
python -m venv venv
source venv/bin/activate            # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

Make sure Ollama is reachable and the model is present. The `ollama` CLI is not
always on PATH (server can run via the app or Docker), so check with `curl` -
it works regardless:

```bash
curl -s http://localhost:11434/api/tags   # lists installed models
```

If `llama3.1:8b` isn't listed and you do have the CLI: `ollama pull llama3.1:8b`.

- Demoing on your own laptop? Leave defaults (`http://localhost:11434`).
- Using the room's shared Ollama? `export OLLAMA_BASE_URL=http://<shared-host>:11434`

> First run of `bot.py`/`ingest.py` downloads the MiniLM embedding model (~90 MB,
> ~30s). Do it once during setup so it's cached and instant on stage.

---

## 1. BUILD - index the clean knowledge base

```bash
python ingest.py
```

You'll see `LOAD -> SPLIT -> EMBED -> STORE`. This is the deck's Indexing phase, live.

## 2. QUERY - watch retrieval work

```bash
python bot.py
```

Ask a normal question:

```
you > What is the policy on remote work?
```

Point at the **retrieved chunks** printed under the answer. That's the money line:
the model saw those chunks pasted in *verbatim*. RAG stops being magic here.

## 3. BREAK - poison a document (indirect injection)

Drop the poisoned doc into the corpus and re-index:

```bash
cp poison.txt docs/
python ingest.py
python bot.py
```

Ask the **same innocent question**:

```
you > What is the policy on remote work?
```

The poisoned chunk lands in the retrieved list, and a weak model obeys the hidden
instruction (the fake "VPN expired" message) instead of answering. Nobody typed
anything malicious into the question - that's indirect prompt injection.

> If the model resists (frontier models often do), don't fight it - that's the
> teaching point. Say so, then hand off to the Eiger lab where the grade is a
> mechanism check (`poisoned_chunk_in_context`), not the model's mood.

## 4. RESET - back to clean

```bash
rm -rf chroma_db docs/poison.txt
python ingest.py
```

---

## Hand-off line to the Eiger lab

> "That was one bot, one user, and I proved it by eyeballing the reply. Now do it
> where it's graded, multi-session, and the payload you plant trips **someone
> else's** question."

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| Hangs ~30s on first run | MiniLM embedding model downloading; one-time, pre-cache in setup |
| `Connection refused` | Ollama not running / wrong `OLLAMA_BASE_URL`. Check `curl -s $OLLAMA_BASE_URL/api/tags` |
| `model not found` | Confirm via `curl -s http://localhost:11434/api/tags`; pull with the CLI or set `OLLAMA_MODEL` to one you have |
| Empty / irrelevant answers | Re-run `python ingest.py`; confirm `docs/` has content |
| Poison ignored | Expected on strong models - it's a feature, not a bug. See step 3 note |

## Environment variables

| Var | Default | Purpose |
|---|---|---|
| `OLLAMA_MODEL` | `llama3.1:8b` | which model bot.py uses |
| `OLLAMA_BASE_URL` | `http://localhost:11434` | shared Ollama endpoint |
| `DOCS_DIR` | `docs` | folder ingest.py reads |
| `CHROMA_DIR` | `./chroma_db` | where vectors persist |
