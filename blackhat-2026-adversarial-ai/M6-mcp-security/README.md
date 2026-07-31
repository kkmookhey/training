# M6 · MCP Security

> **One-line premise:** the tools Iggy trusts describe themselves — poison the description, own the agent.
> **OWASP:** — · **Eiger layer:** L3 · **Model tier:** BYOK

## Objectives
- **Core (everyone):** tool-description poisoning — a hidden instruction in a tool description makes Iggy leak data / call an unintended tool.
- **Stretch (pick one):** rug pull · tool shadowing · token theft.

## Run-of-show (~75 min)
| Phase | What happens |
|-------|--------------|
| Build | MCP servers (core-banking + CRM) whose tool descriptions are trusted verbatim; tokens stored loosely |
| Break | hide an instruction in a description; (stretch) mutate post-approval, shadow a tool, or read a token |
| Secure | flip `SEC_MCP_DESC_PINNING` + `SEC_MCP_TOKEN_SCOPING`; hash descriptions at approval, isolate tokens |

## Demos
- `code/` — a poisoned tool description; description-hash pinning before/after. *(Patterns sourced from DVMCP + mcp-breach-to-fix — ported, never run raw.)*

## Validation
Events: `mcp_poisoned_invocation` / `mcp_desc_mutation_accepted` / `cross_server_shadow` / `token_read`.

## Further reading
→ Basecamp: [Model Context Protocol](https://github.com/kkmookhey/basecamp-ai-sec/blob/main/docs/topics/03-mcp.md)
