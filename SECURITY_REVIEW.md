# Moltbot Security Review Report

## Executive Summary

**Moltbot** is a local-first personal AI assistant that runs on your own devices, integrating with 28+ messaging channels (Slack, Discord, Telegram, WhatsApp, Signal, etc.), browser automation, voice capabilities, and shell command execution. This is a **high-risk application** due to its extensive system access and multi-channel attack surface.

---

## 1. Architecture Overview

- **Runtime**: Node.js ≥22.12.0 (enforces critical security patches)
- **Deployment**: Local single-user, Docker containerized, or cloud (Fly.io)
- **Communication**: WebSocket gateway (port 18789), HTTP APIs
- **Storage**: SQLite sessions, JSON config files, LanceDB for vector memory
- **State Directory**: `~/.clawdbot/` containing credentials, tokens, sessions

---

## 2. Security Strengths ✅

### 2.1 Authentication & Authorization
- **Timing-safe token comparison** (`src/gateway/auth.ts:35-38`) - prevents timing attacks
- **Multi-layered auth**: token mode, password mode, Tailscale identity verification
- **Device identity management** with role-based scopes (`src/infra/device-auth-store.ts`)
- **Pairing system** for DM authorization with cryptographically random codes

### 2.2 Command Execution Security
- **Allowlist-based execution** (`src/infra/exec-approvals.ts`) with three modes:
  - `deny`: Block all commands
  - `allowlist`: Only pre-approved commands/paths
  - `full`: All commands allowed (requires explicit opt-in)
- **User approval workflow** for commands not in allowlist
- **Safe binaries list** (`jq`, `grep`, `cut`, `sort`, etc.) with path validation
- **Sandbox support** via Docker containers

### 2.3 External Content Protection
- **Prompt injection detection** (`src/security/external-content.ts:15-28`) with patterns like:
  - `ignore previous instructions`
  - `you are now a`
  - `system prompt override`
  - `rm -rf`
- **Content wrapping** with security boundaries for untrusted sources (emails, webhooks)

### 2.4 SSRF Protection
- **DNS rebinding prevention** (`src/infra/net/ssrf.ts`) with pinned DNS resolution
- **Private IP blocking**: 10.x.x.x, 127.x.x.x, 172.16-31.x.x, 192.168.x.x, link-local
- **Blocked hostnames**: localhost, *.local, *.internal, metadata.google.internal

### 2.5 File System Security
- **Permissions enforcement**: 0o600 for secrets, 0o700 for directories
- **Path traversal prevention** in pairing store (`safeChannelKey()` sanitization)
- **Atomic file writes** with temp file + rename pattern
- **Symlink detection** in security audit

### 2.6 Built-in Security Audit
- `moltbot security audit --deep` command checks:
  - Gateway authentication configuration
  - File permissions
  - Channel DM/group policies
  - Elevated privileges configuration
  - Secrets in config files

---

## 3. Security Risks & Vulnerabilities ⚠️

### 3.1 CRITICAL: Shell Command Execution

**Risk**: The exec tool allows arbitrary shell command execution via LLM agents.

**Location**: `src/agents/bash-tools.exec.ts`

**Details**:
- Commands are passed to shell via `spawn(shell, ["-c", command])`
- Even with `allowlist` mode, complex shell commands can bypass restrictions
- The `elevated` mode grants unrestricted host access when enabled
- Default `askFallback: "deny"` on timeout is good, but `askFallback: "full"` is allowed

**Mitigations present**:
- Shell command analysis with quote-aware parsing
- Allowlist pattern matching for executable paths
- User approval workflow for unknown commands
- Safe bins allowlist for simple utilities

**Residual risk**: Social engineering LLM to execute malicious commands

### 3.2 CRITICAL: Browser Automation with CDP

**Risk**: Chrome DevTools Protocol allows JavaScript execution in browser context.

**Location**: `src/browser/cdp.ts:118-144`

```typescript
// Arbitrary JavaScript execution via CDP
const evaluated = await send("Runtime.evaluate", {
  expression: opts.expression,  // LLM-provided code
  awaitPromise: Boolean(opts.awaitPromise),
  returnByValue: opts.returnByValue ?? true,
  userGesture: true,
  includeCommandLineAPI: true,  // Enables $, $$, copy, etc.
});
```

**Attack vectors**:
- LLM can be manipulated to execute malicious JavaScript
- Access to browser cookies, localStorage, passwords
- Potential for credential theft via form filling observation

### 3.3 HIGH: Multi-Channel Attack Surface

**Risk**: 28+ messaging integrations multiply attack vectors.

**Concerns**:
- **Open DM policies** (`dmPolicy: "open"`) allow anyone to interact with the bot
- **Group chat wildcards** (`allowFrom: ["*"]`) permit all members to send commands
- Each channel SDK has its own authentication model
- Message content from untrusted users flows to LLM

**Security indicators in audit** (`src/security/audit.ts`):
```typescript
if (input.dmPolicy === "open") {
  findings.push({
    severity: "critical",
    title: `${input.label} DMs are open`,
    detail: `${policyPath}="open" allows anyone to DM the bot.`,
  });
}
```

### 3.4 HIGH: Elevated Privileges Feature

**Risk**: The `elevated` mode bypasses security controls.

**Location**: `src/agents/bash-tools.exec.ts:848-851`

```typescript
if (bypassApprovals) {
  ask = "off";  // Disables approval workflow
}
```

**Configuration path**:
- `tools.elevated.enabled: true`
- `tools.elevated.allowFrom.<provider>: ["user-id"]`

### 3.5 HIGH: Dangerous Configuration Options

Several config options explicitly disable security controls:

| Option | Risk |
|--------|------|
| `gateway.controlUi.dangerouslyDisableDeviceAuth` | Disables device identity verification |
| `gateway.controlUi.allowInsecureAuth` | Allows HTTP auth without HTTPS |
| `hooks.*.allowUnsafeExternalContent` | Disables prompt injection protection |
| `gateway.tailscale.mode: "funnel"` | Exposes gateway to public internet |

### 3.6 MEDIUM: Plugin Security

**Risk**: Arbitrary code execution via plugins.

**Location**: `src/plugins/discovery.ts`

- Plugins discovered from `~/.clawdbot/extensions/`, workspace directories, and bundled
- No code signing or integrity verification
- `package.json` manifest validation only checks structure, not code

### 3.7 MEDIUM: Credential Storage

**Locations where credentials are stored**:
- `~/.clawdbot/config.yaml` - gateway tokens, channel tokens
- `~/.clawdbot/.env` - API keys
- `~/.clawdbot/identity/device-auth.json` - device tokens
- `~/.clawdbot/oauth/` - OAuth refresh tokens
- macOS Keychain (for Claude CLI credentials)

**Concerns**:
- JSON/YAML files on disk (even with 0o600 permissions)
- Environment variables can leak in crash dumps
- No encryption at rest

### 3.8 MEDIUM: WebSocket Security

**Location**: `src/gateway/server.ts`, `src/gateway/client.ts`

- Max payload 25MB (could be used for DoS)
- No rate limiting mentioned in code
- Heartbeat interval 30s (connection hijacking window)

### 3.9 LOW: Logging & Telemetry

- `logging.redactSensitive: "off"` can leak secrets to logs
- Tool call arguments/outputs may contain sensitive data
- Stack traces may expose paths and internal structure

---

## 4. Risk Matrix for End Users

| Scenario | Risk Level | Impact |
|----------|------------|--------|
| Running with default config + pairing mode | **Medium** | Limited to approved senders |
| Running with `dmPolicy: "open"` on any channel | **Critical** | Anyone can prompt the bot |
| Enabling `tools.elevated.enabled` | **Critical** | Full system access possible |
| Exposing gateway via Tailscale Funnel | **Critical** | Public internet exposure |
| Using browser automation tools | **High** | Browser session compromise |
| Installing untrusted plugins | **High** | Arbitrary code execution |
| Running without sandbox (host=gateway) | **High** | Direct system access |
| Running in Docker sandbox | **Medium** | Container escape risk |

---

## 5. Specific Risks for End Users

### 5.1 Data Exposure
- **Conversation history** stored in SQLite sessions
- **API keys** for all integrated services
- **OAuth tokens** for Google (Gmail), GitHub, etc.
- **Browser session data** accessible via CDP

### 5.2 System Compromise
- LLM-directed shell commands can modify/delete files
- Browser automation can observe/exfiltrate data
- Plugin code runs with Node.js full privileges

### 5.3 Account Takeover
- Channel tokens (Slack, Discord, Telegram) could be exfiltrated
- OAuth refresh tokens allow persistent access
- macOS Keychain credentials accessible to the process

### 5.4 Prompt Injection via Messages
- Malicious messages from other users in allowed channels
- Crafted emails processed by Gmail hooks
- Webhook payloads from external systems

---

## 6. Security Recommendations

### For End Users:

1. **Use pairing mode** instead of open DMs:
   ```yaml
   channels:
     defaults:
       dmPolicy: pairing  # Not "open"
   ```

2. **Enable sandbox mode** for command execution:
   ```yaml
   tools:
     exec:
       host: sandbox
       security: allowlist
   ```

3. **Never expose gateway publicly** without strong auth:
   ```yaml
   gateway:
     bind: loopback  # Not "all"
     tailscale:
       mode: serve  # Not "funnel"
   ```

4. **Review elevated permissions** carefully:
   ```yaml
   tools:
     elevated:
       enabled: false  # Unless absolutely needed
   ```

5. **Run security audit regularly**:
   ```bash
   moltbot security audit --deep
   ```

6. **Restrict file permissions**:
   ```bash
   chmod 700 ~/.clawdbot
   chmod 600 ~/.clawdbot/config.yaml
   ```

7. **Review channel allowlists** periodically
8. **Use strong, unique gateway tokens** (24+ chars)
9. **Monitor for prompt injection patterns** in logs

---

## 7. Dynamic Assessment Feasibility

A dynamic security assessment (installing and running the application) was not performed because:

1. **Network exposure**: Installing would require actual API keys and could expose real accounts
2. **Credential risk**: Dynamic testing would require real credentials for messaging platforms
3. **System modification**: The application modifies system state (`~/.clawdbot/`)
4. **Docker requirement**: Sandbox mode requires Docker daemon

The static analysis above covers the critical security paths.

---

## 8. Conclusion

Moltbot is a powerful tool with **significant security implications**. It provides many security controls, but the fundamental design—allowing an LLM to execute shell commands and control a browser—creates inherent risks that cannot be fully mitigated.

**Key takeaways for end users**:
- ✅ The codebase shows security awareness (SSRF protection, timing-safe auth, prompt injection detection)
- ⚠️ Many security controls are opt-in and disabled by default
- ❌ The application has a large attack surface that requires careful configuration
- ❌ LLM-driven command execution is fundamentally risky

**This application should only be run by users who**:
- Understand the security implications
- Have isolated test environments
- Can configure proper access controls
- Accept the risk of potential system compromise

---

*Report generated: 2026-01-28*
*Repository: https://github.com/moltbot/moltbot*
