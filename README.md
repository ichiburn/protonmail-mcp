# protonmail-mcp

An MCP (Model Context Protocol) server for ProtonMail. Read, search, and send emails directly from AI assistants like Claude Code.

**No Proton Bridge required.** Works with free ProtonMail accounts.

## Features

- **One-time CLI Login (OS Keychain)** — Run `protonmail-mcp login` once; no plaintext passwords or TOTP secrets in `.mcp.json`
- **Login & Auto-Refresh** — SRP authentication with 2FA (TOTP) support and automatic refresh token rotation
- **List messages** — Browse inbox, sent, drafts, trash, spam, archive
- **Read messages** — Decrypt and read PGP-encrypted email bodies locally
- **Search messages** — Filter by sender, subject, keyword
- **Send messages** — Compose and send emails with attachments (auto-encrypts for Proton-to-Proton)

## Security

- Uses **only official Proton libraries** — no third-party API wrappers
  - [go-proton-api](https://github.com/ProtonMail/go-proton-api) — API client (used by Proton Bridge)
  - [go-srp](https://github.com/ProtonMail/go-srp) — SRP authentication
  - [gopenpgp](https://github.com/ProtonMail/gopenpgp) — OpenPGP encryption/decryption
- **Zero passwords in `.mcp.json`** — One-time `protonmail-mcp login` derives your PGP key passphrase (`saltedKeyPass`), wipes the plaintext password from memory (`ZeroBytes`), and stores only the refresh token (`UID` / `RefreshToken`) and `saltedKeyPass` in your OS keychain ([zalando/go-keyring](https://github.com/zalando/go-keyring): macOS Keychain, Linux Secret Service, Windows Credential Manager; or a strict `0600` file fallback on headless Linux)
- All PGP encryption and decryption happens locally

## Install

```bash
go install github.com/ichiburn/protonmail-mcp@latest
```

Or build from source:

```bash
git clone https://github.com/ichiburn/protonmail-mcp.git
cd protonmail-mcp
go build -o protonmail-mcp .
```

## Setup

### Recommended: One-time CLI Login (OS Keychain — no passwords in `.mcp.json`)

ProtonMail uses zero-knowledge end-to-end PGP encryption, which means standard web OAuth tokens alone cannot unlock your private PGP keys to decrypt email bodies. Instead of putting your password in `.mcp.json`, run `protonmail-mcp login` once in your terminal:

```bash
protonmail-mcp login
# ProtonMail Email: your-email@proton.me
# Password: ********
# 2FA TOTP Code (6 digits) or Base32 Secret: 123456
```

What happens during `protonmail-mcp login`:
1. Performs SRP authentication (`NewClientWithLogin` + `Auth2FA`) and derives the salted PGP key passphrase (`salts.SaltForKey`).
2. Verifies local PGP keyring unlock (`proton.Unlock`) and immediately zeroes the raw password bytes in memory.
3. Saves only `UID`, `RefreshToken`, and `saltedKeyPass` into the **OS keychain** (macOS Keychain / Linux Secret Service / Windows Credential Manager). On headless Linux systems without a keyring daemon, it falls back to `~/.config/protonmail-mcp/credentials.json` with enforced `0700` directory and `0600` file permissions (refusing to load if group/world permissions are present).

Then configure `.mcp.json` **without any `env` credentials**:

```json
{
  "mcpServers": {
    "protonmail": {
      "command": "protonmail-mcp"
    }
  }
}
```

When the MCP server starts, it automatically restores the session via `NewClientWithRefresh`, unlocks your PGP keyring locally, and rotates the refresh token in the OS keychain whenever `go-proton-api` refreshes authentication.

#### CLI Commands

```bash
protonmail-mcp login              # Interactive one-time login (saves to OS keychain)
protonmail-mcp status             # Check stored credentials & verify session online
protonmail-mcp status --offline   # Check stored credentials without making API calls
protonmail-mcp logout             # Revoke server session & delete stored credentials
```

---

### Alternative (Legacy / Fallback): Environment Variables

If you prefer stateless configuration without the OS keychain, you can still pass credentials via environment variables:

```json
{
  "mcpServers": {
    "protonmail": {
      "command": "protonmail-mcp",
      "env": {
        "PROTON_USER": "your-email@proton.me",
        "PROTON_PASS": "your-password",
        "PROTON_TOTP_SECRET": "your-base32-totp-secret"
      }
    }
  }
}
```

| Variable | Description |
|----------|-------------|
| `PROTON_USER` | ProtonMail email address |
| `PROTON_PASS` | ProtonMail password |
| `PROTON_TOTP_SECRET` | Base32 TOTP secret, only if 2FA is enabled. The server derives the 6-digit code locally (RFC6238). |
| `PROTON_MCP_CRED_FILE` | Optional custom path for the `0600` fallback credential file (default: `~/.config/protonmail-mcp/credentials.json`) |

## Tools

### `protonmail_login`

Authenticate or refresh the ProtonMail session. **Takes no arguments** — it first restores your saved session from the OS keychain (created via `protonmail-mcp login`), or falls back to `PROTON_USER`, `PROTON_PASS`, and `PROTON_TOTP_SECRET` environment variables if no keychain session exists. Tool arguments are never accepted so credentials never enter the AI agent's context.

| Parameter | Required | Description |
|-----------|----------|-------------|
| _(none)_ | — | Restores from OS keychain or reads environment variables |

### `protonmail_list_messages`

List messages from a folder.

| Parameter | Required | Description |
|-----------|----------|-------------|
| `folder` | No | `inbox`, `sent`, `drafts`, `trash`, `spam`, `archive`, `all` (default: `inbox`) |
| `subject` | No | Filter by subject |
| `limit` | No | Number of messages (default: 20) |
| `page` | No | Page number (default: 0) |

### `protonmail_read_message`

Read and decrypt a message body.

| Parameter | Required | Description |
|-----------|----------|-------------|
| `message_id` | Yes | Message ID from list/search |

### `protonmail_search_messages`

Search messages by sender, subject, or keyword.

| Parameter | Required | Description |
|-----------|----------|-------------|
| `sender` | No | Sender email/name (partial match) |
| `subject` | No | Subject keyword |
| `keyword` | No | Keyword (matches against subject) |
| `limit` | No | Number of results (default: 20) |

### `protonmail_send_preview`

Generate a send preview. Returns a `confirm_token` for use with `protonmail_send_confirm`.

| Parameter | Required | Description |
|-----------|----------|-------------|
| `to` | Yes | Recipient(s), comma-separated |
| `subject` | Yes | Subject line |
| `body` | Yes | Plain text body |
| `cc` | No | CC recipient(s), comma-separated |
| `attachments` | No | File path(s), comma-separated (max 20 files, 25MB total) |

### `protonmail_send_confirm`

Actually send a previewed email. Requires the token from `protonmail_send_preview`.

| Parameter | Required | Description |
|-----------|----------|-------------|
| `confirm_token` | Yes | Token from `protonmail_send_preview` (valid for 5 minutes) |

## How It Works

1. **Authentication**: One-time SRP (Secure Remote Password) login via `protonmail-mcp login` (using Proton's `go-srp`), followed by token-based session restoration (`NewClientWithRefresh`) and automatic token rotation (`AddAuthHandler`)
2. **Key management**: User's PGP private key is decrypted locally with the derived `saltedKeyPass` stored in the OS keychain
3. **Reading**: Encrypted message bodies are decrypted with the user's keyring via `gopenpgp`
4. **Sending**: Messages are encrypted with recipient's public key (Proton-to-Proton) or sent in clear (external)

### Honest client identification

The `x-pm-appversion` header is set to **`protonmail-mcp@<version>`** — this tool identifies itself honestly rather than impersonating an official Proton client (e.g. `web-mail`). Spoofing a first-party client would violate community norms and Proton's terms; naming the tool truthfully is the expected practice for a `go-proton-api`-based project.

## Security Measures

### Adversarial Security Audit

This codebase has been through **8 rounds of adversarial review** using Claude (writer) + OpenAI Codex (reviewer) separation. 24 issues were identified and fixed across all rounds:

| Round | CRITICAL | HIGH | MEDIUM | Issues Fixed |
|-------|----------|------|--------|-------------|
| 1 | 3 | 4 | 5 | 3 |
| 2 | 0 | 2 | 4 | 7 |
| 3 | 0 | 5 | 0 | 5 |
| 4 | 0 | 2 | 0 | 2 |
| 5 | 0 | 0 | 4 | 4 |
| 6 | 0 | 0 | 2 | 2 |
| 7 | 0 | 0 | 1 | 1 |
| **8** | **0** | **0** | **0** | **0** |

Key issues found and fixed include: prompt injection via email content, SRP session leaks on 2FA failure, PGP key material not zeroed, SMTP header injection in address parsing, race conditions in session management, and resource leaks on error paths.

### Prompt Injection Defense

- Email content from `protonmail_read_message` is wrapped with untrusted-content markers and escape sequences
- A `_warning` field instructs the AI not to follow instructions found in email bodies
- Delimiter strings within email bodies are escaped to prevent breakout

### Two-Step Send with Server-Side Token

Sending requires two separate tool calls:

1. `protonmail_send_preview` — generates a preview and returns a cryptographically random `confirm_token` (256-bit)
2. `protonmail_send_confirm` — requires the token to actually send

This prevents prompt injection attacks from triggering sends — even if a malicious email instructs the AI to send, it cannot guess the confirmation token. Tokens are single-use and expire after 5 minutes.

### Rate Limiting

Sending is limited to 5 emails per 10-minute window. Rate limit slots are reserved atomically before the send attempt and released on failure.

### Session Management

- Session state is protected by `sync.RWMutex` to prevent data races
- Reference counting ensures in-flight handlers complete before session teardown
- Session close has a 30-second timeout to prevent indefinite blocking
- Re-login properly closes the previous session (client + manager) before creating a new one

### Credential Handling

- **OS Keychain first (recommended)**: `protonmail-mcp login` reads credentials interactively from the terminal (with echo disabled), derives `saltedKeyPass`, and persists only `UID`, `RefreshToken`, and `saltedKeyPass` to the OS keychain (or a `0600`-enforced file on headless systems). No plaintext password or TOTP secret is stored on disk or in `.mcp.json`.
- **Never accepted as tool arguments**: Credentials are never passed through MCP tool arguments, keeping secrets out of the AI agent's context, chat transcript, and logs.
- **Memory hygiene**: Password byte slices and `saltedKeyPass` buffers are zeroed (`auth.ZeroBytes`) immediately after key derivation or keyring unlock.

### Input Validation

- Message IDs are validated against a strict regex before API calls
- Email addresses containing CRLF characters are rejected (SMTP header injection prevention)
- `limit` and `page` parameters are clamped to safe ranges
- Empty recipient lists are caught before draft creation

### Attachment Security

- File paths are validated with symlink resolution (`filepath.EvalSymlinks`) and path traversal prevention
- Sensitive files are blocked (`.env`, `.ssh/`, `.aws/`, `.gnupg/`, shell configs, etc.)
- Per-file limit: 25MB, total limit: 25MB, max 20 attachments
- Attachments are PGP-encrypted and signed before upload
- File validation is performed at both preview and send time (TOCTOU protection)

## Limitations

- Attachment download not yet supported (upload/send works)
- HTML email composition not yet supported (plain text only)
- No event streaming / real-time notifications
- ProtonMail API is not officially documented — endpoints may change

## Disclaimer

This is an **unofficial** project. Not affiliated with or endorsed by Proton AG.

Uses Proton's own open-source libraries (`go-proton-api`, `go-srp`, `gopenpgp`) which are published under open-source licenses. This project accesses your own account data — it does not scrape, proxy, or redistribute any Proton services.

Use responsibly. Do not use for spam or any activity that violates [Proton's Terms of Service](https://proton.me/legal/terms).

## License

MIT
