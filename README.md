# protonmail-mcp

An MCP (Model Context Protocol) server for ProtonMail. Read, search, and send emails directly from AI assistants like Claude Code.

**No Proton Bridge required.** Works with free ProtonMail accounts.

## Features

- **Login** — SRP authentication with 2FA (TOTP) support
- **List messages** — Browse inbox, sent, drafts, trash, spam, archive
- **Read messages** — Decrypt and read PGP-encrypted email bodies
- **Search messages** — Filter by sender, subject, keyword
- **Send messages** — Compose and send emails with attachments (auto-encrypts for Proton-to-Proton)

## Security

- Uses **only official Proton libraries** — no third-party API wrappers
  - [go-proton-api](https://github.com/ProtonMail/go-proton-api) — API client (used by Proton Bridge)
  - [go-srp](https://github.com/ProtonMail/go-srp) — SRP authentication
  - [gopenpgp](https://github.com/ProtonMail/gopenpgp) — OpenPGP encryption/decryption
- Credentials are passed via environment variables — never stored on disk
- All encryption/decryption happens locally

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

### Claude Code

Add to your `.mcp.json`:

```json
{
  "mcpServers": {
    "protonmail": {
      "command": "protonmail-mcp",
      "env": {
        "PROTON_USER": "your-email@proton.me",
        "PROTON_PASS": "your-password"
      }
    }
  }
}
```

Or pass credentials at login time instead of storing them in config.

### Environment Variables

| Variable | Description |
|----------|-------------|
| `PROTON_USER` | ProtonMail email address |
| `PROTON_PASS` | ProtonMail password |

## Tools

### `protonmail_login`

Authenticate with ProtonMail. Uses environment variables or explicit parameters.

| Parameter | Required | Description |
|-----------|----------|-------------|
| `username` | No | Email address (falls back to `PROTON_USER`) |
| `password` | No | Password (falls back to `PROTON_PASS`) |
| `totp` | No | 2FA code if TOTP is enabled |

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

1. **Authentication**: SRP (Secure Remote Password) protocol via Proton's official `go-srp` library
2. **Key management**: User's PGP private key is decrypted locally with the mailbox password
3. **Reading**: Encrypted message bodies are decrypted with the user's keyring via `gopenpgp`
4. **Sending**: Messages are encrypted with recipient's public key (Proton-to-Proton) or sent in clear (external)

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

- Credentials are passed via environment variables — never stored on disk by this tool
- Password byte slices are zeroed after use
- Key passphrase material (`saltedKeyPass`) is zeroed immediately after key unlock
- **Known limitation**: Go strings are immutable and cannot be reliably zeroed in memory. The password string from environment variables persists until GC collection.

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
