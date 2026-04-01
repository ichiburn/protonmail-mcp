# protonmail-mcp

An MCP (Model Context Protocol) server for ProtonMail. Read, search, and send emails directly from AI assistants like Claude Code.

**No Proton Bridge required.** Works with free ProtonMail accounts.

## Features

- **Login** — SRP authentication with 2FA (TOTP) support
- **List messages** — Browse inbox, sent, drafts, trash, spam, archive
- **Read messages** — Decrypt and read PGP-encrypted email bodies
- **Search messages** — Filter by sender, subject, keyword
- **Send messages** — Compose and send emails (auto-encrypts for Proton-to-Proton)

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

### `protonmail_send_message`

Send an email.

| Parameter | Required | Description |
|-----------|----------|-------------|
| `to` | Yes | Recipient(s), comma-separated |
| `subject` | Yes | Subject line |
| `body` | Yes | Plain text body |
| `cc` | No | CC recipient(s), comma-separated |

## How It Works

1. **Authentication**: SRP (Secure Remote Password) protocol via Proton's official `go-srp` library
2. **Key management**: User's PGP private key is decrypted locally with the mailbox password
3. **Reading**: Encrypted message bodies are decrypted with the user's keyring via `gopenpgp`
4. **Sending**: Messages are encrypted with recipient's public key (Proton-to-Proton) or sent in clear (external)

## Limitations

- Attachment download/upload not yet supported
- HTML email composition not yet supported (plain text only)
- No event streaming / real-time notifications
- ProtonMail API is not officially documented — endpoints may change

## Disclaimer

This is an **unofficial** project. Not affiliated with or endorsed by Proton AG.

Uses Proton's own open-source libraries (`go-proton-api`, `go-srp`, `gopenpgp`) which are published under open-source licenses. This project accesses your own account data — it does not scrape, proxy, or redistribute any Proton services.

Use responsibly. Do not use for spam or any activity that violates [Proton's Terms of Service](https://proton.me/legal/terms).

## License

MIT
