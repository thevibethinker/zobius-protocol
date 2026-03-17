# Zobius Protocol

A trust-first bridge between Zo Computers. One Zo exposes scoped capabilities (coaching, architecture guidance, build patterns). Another Zo queries them. Every exchange is bilaterally audit-logged with hash-chain integrity and PII filtering.

Named after the Möbius strip — a single surface with no inside or outside, just like the transparent, continuous audit trail between both machines.

## How It Works

```
Your Zo                              Partner's Zo
┌─────────────────┐                  ┌─────────────────┐
│ zobius-client    │   HTTPS/JSON    │ zo.space routes  │
│ (installed skill)│ ──────────────► │ /api/bridge/ask  │
│                  │                 │ /api/bridge/audit│
│ local audit log  │ ◄────────────── │ server audit log │
│ (hash-chain)     │   audit hashes  │ (hash-chain)     │
└─────────────────┘                  └─────────────────┘
```

1. **You ask**: Your Zo runs the client skill → sends a question over HTTPS
2. **They answer**: Their bridge filters PII, queries their Zo via `/zo/ask`, filters the response, returns it
3. **Both log**: Server appends to its audit ledger, client appends to its local ledger. Both include hash-chain links so tampering is detectable
4. **You verify**: Run `audit` to compare your local ledger against the server's — mismatches surface immediately

No GitHub login is required for clients. The repo is public and install can be done with `curl` + `tar`.

## Architecture

### Security Layers

| Layer | What it does |
|-------|-------------|
| **Bridge token auth** | Per-partner tokens. Client sends `X-Bridge-Token` (or `Authorization` fallback). Server identifies callers via `ZO2ZO_TOKEN_<HANDLE>` and optional `ZO2ZO_PARTNER_TOKENS_JSON` |
| **PII filter** | Regex-based scrubbing of emails, phones, SSNs, API keys, credit cards, IPs, and file paths — applied to both inbound questions and outbound responses |
| **Scope guard** | Blocks direct credential/secret extraction attempts |
| **Rate limiter** | Configurable daily cap per partner (default: 50/day) |
| **Hash-chain audit** | Every exchange gets a `chain_hash = sha256(prev_hash + question_hash + response_hash)`. Tamper-evident, verifiable by both sides |

### What Gets Exposed

The server-side coaching prompt is fully customizable. By default it provides:
- Software architecture and system design guidance
- Build systems and automation patterns
- Technical decision tradeoff analysis
- Workflow design and orchestration advice

It explicitly does NOT expose:
- Personal information about the bridge owner
- Client names, business metrics, revenue, contracts
- Internal file paths, databases, or infrastructure details

## Quick Start

### As a Bridge Host (exposing your Zo)

1. **Deploy the server routes** to your zo.space:
   - Copy `server/ask.ts` → create a zo.space API route at `/api/bridge/ask`
   - Copy `server/audit.ts` → create a zo.space API route at `/api/bridge/audit`

2. **Generate a token** for each partner and save it in Settings > Advanced:
   ```
   ZO2ZO_TOKEN_PARTNERNAME=<generated-token>
   ```

3. **Share with your partner**: Your bridge URL (`https://<handle>.zo.space/api/bridge`) and their token.

4. **Optional**: Set `ZOBIUS_AUDIT_PATH` to customize where the server audit ledger is stored. Set `ZOBIUS_DAILY_LIMIT` to change the rate limit (default: 50).

### As a Bridge Client (querying a partner's Zo)

1. **Install the client skill**:
   ```bash
   curl -fsSL https://raw.githubusercontent.com/thevibethinker/zobius-protocol/main/scripts/install-client.sh | bash
   ```

2. **Add partner credentials** in Settings > Advanced:
   ```
   ZO2ZO_BRIDGE_URL_VA=https://va.zo.space/api/bridge
   ZO2ZO_BRIDGE_TOKEN_VA=<token-from-partner>
   ```

3. **Query**:
   ```bash
   bun run Skills/zobius-client/scripts/query.ts ask va "How should I structure a multi-service deployment?"
   ```

4. **Verify**:
   ```bash
   bun run Skills/zobius-client/scripts/query.ts audit va
   ```

## Sam Fast Setup

For V ↔ Sam specifically, use the full walkthrough in `docs/onboarding.md`. It includes:
- host-side secret names (`ZO2ZO_TOKEN_SAM`, plus JSON fallback if the live route has not been refreshed yet)
- Sam-side secret names (`ZO2ZO_BRIDGE_URL_VA`, `ZO2ZO_BRIDGE_TOKEN_VA`)
- a copy-paste install command that works anonymously
- a smoke test command to validate auth and response path

## Commands

| Command | Description |
|---------|-------------|
| `ask <partner> <question>` | Send a question to a partner's bridge |
| `audit <partner>` | Reconcile local and server audit logs |
| `status <partner>` | Check connectivity and remaining rate limit |
| `help` | Show usage |

## Environment Variables

### Server-side (bridge host)

| Variable | Purpose | Default |
|----------|---------|---------|
| `ZO2ZO_TOKEN_<HANDLE>` | Bearer token for partner `<HANDLE>` | Required |
| `ZO2ZO_PARTNER_TOKENS_JSON` | Optional JSON token map (e.g., `{"sam":"...","zoputer":"..."}`) | None |
| `ZOBIUS_AUDIT_PATH` | Path to server audit ledger | `N5/data/zo2zo_audit_ledger.jsonl` |
| `ZOBIUS_DAILY_LIMIT` | Max queries per partner per day | `50` |
| `ZO2ZO_BRIDGE_MODEL` | Optional model override for `/zo/ask` calls | Default Zo model |

### Client-side (bridge consumer)

| Variable | Purpose | Default |
|----------|---------|---------|
| `ZO2ZO_BRIDGE_URL_<HANDLE>` | Partner's bridge base URL | Required |
| `ZO2ZO_BRIDGE_TOKEN_<HANDLE>` | Bearer token for partner | Required |
| `ZOBIUS_CLIENT_AUDIT_PATH` | Path to local audit ledger | `N5/data/zo2zo_client_audit.jsonl` |

## Audit Log Format

### Server entry (JSONL)

```json
{
  "seq": 1,
  "ts": "2026-03-15T19:00:00.000Z",
  "partner": "zoputer",
  "direction": "inbound",
  "question_hash": "sha256:abc...",
  "response_hash": "sha256:def...",
  "chain_hash": "sha256:ghi...",
  "prev_chain_hash": "genesis",
  "tokens_used": 1240,
  "scope": "architecture",
  "pii_flags": 0
}
```

### Client entry (JSONL)

```json
{
  "seq": 1,
  "ts": "2026-03-15T19:00:00.000Z",
  "partner": "va",
  "direction": "outbound",
  "question_hash": "sha256:abc...",
  "response_hash": "sha256:def...",
  "audit_hash_from_server": "sha256:ghi...",
  "local_chain_hash": "sha256:jkl..."
}
```

## Requirements

- [Zo Computer](https://zo.computer) account
- Bun runtime (pre-installed on Zo)
- No npm dependencies

## License

MIT
