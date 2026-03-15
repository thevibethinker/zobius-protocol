---
name: zobius-client
description: Query a partner's Zo for architectural coaching via the Zobius Protocol. Provides ask, audit, and status commands with bilateral audit logging and PII pre-checking.
compatibility: Created for Zo Computer
metadata:
  author: va.zo.computer
  protocol: zobius-protocol
  version: "1.0"
---

# zobius-client

Query a partner's Zo Computer for architectural coaching, build guidance, and technical decisions via the Zobius Protocol. All interactions are bilaterally audit-logged with hash-chain integrity. Outbound questions are pre-checked for PII before transmission.

## Setup

1. Obtain a bridge URL and token from your partner (they run the Zobius server-side routes on their zo.space).
2. Add credentials in **Settings > Advanced** as environment variables:
   - `ZO2ZO_BRIDGE_URL_<HANDLE>` — Partner's bridge base URL (e.g., `https://va.zo.space/api/bridge`)
   - `ZO2ZO_BRIDGE_TOKEN_<HANDLE>` — Bearer token issued by the partner

   Replace `<HANDLE>` with the partner's uppercase handle. For partner `va`:
   - `ZO2ZO_BRIDGE_URL_VA=https://va.zo.space/api/bridge`
   - `ZO2ZO_BRIDGE_TOKEN_VA=<token from partner>`

3. Optionally set `ZOBIUS_CLIENT_AUDIT_PATH` to customize where the local audit log is stored (defaults to `N5/data/zo2zo_client_audit.jsonl` relative to workspace).

## Usage

### ask — Query a partner

```bash
bun run Skills/zobius-client/scripts/query.ts ask <partner> "How should I structure my build pipeline?"
```

Sends a question to the partner's bridge. PII is scanned before transmission. Response and audit metadata are logged locally.

### audit — Reconcile audit logs

```bash
bun run Skills/zobius-client/scripts/query.ts audit <partner>
```

Fetches server-side audit log and compares against local records. Reports matches, mismatches, and one-sided entries.

### status — Check bridge connectivity

```bash
bun run Skills/zobius-client/scripts/query.ts status <partner>
```

Shows partner name, bridge URL, and remaining rate limit.

## Audit Log

Local entries appended to the audit path (default `N5/data/zo2zo_client_audit.jsonl`):

```json
{
  "seq": 1,
  "ts": "2026-03-15T12:00:00.000Z",
  "partner": "va",
  "direction": "outbound",
  "question_hash": "sha256:...",
  "response_hash": "sha256:...",
  "audit_hash_from_server": "sha256:...",
  "local_chain_hash": "sha256:..."
}
```

The `local_chain_hash` chains entries: `sha256(prev + question_hash + response_hash)`. Genesis value is `"genesis"`.

## Dependencies

Bun runtime only — no npm dependencies. Uses built-in fetch, crypto, fs.
