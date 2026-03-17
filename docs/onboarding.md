---
created: 2026-03-16
last_edited: 2026-03-16
version: 1.0
provenance: con_3z63XyOQOHIMWfaR
---

# Sam Onboarding (No GitHub Login)

This setup keeps the repo public and requires no GitHub auth for Sam.

## 1) V (host) setup

In Zo Settings > Advanced, add a per-partner secret:

`ZO2ZO_TOKEN_SAM=<strong-random-token>`

For immediate compatibility with the currently deployed bridge, also add:

`ZO2ZO_PARTNER_TOKENS_JSON={"sam":"<same-strong-random-token>"}`

The bridge endpoint is:

`https://va.zo.space/api/bridge`

## 2) Sam install command

Sam runs this once in his Zo terminal:

```bash
curl -fsSL https://raw.githubusercontent.com/thevibethinker/zobius-protocol/main/scripts/install-client.sh | bash
```

This installs the client skill to:

`/home/workspace/Skills/zobius-client`

## 3) Sam secrets

Sam adds these in his Zo Settings > Advanced:

`ZO2ZO_BRIDGE_URL_VA=https://va.zo.space/api/bridge`

`ZO2ZO_BRIDGE_TOKEN_VA=<token-shared-by-v>`

## 4) Smoke test

Sam runs:

```bash
bun run /home/workspace/Skills/zobius-client/scripts/query.ts status va
bun run /home/workspace/Skills/zobius-client/scripts/query.ts ask va "Give me a clean architecture pattern for orchestrating multi-step agent workflows."
```

If auth is correct, the first command shows `Connected` and the second returns a coaching response.

## 5) Audit check

Sam runs:

```bash
bun run /home/workspace/Skills/zobius-client/scripts/query.ts audit va
```

This compares local and server hash-linked audit records.
