# Zobius Protocol — Known Issues & Fixes

## zo.space Secrets Caching

After adding secrets in Settings > Advanced, you MUST redeploy the bridge routes for them to take effect. The zo.space runtime caches environment variables at deploy time.

**Fix:** Touch/redeploy routes after adding secrets, or make a trivial code change to trigger restart.

## Authorization Header Stripping

The zo.space reverse proxy strips standard `Authorization: Bearer` headers. The Zobius bridge uses `X-Bridge-Token` as a custom header instead.

## Timeout Chain (3 layers)

Three independent timeout layers affect bridge queries:
1. **Client script** (query.ts): 300s
2. **Bridge route** (AbortSignal.timeout): 300s  
3. **Zo shell wrapper**: Your Zo may wrap commands in `timeout 30` — raise this to 300+

If you see timeout errors, check all three layers.

## Response Deduplication

The bridge caches responses for 5 minutes by question hash per partner. Duplicate queries within the TTL window return the cached response instantly, preventing retry storms.

## Telemetry

The bridge logs PII-filtered question text and response metadata to a telemetry file (separate from the hash-only audit trail). Run the digest script for analysis:

```bash
python3 scripts/zo2zo_digest.py --questions  # See what partners are asking
python3 scripts/zo2zo_digest.py --improvements  # Get improvement suggestions
python3 scripts/zo2zo_digest.py --partner sam  # Filter by partner
```
