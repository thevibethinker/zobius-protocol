#!/usr/bin/env python3
"""
Zobius Protocol — Telemetry Digest & Self-Improvement Loop

Reads zo2zo_audit_ledger.jsonl + zo2zo_telemetry.jsonl and produces:
1. Partner activity summary
2. Retry/cache analysis (wasted compute detection)
3. Response time distribution
4. Question topic clusters (what are partners asking about?)
5. Actual questions & responses (PII-filtered, from telemetry)
6. Improvement suggestions based on patterns

Usage:
  python3 N5/scripts/zo2zo_digest.py                    # Full digest
  python3 N5/scripts/zo2zo_digest.py --date 2026-03-17  # Single day
  python3 N5/scripts/zo2zo_digest.py --since 2026-03-16 # Since date
  python3 N5/scripts/zo2zo_digest.py --partner sam       # Filter by partner
  python3 N5/scripts/zo2zo_digest.py --improvements      # Just improvement suggestions
  python3 N5/scripts/zo2zo_digest.py --json              # Machine-readable output
  python3 N5/scripts/zo2zo_digest.py --questions         # Show actual questions
"""

import json
import sys
import hashlib
import argparse
from pathlib import Path
from datetime import datetime, timezone
from collections import defaultdict, Counter

AUDIT_PATH = Path("/home/workspace/N5/data/zo2zo_audit_ledger.jsonl")
TELEMETRY_PATH = Path("/home/workspace/N5/data/zo2zo_telemetry.jsonl")


def load_jsonl(path, since=None, date_filter=None, partner=None):
    if not path.exists():
        return []
    entries = []
    for line in path.read_text().strip().split("\n"):
        if not line:
            continue
        try:
            e = json.loads(line)
        except json.JSONDecodeError:
            continue
        ts = e.get("ts", "")
        if date_filter and ts[:10] != date_filter:
            continue
        if since and ts < since:
            continue
        if partner and e.get("partner", "") != partner:
            continue
        entries.append(e)
    return entries


def verify_chain(entries):
    for i, entry in enumerate(entries):
        expected_prev = "genesis" if i == 0 else entries[i - 1]["chain_hash"]
        if entry.get("prev_chain_hash") != expected_prev:
            return {"valid": False, "broken_at": entry.get("seq")}
        payload = expected_prev + entry["question_hash"] + entry["response_hash"]
        expected_chain = "sha256:" + hashlib.sha256(payload.encode()).hexdigest()
        if entry.get("chain_hash") != expected_chain:
            return {"valid": False, "broken_at": entry.get("seq")}
    return {"valid": True}


def analyze_retries(audit_entries):
    q_hashes = defaultdict(list)
    for e in audit_entries:
        q_hashes[e["question_hash"]].append(e)
    retries = {h: group for h, group in q_hashes.items() if len(group) > 1}
    total_wasted = sum(len(g) - 1 for g in retries.values())
    return retries, total_wasted


def analyze_timing(telemetry):
    queries = [e for e in telemetry if e.get("event") == "query" and "elapsed_ms" in e]
    if not queries:
        return {}
    times = [e["elapsed_ms"] for e in queries]
    return {
        "count": len(times),
        "avg_ms": sum(times) / len(times),
        "min_ms": min(times),
        "max_ms": max(times),
        "p50_ms": sorted(times)[len(times) // 2],
        "over_60s": sum(1 for t in times if t > 60000),
        "over_30s": sum(1 for t in times if t > 30000),
    }


def extract_topics(telemetry):
    questions = [e.get("question_preview", "") for e in telemetry if e.get("event") == "query"]
    keyword_map = {
        "architecture": ["architecture", "architect", "design pattern", "system design"],
        "pulse/orchestration": ["pulse", "orchestrat", "wave", "drop", "stream", "build"],
        "n5os": ["n5", "n5os", "preference", "principle"],
        "automation": ["automat", "schedule", "cron", "agent", "workflow"],
        "debugging": ["debug", "troubleshoot", "error", "fix", "broken"],
        "integration": ["mcp", "api", "webhook", "bridge", "integration"],
        "skills": ["skill", "recipe", "prompt", "command"],
        "file/state": ["file", "folder", "state", "config", "ssot"],
        "persona": ["persona", "routing", "switch", "specialist"],
    }
    topic_counts = defaultdict(int)
    for q in questions:
        ql = q.lower()
        for topic, keywords in keyword_map.items():
            if any(kw in ql for kw in keywords):
                topic_counts[topic] += 1
    return dict(sorted(topic_counts.items(), key=lambda x: -x[1]))


def generate_improvements(audit_entries, telemetry, timing):
    improvements = []

    retries, wasted = analyze_retries(audit_entries)
    if wasted > 0:
        pct = wasted * 100 // len(audit_entries) if audit_entries else 0
        improvements.append({
            "type": "performance",
            "priority": "high" if pct > 30 else "medium",
            "issue": f"{wasted} duplicate queries ({pct}% of total) — retry storms from timeouts",
            "fix": "Response caching deployed. Monitor cache_hit events to verify effectiveness.",
            "metric": f"retry_rate:{pct}%",
        })

    if timing and timing.get("over_60s", 0) > 0:
        pct = timing["over_60s"] * 100 // timing["count"]
        improvements.append({
            "type": "performance",
            "priority": "high" if pct > 25 else "medium",
            "issue": f"{timing['over_60s']} responses over 60s ({pct}% of queries)",
            "fix": "Consider pre-warming coaching context or lighter model for simple questions",
            "metric": f"slow_query_rate:{pct}%",
        })

    scope_blocks = [e for e in telemetry if e.get("event") == "scope_blocked"]
    if scope_blocks:
        previews = [e.get("question_preview", "?")[:80] for e in scope_blocks[:3]]
        improvements.append({
            "type": "scope",
            "priority": "medium",
            "issue": f"{len(scope_blocks)} queries blocked by scope filter",
            "fix": f"Review blocked questions: {previews}",
            "metric": f"block_count:{len(scope_blocks)}",
        })

    pii_flagged = [e for e in telemetry if e.get("event") == "query"
                   and (e.get("pii_flags_in", 0) + e.get("pii_flags_out", 0)) > 0]
    if pii_flagged:
        improvements.append({
            "type": "security",
            "priority": "high",
            "issue": f"{len(pii_flagged)} queries had PII flags",
            "fix": "Review flagged content for false positives vs real leaks",
            "metric": f"pii_flag_count:{len(pii_flagged)}",
        })

    cache_hits = [e for e in telemetry if e.get("event") == "cache_hit"]
    if cache_hits:
        improvements.append({
            "type": "performance",
            "priority": "info",
            "issue": f"{len(cache_hits)} cache hits — deduplication saving compute",
            "fix": "No action needed.",
            "metric": f"cache_hits:{len(cache_hits)}",
        })

    return improvements


def print_digest(args):
    audit = load_jsonl(AUDIT_PATH, since=args.since, date_filter=args.date, partner=args.partner)
    telemetry = load_jsonl(TELEMETRY_PATH, since=args.since, date_filter=args.date, partner=args.partner)
    all_audit = load_jsonl(AUDIT_PATH)

    if not audit and not telemetry:
        print("No data found for the specified filters.")
        return

    timing = analyze_timing(telemetry)
    topics = extract_topics(telemetry)
    chain_status = verify_chain(all_audit)
    improvements = generate_improvements(audit, telemetry, timing)

    if args.improvements:
        print("## Improvement Suggestions\n")
        for imp in improvements:
            icon = {"high": "🔴", "medium": "🟡", "info": "🟢"}.get(imp["priority"], "⚪")
            print(f"{icon} **[{imp['type']}]** {imp['issue']}")
            print(f"   Fix: {imp['fix']}")
            print(f"   Metric: {imp['metric']}\n")
        return

    if args.questions:
        queries = [e for e in telemetry if e.get("event") == "query"]
        if not queries:
            print("No telemetry questions available (telemetry logging was added after these queries).")
            print("New queries will be logged going forward.")
            return
        print("## Questions (PII-filtered)\n")
        for e in queries:
            ts = e.get("ts", "?")[:19]
            p = e.get("partner", "?")
            q = e.get("question_preview", "?")
            r = e.get("response_preview", "")
            ms = e.get("elapsed_ms", 0)
            print(f"**[{ts}] {p}:**")
            print(f"  Q: {q}")
            if r:
                print(f"  A: {r[:200]}{'...' if len(r) > 200 else ''}")
            print(f"  ({e.get('response_length', '?')} chars, {ms/1000:.1f}s)\n")
        return

    # Full digest
    period = args.date or (f"since {args.since}" if args.since else "all time")
    partner_filter = f" (partner: {args.partner})" if args.partner else ""
    print(f"# 🌉 Zobius Bridge Digest — {period}{partner_filter}\n")

    # Partner breakdown
    partner_counts = Counter(e.get("partner", "unknown") for e in audit)
    print("## Partner Activity")
    for p, count in partner_counts.most_common():
        print(f"  {p}: {count} queries")
    print(f"  **Total: {len(audit)} queries**\n")

    # Response times
    if timing:
        print("## Response Times")
        print(f"  Average: {timing['avg_ms']/1000:.1f}s | Median: {timing['p50_ms']/1000:.1f}s")
        print(f"  Min: {timing['min_ms']/1000:.1f}s | Max: {timing['max_ms']/1000:.1f}s")
        print(f"  Over 30s: {timing.get('over_30s', 0)} | Over 60s: {timing.get('over_60s', 0)}\n")

    # Retries
    retries, wasted = analyze_retries(audit)
    if wasted > 0:
        print("## Retry Analysis")
        print(f"  Wasted queries: {wasted}/{len(audit)} ({wasted*100//len(audit)}%)")
        for h, group in retries.items():
            partners_set = set(e["partner"] for e in group)
            print(f"  {h[:24]}... × {len(group)} by {partners_set}")
        print()

    # Topics
    if topics:
        print("## Question Topics")
        for topic, count in topics.items():
            bar = "█" * count
            print(f"  {topic:25s} {bar} ({count})")
        print()

    # PII / Security
    total_pii = sum(e.get("pii_flags", 0) for e in audit)
    print(f"## Security")
    print(f"  PII flags: {total_pii}")
    if total_pii > 0:
        flagged = [e for e in audit if e.get("pii_flags", 0) > 0]
        for e in flagged:
            print(f"  ⚠️ seq {e['seq']} ({e['partner']}): {e['pii_flags']} flags")
    print()

    # Chain integrity
    print("## Audit Chain")
    if chain_status["valid"]:
        print(f"  ✅ Valid ({len(all_audit)} total entries)")
    else:
        print(f"  ⚠️ Broken at seq {chain_status.get('broken_at')}")
    print()

    # Improvements
    if improvements:
        print("## Improvement Suggestions")
        for imp in improvements:
            icon = {"high": "🔴", "medium": "🟡", "info": "🟢"}.get(imp["priority"], "⚪")
            print(f"  {icon} [{imp['type']}] {imp['issue']}")
            print(f"     → {imp['fix']}")
        print()

    # Recent questions (if telemetry available)
    queries = [e for e in telemetry if e.get("event") == "query"]
    if queries:
        print("## Recent Questions (last 5)")
        for e in queries[-5:]:
            ts = e.get("ts", "?")[:19]
            p = e.get("partner", "?")
            q = e.get("question_preview", "?")
            ms = e.get("elapsed_ms", 0)
            print(f"  [{ts}] {p}: {q[:120]}{'...' if len(q) > 120 else ''}")
            print(f"    → {e.get('response_length', '?')} chars in {ms/1000:.1f}s")
        print()
    else:
        print("## Questions")
        print("  No telemetry data yet (logging activated — new queries will be captured)")
        print()

    print(f"*Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}*")


def output_json(args):
    audit = load_jsonl(AUDIT_PATH, since=args.since, date_filter=args.date, partner=args.partner)
    telemetry = load_jsonl(TELEMETRY_PATH, since=args.since, date_filter=args.date, partner=args.partner)
    timing = analyze_timing(telemetry)
    improvements = generate_improvements(audit, telemetry, timing)
    questions = [
        {
            "ts": e.get("ts"),
            "partner": e.get("partner"),
            "question": e.get("question_preview"),
            "response_length": e.get("response_length"),
            "elapsed_ms": e.get("elapsed_ms"),
        }
        for e in telemetry if e.get("event") == "query"
    ]
    print(json.dumps({
        "period": args.date or args.since or "all",
        "partner_filter": args.partner,
        "total_queries": len(audit),
        "telemetry_entries": len(telemetry),
        "timing": timing,
        "topics": extract_topics(telemetry),
        "improvements": improvements,
        "questions": questions,
    }, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Zobius Protocol telemetry digest")
    parser.add_argument("--date", help="Filter to single date (YYYY-MM-DD)")
    parser.add_argument("--since", help="Filter entries since date (YYYY-MM-DD)")
    parser.add_argument("--partner", help="Filter by partner name")
    parser.add_argument("--improvements", action="store_true", help="Show only improvements")
    parser.add_argument("--questions", action="store_true", help="Show actual questions")
    parser.add_argument("--json", action="store_true", help="Machine-readable JSON output")
    args = parser.parse_args()

    if args.json:
        output_json(args)
    else:
        print_digest(args)
