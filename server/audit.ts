import type { Context } from "hono";
import { createHash, timingSafeEqual } from "node:crypto";
import { readFileSync, existsSync } from "node:fs";

const AUDIT_PATH =
  process.env.ZOBIUS_AUDIT_PATH ||
  "/home/workspace/N5/data/zo2zo_audit_ledger.jsonl";
const PARTNER_TOKEN_PREFIX = "ZO2ZO_TOKEN_";

function sha256(data: string): string {
  return createHash("sha256").update(data).digest("hex");
}

function constantTimeEqual(a: string, b: string): boolean {
  const aB = Buffer.from(a);
  const bB = Buffer.from(b);
  if (aB.length !== bB.length) return false;
  return timingSafeEqual(aB, bB);
}

function parsePartnerTokenMap(): Record<string, string> {
  const raw = process.env.ZO2ZO_PARTNER_TOKENS_JSON;
  if (!raw) return {};
  try {
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== "object") return {};
    return Object.entries(parsed).reduce<Record<string, string>>((acc, [key, value]) => {
      if (typeof value === "string" && value.trim().length > 0) {
        acc[key.toLowerCase()] = value;
      }
      return acc;
    }, {});
  } catch {
    return {};
  }
}

function identifyPartner(token: string): string | null {
  for (const [key, val] of Object.entries(process.env)) {
    if (key.startsWith(PARTNER_TOKEN_PREFIX) && val && constantTimeEqual(val, token)) {
      return key.replace(PARTNER_TOKEN_PREFIX, "").toLowerCase();
    }
  }

  const mapped = parsePartnerTokenMap();
  for (const [partner, secret] of Object.entries(mapped)) {
    if (constantTimeEqual(secret, token)) {
      return partner;
    }
  }

  return null;
}

interface AuditEntry {
  seq: number;
  ts: string;
  partner: string;
  direction: string;
  question_hash: string;
  response_hash: string;
  chain_hash: string;
  prev_chain_hash: string;
  tokens_used: number;
  scope: string;
  pii_flags: number;
}

function readAuditLog(): AuditEntry[] {
  if (!existsSync(AUDIT_PATH)) return [];
  const content = readFileSync(AUDIT_PATH, "utf-8").trim();
  if (!content) return [];
  return content.split("\n").map((line) => JSON.parse(line));
}

function verifyChain(entries: AuditEntry[]): { valid: boolean; brokenAt?: number } {
  for (let i = 0; i < entries.length; i++) {
    const entry = entries[i];
    const expectedPrev = i === 0 ? "genesis" : entries[i - 1].chain_hash;
    if (entry.prev_chain_hash !== expectedPrev) {
      return { valid: false, brokenAt: entry.seq };
    }
    const expectedChain =
      "sha256:" + sha256(entry.prev_chain_hash + entry.question_hash + entry.response_hash);
    if (entry.chain_hash !== expectedChain) {
      return { valid: false, brokenAt: entry.seq };
    }
  }
  return { valid: true };
}

function extractToken(c: Context): string | null {
  const direct = c.req.header("x-bridge-token");
  if (direct) return direct;
  const auth = c.req.header("authorization");
  if (!auth?.startsWith("Bearer ")) return null;
  return auth.slice(7);
}

export default async (c: Context) => {
  try {
    const token = extractToken(c);
    if (!token) {
      return c.json({ error: "Unauthorized" }, 401);
    }

    const partner = identifyPartner(token);
    if (!partner) {
      return c.json({ error: "Unauthorized" }, 401);
    }

    const filterPartner = c.req.query("partner") || partner;
    const since = c.req.query("since");

    let entries = readAuditLog();
    entries = entries.filter((e) => e.partner === filterPartner);

    if (since) {
      const sinceDate = new Date(since);
      if (!isNaN(sinceDate.getTime())) {
        entries = entries.filter((e) => new Date(e.ts) >= sinceDate);
      }
    }

    const chainCheck = verifyChain(readAuditLog());

    return c.json({
      entries,
      total: entries.length,
      chain_valid: chainCheck.valid,
      chain_broken_at: chainCheck.brokenAt || null,
    });
  } catch (err) {
    console.error("Bridge audit error:", err);
    return c.json({ error: "Internal bridge error" }, 500);
  }
};
