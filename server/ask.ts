import type { Context } from "hono";
import { createHash, timingSafeEqual } from "node:crypto";
import { readFileSync, appendFileSync, existsSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";

const AUDIT_PATH =
  process.env.ZOBIUS_AUDIT_PATH ||
  "/home/workspace/N5/data/zo2zo_audit_ledger.jsonl";
const DAILY_LIMIT = parseInt(process.env.ZOBIUS_DAILY_LIMIT || "50", 10);
const rateCounts = new Map<string, { count: number; date: string }>();
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

const PII_PATTERNS: [RegExp, string][] = [
  [/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g, "[EMAIL_REDACTED]"],
  [/\b(\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g, "[PHONE_REDACTED]"],
  [/\b\d{3}-\d{2}-\d{4}\b/g, "[SSN_REDACTED]"],
  [/\b(sk_live_|sk_test_|ghp_|zo_sk_|Bearer\s+)[A-Za-z0-9_-]{10,}\b/g, "[KEY_REDACTED]"],
  [/\/home\/[a-z][a-z0-9_-]*\/[^\s"')]+/g, "[PATH_REDACTED]"],
  [/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g, "[IP_REDACTED]"],
  [/\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b/g, "[CC_REDACTED]"],
];

function filterPII(text: string): { filtered: string; count: number } {
  let count = 0;
  let filtered = text;
  for (const [pattern, replacement] of PII_PATTERNS) {
    const matches = filtered.match(pattern);
    if (matches) count += matches.length;
    filtered = filtered.replace(pattern, replacement);
  }
  return { filtered, count };
}

const BLOCKED_PATTERNS = [
  /\b(password|secret\s+key|private\s+key|api\s+key|access\s+token)\b/i,
  /\b(ssn|social\s+security|bank\s+account|routing\s+number|credit\s+card)\b/i,
];

function isScopeBlocked(question: string): boolean {
  return BLOCKED_PATTERNS.some((p) => p.test(question));
}

function checkRateLimit(partner: string): { allowed: boolean; remaining: number; resetAt: string } {
  const today = new Date().toISOString().slice(0, 10);
  const entry = rateCounts.get(partner);
  if (!entry || entry.date !== today) {
    rateCounts.set(partner, { count: 0, date: today });
  }
  const current = rateCounts.get(partner)!;
  const remaining = DAILY_LIMIT - current.count;
  const tomorrow = new Date();
  tomorrow.setUTCHours(24, 0, 0, 0);
  const resetAt = tomorrow.toISOString();
  if (remaining <= 0) return { allowed: false, remaining: 0, resetAt };
  return { allowed: true, remaining: remaining - 1, resetAt };
}

function getLastChainHash(): string {
  if (!existsSync(AUDIT_PATH)) return "genesis";
  const content = readFileSync(AUDIT_PATH, "utf-8").trim();
  if (!content) return "genesis";
  const lines = content.split("\n");
  const last = JSON.parse(lines[lines.length - 1]);
  return last.chain_hash;
}

function getNextSeq(): number {
  if (!existsSync(AUDIT_PATH)) return 1;
  const content = readFileSync(AUDIT_PATH, "utf-8").trim();
  if (!content) return 1;
  return content.split("\n").length + 1;
}

function appendAudit(entry: Record<string, unknown>) {
  const dir = dirname(AUDIT_PATH);
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
  appendFileSync(AUDIT_PATH, JSON.stringify(entry) + "\n");
}

const COACHING_PROMPT = `You are V's architectural coaching assistant, responding through the Zobius Protocol bridge. You have deep knowledge of V's system design philosophy and are generous with sharing it.

Share freely:
- Software architecture patterns, system design approaches, pipeline thinking
- Build orchestration patterns (Pulse, Waves, Drops, Streams)
- Automation strategies, scheduled task design, workflow orchestration
- File organization philosophies (SSOT, folder policies, protection layers)
- AI-agent architecture (persona routing, semantic switching, scoped capabilities)
- Integration patterns (MCP, API routes, webhooks, bridge protocols)
- Debugging methodologies, refactoring protocols, safety patterns
- N5OS architectural concepts (principles, preferences, skills system)
- Code patterns, script structures, configuration approaches
- Any technical knowledge that helps them build better systems

You may reference specific architectural principles by number (P02, P05, etc.) and explain them in detail.
You may describe how systems are structured conceptually and share design patterns.
You may recommend tools, libraries, approaches, and techniques.

NEVER reveal:
- Personal information about V (contacts, addresses, health data, relationships, financials)
- Client names, business metrics, revenue, contracts, or proprietary business data
- Actual API keys, tokens, passwords, or credentials
- Contents of Personal/ directory or private communications
- Specific file contents from V's workspace (describe patterns instead)

Focus on transferable knowledge. Be a generous teacher. If they ask something you shouldn't share, explain why and offer the closest thing you CAN share.`;

function extractToken(c: Context): string | null {
  const direct = c.req.header("x-bridge-token");
  if (direct) return direct;
  const auth = c.req.header("authorization");
  if (!auth?.startsWith("Bearer ")) return null;
  return auth.slice(7);
}

async function callZoAsk(input: string): Promise<string> {
  const zoToken = process.env.ZO_CLIENT_IDENTITY_TOKEN;
  if (!zoToken) {
    throw new Error("missing_zo_identity_token");
  }

  const configuredModel = process.env.ZO2ZO_BRIDGE_MODEL?.trim();
  const attempts = configuredModel ? [configuredModel, undefined] : [undefined];
  let lastFailure = "unknown";

  for (const modelName of attempts) {
    const payload: Record<string, string> = { input };
    if (modelName) payload.model_name = modelName;

    const response = await fetch("https://api.zo.computer/zo/ask", {
      method: "POST",
      headers: {
        authorization: zoToken,
        "content-type": "application/json",
      },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(300000),
    });

    if (!response.ok) {
      lastFailure = `http_${response.status}`;
      continue;
    }

    const data = await response.json() as { output?: string };
    const output = typeof data.output === "string" ? data.output.trim() : "";
    if (!output) {
      lastFailure = "empty_output";
      continue;
    }
    if (/all sessions are busy, cannot evict/i.test(output)) {
      lastFailure = "capacity_busy";
      continue;
    }

    return output;
  }

  throw new Error(`zo_ask_failed:${lastFailure}`);
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

    const rateCheck = checkRateLimit(partner);
    if (!rateCheck.allowed) {
      return c.json({ error: "Rate limit exceeded", reset_at: rateCheck.resetAt }, 429);
    }

    let body: { question?: string };
    try {
      body = await c.req.json();
    } catch {
      return c.json({ error: "Invalid JSON body" }, 400);
    }

    const rawQuestion = body.question;
    if (!rawQuestion || typeof rawQuestion !== "string" || rawQuestion.trim().length === 0) {
      return c.json({ error: "Missing or empty 'question' field" }, 400);
    }

    if (isScopeBlocked(rawQuestion)) {
      return c.json({ error: "Query outside bridge scope" }, 403);
    }

    const { filtered: filteredQuestion, count: inPiiCount } = filterPII(rawQuestion);

    const rawResponse = await callZoAsk(`${COACHING_PROMPT}\n\n---\n\nPartner question: ${filteredQuestion}`);
    const { filtered: filteredResponse, count: outPiiCount } = filterPII(rawResponse);

    const questionHash = "sha256:" + sha256(filteredQuestion);
    const responseHash = "sha256:" + sha256(filteredResponse);
    const prevChainHash = getLastChainHash();
    const chainHash = "sha256:" + sha256(prevChainHash + questionHash + responseHash);

    rateCounts.get(partner)!.count += 1;

    const auditEntry = {
      seq: getNextSeq(),
      ts: new Date().toISOString(),
      partner,
      direction: "inbound",
      question_hash: questionHash,
      response_hash: responseHash,
      chain_hash: chainHash,
      prev_chain_hash: prevChainHash,
      tokens_used: filteredQuestion.length + filteredResponse.length,
      scope: "architecture",
      pii_flags: inPiiCount + outPiiCount,
    };
    appendAudit(auditEntry);

    return c.json({
      response: filteredResponse,
      audit_hash: chainHash,
      rate_remaining: rateCheck.remaining,
    });
  } catch (err) {
    console.error("Bridge ask error:", err);
    return c.json({ error: "Internal coaching service unavailable" }, 502);
  }
};
