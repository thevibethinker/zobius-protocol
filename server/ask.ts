import type { Context } from "hono";
import { createHash, timingSafeEqual } from "node:crypto";
import { readFileSync, appendFileSync, existsSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";

const AUDIT_PATH =
  process.env.ZOBIUS_AUDIT_PATH ||
  "/home/workspace/N5/data/zo2zo_audit_ledger.jsonl";
const DAILY_LIMIT = parseInt(process.env.ZOBIUS_DAILY_LIMIT || "50", 10);
const rateCounts = new Map<string, { count: number; date: string }>();

function sha256(data: string): string {
  return createHash("sha256").update(data).digest("hex");
}

function constantTimeEqual(a: string, b: string): boolean {
  const aB = Buffer.from(a);
  const bB = Buffer.from(b);
  if (aB.length !== bB.length) return false;
  return timingSafeEqual(aB, bB);
}

function identifyPartner(token: string): string | null {
  for (const [key, val] of Object.entries(process.env)) {
    if (key.startsWith("ZO2ZO_TOKEN_") && val && constantTimeEqual(val, token)) {
      return key.replace("ZO2ZO_TOKEN_", "").toLowerCase();
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
  /\b(revenue|income|salary|compensation|earnings|profit|loss)\b/i,
  /\b(client\s+name|client\s+list|customer\s+list|contract\s+details)\b/i,
  /\b(password|secret\s+key|private\s+key|api\s+key|access\s+token)\b/i,
  /\b(ssn|social\s+security|bank\s+account|routing\s+number)\b/i,
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

// Customize this prompt to match what you want to expose through the bridge.
// This is the system prompt sent to /zo/ask alongside the partner's question.
const COACHING_PROMPT = `You are an architectural coaching assistant responding through the Zobius Protocol bridge. Provide thoughtful, practical guidance on:
- Software architecture and system design
- Build systems and automation patterns
- Technical decisions and tradeoffs
- Workflow design and orchestration

Guidelines:
- Be direct and specific. Give actionable advice.
- Draw on general architectural principles (separation of concerns, SSOT, pipeline thinking, etc.)
- NEVER reveal personal information about the bridge owner, client names, business metrics, revenue, contracts, or proprietary system details
- NEVER mention specific file paths, internal databases, or infrastructure details
- Focus on transferable architectural patterns and coaching
- If asked about something outside your coaching scope, say so clearly`;

export default async (c: Context) => {
  try {
    const auth = c.req.header("authorization");
    if (!auth?.startsWith("Bearer ")) {
      return c.json({ error: "Unauthorized" }, 401);
    }
    const token = auth.slice(7);
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

    const zoToken = process.env.ZO_CLIENT_IDENTITY_TOKEN;
    if (!zoToken) {
      return c.json({ error: "Bridge misconfigured" }, 500);
    }

    const zoResponse = await fetch("https://api.zo.computer/zo/ask", {
      method: "POST",
      headers: {
        authorization: zoToken,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        input: `${COACHING_PROMPT}\n\n---\n\nPartner question: ${filteredQuestion}`,
      }),
    });

    if (!zoResponse.ok) {
      return c.json({ error: "Internal coaching service unavailable" }, 502);
    }

    const zoData = (await zoResponse.json()) as { output?: string };
    const rawResponse = zoData.output || "No response generated.";
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
    return c.json({ error: "Internal bridge error" }, 500);
  }
};
