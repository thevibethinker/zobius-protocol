import { createHash } from "node:crypto";
import { readFileSync, appendFileSync, existsSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";

const AUDIT_PATH =
  process.env.ZOBIUS_CLIENT_AUDIT_PATH ||
  "/home/workspace/N5/data/zo2zo_client_audit.jsonl";

function sha256(data: string): string {
  return createHash("sha256").update(data).digest("hex");
}

const PII_PATTERNS: [RegExp, string][] = [
  [/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g, "email"],
  [/\b(\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g, "phone"],
  [/\b\d{3}-\d{2}-\d{4}\b/g, "SSN"],
  [/\b(sk_live_|sk_test_|ghp_|zo_sk_|Bearer\s+)[A-Za-z0-9_-]{10,}\b/g, "API key"],
];

function checkPII(text: string): { detected: boolean; count: number; types: string[] } {
  const types: string[] = [];
  let count = 0;
  for (const [pattern, label] of PII_PATTERNS) {
    const matches = text.match(pattern);
    if (matches) {
      count += matches.length;
      if (!types.includes(label)) types.push(label);
    }
  }
  return { detected: count > 0, count, types };
}

function getPartnerConfig(handle: string): { url: string; token: string } | null {
  const upper = handle.toUpperCase();
  const url = process.env[`ZO2ZO_BRIDGE_URL_${upper}`];
  const token = process.env[`ZO2ZO_BRIDGE_TOKEN_${upper}`];
  if (!url || !token) return null;
  return { url, token };
}

function getLastLocalChainHash(): string {
  if (!existsSync(AUDIT_PATH)) return "genesis";
  const content = readFileSync(AUDIT_PATH, "utf-8").trim();
  if (!content) return "genesis";
  const lines = content.split("\n");
  const last = JSON.parse(lines[lines.length - 1]);
  return last.local_chain_hash;
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

function readLocalAudit(): any[] {
  if (!existsSync(AUDIT_PATH)) return [];
  const content = readFileSync(AUDIT_PATH, "utf-8").trim();
  if (!content) return [];
  return content.split("\n").map((l) => JSON.parse(l));
}

async function cmdAsk(partner: string, question: string) {
  const config = getPartnerConfig(partner);
  if (!config) {
    console.error(
      `Bridge not configured for partner '${partner}'. Set ZO2ZO_BRIDGE_URL_${partner.toUpperCase()} and ZO2ZO_BRIDGE_TOKEN_${partner.toUpperCase()} in Settings > Advanced.`
    );
    process.exit(1);
  }

  const pii = checkPII(question);
  if (pii.detected) {
    console.warn(
      `⚠️ PII detected in question (${pii.count} item${pii.count > 1 ? "s" : ""}: ${pii.types.join(", ")}) — will be filtered server-side`
    );
  }

  try {
    const resp = await fetch(`${config.url}/ask`, {
      method: "POST",
      headers: {
        "X-Bridge-Token": config.token,
        "Content-Type": "application/json",
        Accept: "application/json",
      },
      body: JSON.stringify({ question }),
      signal: AbortSignal.timeout(300000),
    });

    if (resp.status === 401) {
      console.error("Authentication failed. Check your token in Settings > Advanced.");
      process.exit(1);
    }
    if (resp.status === 403) {
      console.error("Query outside bridge scope. Try rephrasing.");
      process.exit(1);
    }
    if (resp.status === 429) {
      const data = (await resp.json()) as { reset_at?: string };
      console.error(`Rate limit reached. Resets at ${data.reset_at || "midnight UTC"}. Try again tomorrow.`);
      process.exit(1);
    }
    if (resp.status >= 500) {
      console.error("Bridge server error. Try again later.");
      process.exit(1);
    }
    if (!resp.ok) {
      const data = await resp.json().catch(() => ({}));
      console.error(`Bridge error (${resp.status}):`, (data as any).error || resp.statusText);
      process.exit(1);
    }

    const data = (await resp.json()) as {
      response: string;
      audit_hash: string;
      rate_remaining: number;
    };

    console.log("\n" + data.response);
    console.log(`\n--- Rate remaining: ${data.rate_remaining} ---`);

    const questionHash = "sha256:" + sha256(question);
    const responseHash = "sha256:" + sha256(data.response);
    const prevChain = getLastLocalChainHash();
    const localChainHash = "sha256:" + sha256(prevChain + questionHash + responseHash);

    appendAudit({
      seq: getNextSeq(),
      ts: new Date().toISOString(),
      partner,
      direction: "outbound",
      question_hash: questionHash,
      response_hash: responseHash,
      audit_hash_from_server: data.audit_hash,
      local_chain_hash: localChainHash,
    });
  } catch (err: any) {
    if (err.code === "ECONNREFUSED" || err.code === "ENOTFOUND" || err.cause) {
      console.error("Cannot reach bridge. Check URL in Settings > Advanced.");
    } else {
      console.error("Bridge request failed:", err.message);
    }
    process.exit(1);
  }
}

async function cmdAudit(partner: string) {
  const config = getPartnerConfig(partner);
  if (!config) {
    console.error(
      `Bridge not configured for partner '${partner}'. Set ZO2ZO_BRIDGE_URL_${partner.toUpperCase()} and ZO2ZO_BRIDGE_TOKEN_${partner.toUpperCase()} in Settings > Advanced.`
    );
    process.exit(1);
  }

  try {
    const resp = await fetch(`${config.url}/audit?partner=${partner}`, {
      headers: {
        "X-Bridge-Token": config.token,
        Accept: "application/json",
      },
    });

    if (!resp.ok) {
      console.error(`Audit fetch failed (${resp.status})`);
      process.exit(1);
    }

    const serverData = (await resp.json()) as {
      entries: any[];
      total: number;
      chain_valid: boolean;
    };

    const localEntries = readLocalAudit().filter((e) => e.partner === partner);

    const serverHashes = new Set(serverData.entries.map((e: any) => e.chain_hash));
    const localHashes = new Set(localEntries.map((e) => e.audit_hash_from_server));

    let matches = 0;
    let mismatches = 0;
    for (const hash of localHashes) {
      if (serverHashes.has(hash)) matches++;
      else mismatches++;
    }

    const serverOnly = serverData.entries.filter(
      (e: any) => !localHashes.has(e.chain_hash)
    ).length;
    const localOnly = localEntries.filter(
      (e) => !serverHashes.has(e.audit_hash_from_server)
    ).length;

    console.log(`\nAudit Reconciliation — Partner: ${partner}`);
    console.log(`Server entries: ${serverData.total}`);
    console.log(`Local entries: ${localEntries.length}`);
    console.log(`Matches: ${matches}`);
    console.log(`Mismatches: ${mismatches}`);
    console.log(`Server-only: ${serverOnly}`);
    console.log(`Local-only: ${localOnly}`);
    console.log(`Server chain valid: ${serverData.chain_valid}`);
  } catch (err: any) {
    console.error("Cannot reach bridge. Check URL in Settings > Advanced.");
    process.exit(1);
  }
}

async function cmdStatus(partner: string) {
  const config = getPartnerConfig(partner);
  if (!config) {
    console.error(
      `Bridge not configured for partner '${partner}'. Set ZO2ZO_BRIDGE_URL_${partner.toUpperCase()} and ZO2ZO_BRIDGE_TOKEN_${partner.toUpperCase()} in Settings > Advanced.`
    );
    process.exit(1);
  }

  console.log(`\nBridge Status — Partner: ${partner}`);
  console.log(`URL: ${config.url}`);
  console.log(`Token: ${config.token.slice(0, 8)}...`);

  try {
    const resp = await fetch(`${config.url}/ask`, {
      method: "POST",
      headers: {
        "X-Bridge-Token": config.token,
        "Content-Type": "application/json",
        Accept: "application/json",
      },
      body: JSON.stringify({ question: "ping" }),
      signal: AbortSignal.timeout(300000),
    });

    if (resp.ok) {
      const data = (await resp.json()) as { rate_remaining: number };
      console.log(`Status: Connected`);
      console.log(`Rate remaining: ${data.rate_remaining}`);
    } else if (resp.status === 401) {
      console.log(`Status: Auth failed — check token`);
    } else if (resp.status === 429) {
      console.log(`Status: Rate limited — try tomorrow`);
    } else {
      console.log(`Status: Error (${resp.status})`);
    }
  } catch {
    console.log(`Status: Unreachable`);
  }
}

function showHelp() {
  console.log(`
Zobius Protocol — Bridge Client

Usage:
  bun run query.ts ask <partner> <question>   Query a partner's bridge
  bun run query.ts audit <partner>            Reconcile audit logs
  bun run query.ts status <partner>           Check bridge connectivity
  bun run query.ts help                       Show this help

Environment Variables (per partner):
  ZO2ZO_BRIDGE_URL_<HANDLE>    Partner's bridge base URL
  ZO2ZO_BRIDGE_TOKEN_<HANDLE>  Bearer token for authentication

Examples:
  bun run query.ts ask va "How should I structure a build pipeline?"
  bun run query.ts audit va
  bun run query.ts status va
`);
}

const args = process.argv.slice(2);
const command = args[0];

switch (command) {
  case "ask": {
    const partner = args[1];
    const question = args.slice(2).join(" ");
    if (!partner || !question) {
      console.error("Usage: bun run query.ts ask <partner> <question>");
      process.exit(1);
    }
    await cmdAsk(partner, question);
    break;
  }
  case "audit": {
    const partner = args[1];
    if (!partner) {
      console.error("Usage: bun run query.ts audit <partner>");
      process.exit(1);
    }
    await cmdAudit(partner);
    break;
  }
  case "status": {
    const partner = args[1];
    if (!partner) {
      console.error("Usage: bun run query.ts status <partner>");
      process.exit(1);
    }
    await cmdStatus(partner);
    break;
  }
  case "help":
  case "--help":
  case "-h":
    showHelp();
    break;
  default:
    showHelp();
    process.exit(command ? 1 : 0);
}
