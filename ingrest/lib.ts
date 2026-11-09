import * as fs from "node:fs";
import * as net from "node:net";
import * as path from "node:path";

export const root = path.join(import.meta.dirname, "..");

export type Source = { type: "http-json" | "http-text"; url: string; selector?: string };
export type Bot = { id: string; categories: string[]; sources: Source[] };

type Entry = {
  id: string;
  verification?: { type: string; sources?: { type: string; url?: string; selector?: string }[] }[];
};

export function quote(v: unknown): string {
  const t = JSON.stringify(String(v));
  return t.length > 160 ? `${t.slice(0, 157)}..."` : t;
}

export function loadBots(file = path.join(root, "ingrest", "bots.json")): { bots: Bot[]; problems: string[] } {
  const pinned: Record<string, { categories: string[]; sources: Source[] }> = JSON.parse(fs.readFileSync(file, "utf-8"));
  const bots: Bot[] = [];
  const problems: string[] = [];
  for (const [id, b] of Object.entries(pinned)) {
    if (!b.sources?.length) problems.push(`${id}: has no IP range source`);
    for (const src of b.sources ?? []) {
      const why = checkSource(src);
      if (why) problems.push(`${id}: ${why}`);
    }
    bots.push({ id, categories: b.categories ?? [], sources: b.sources ?? [] });
  }
  return { bots, problems };
}

function sourceKey(s: { type?: string; url?: string; selector?: string }): string {
  return JSON.stringify([s.type ?? "", s.url ?? "", s.selector ?? ""]);
}

export function catalogDrift(bots: Bot[], catalogFile = path.join(root, "well-known-bots.json")): string[] {
  const catalog: Entry[] = JSON.parse(fs.readFileSync(catalogFile, "utf-8"));
  const out: string[] = [];
  for (const bot of bots) {
    const entry = catalog.find((e) => e.id === bot.id);
    if (!entry) {
      out.push(`${bot.id}: removed from the catalog`);
      continue;
    }
    const theirs = (entry.verification ?? [])
      .filter((v) => v.type === "cidr" || v.type === "ip")
      .flatMap((v) => v.sources ?? [])
      .map(sourceKey)
      .sort();
    const ours = bot.sources.map(sourceKey).sort();
    if (theirs.join("\n") !== ours.join("\n")) {
      out.push(`${bot.id}: the catalog lists other sources: ${theirs.map(quote).join(", ") || "none"}`);
    }
  }
  return out;
}

function checkSource(s: { type: string; url?: string; selector?: string }): string {
  if (s.type !== "http-json" && s.type !== "http-text") return `unsupported source type ${quote(s.type)}`;
  let url: URL;
  try {
    url = new URL(s.url ?? "");
  } catch {
    return `bad source URL ${quote(s.url)}`;
  }
  if (url.href !== s.url || url.protocol !== "https:" || url.port || url.username || url.password || url.hash) {
    return `source must be a plain https URL: ${quote(s.url)}`;
  }
  if (s.type === "http-json") {
    try {
      parseSelector(s.selector ?? "");
    } catch (e) {
      return `${(e as Error).message}: ${quote(s.url)}`;
    }
  } else if (s.selector) {
    return `a text source has a selector: ${quote(s.url)}`;
  }
  return "";
}

type Step = { kind: "all" } | { kind: "keys"; keys: string[] } | { kind: "filter"; key: string; value: string };

export function parseSelector(sel: string): Step[] {
  if (!sel.startsWith("$")) throw new Error(`unsupported selector ${quote(sel)}`);
  const steps: Step[] = [];
  let rest = sel.slice(1);
  const patterns: [RegExp, (m: RegExpMatchArray) => Step][] = [
    [/^\.\*/, () => ({ kind: "all" })],
    [/^\[\*\]/, () => ({ kind: "all" })],
    [/^\.([A-Za-z_][A-Za-z0-9_]*)/, (m) => ({ kind: "keys", keys: [m[1]] })],
    [/^\[("[^"\\]+"(?:,"[^"\\]+")*)\]/, (m) => ({ kind: "keys", keys: JSON.parse(`[${m[1]}]`) })],
    [/^\[\?\(@\.([A-Za-z_][A-Za-z0-9_]*)=="([^"\\]*)"\)\]/, (m) => ({ kind: "filter", key: m[1], value: m[2] })],
  ];
  while (rest) {
    const hit = patterns.map(([re, make]) => [rest.match(re), make] as const).find(([m]) => m);
    if (!hit) throw new Error(`unsupported selector ${quote(sel)}`);
    const [m, make] = hit;
    steps.push(make(m!));
    rest = rest.slice(m![0].length);
  }
  return steps;
}

export function select(data: unknown, sel: string): unknown[] {
  let cur: unknown[] = [data];
  for (const step of parseSelector(sel)) {
    const next: unknown[] = [];
    for (const v of cur) {
      if (v === null || typeof v !== "object") continue;
      const vals = Array.isArray(v) ? v : Object.values(v);
      if (step.kind === "all") next.push(...vals);
      else if (step.kind === "keys") {
        if (Array.isArray(v)) continue;
        for (const k of step.keys) if (Object.hasOwn(v, k)) next.push((v as Record<string, unknown>)[k]);
      } else {
        for (const item of vals) {
          if (item && typeof item === "object" && (item as Record<string, unknown>)[step.key] === step.value) next.push(item);
        }
      }
    }
    cur = next;
  }
  return cur;
}

const reserved4 = ["0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/3"];
const reserved6 = ["2001::/32", "2001:db8::/32", "2002::/16"];

function bits(addr: string, v6: boolean): bigint {
  if (!v6) return addr.split(".").reduce((n, p) => (n << 8n) | BigInt(Number(p)), 0n);
  const [head, tail = ""] = addr.includes("::") ? addr.split("::") : [addr, ""];
  const h = head ? head.split(":") : [];
  const t = tail ? tail.split(":") : [];
  if (addr.includes("::")) {
    const groups = [...h, ...Array(8 - h.length - t.length).fill("0"), ...t];
    return groups.reduce((n, g) => (n << 16n) | BigInt(parseInt(g, 16)), 0n);
  }
  return h.reduce((n, g) => (n << 16n) | BigInt(parseInt(g, 16)), 0n);
}

function format(n: bigint, v6: boolean): string {
  if (!v6) return [24n, 16n, 8n, 0n].map((s) => String((n >> s) & 255n)).join(".");
  const groups = Array.from({ length: 8 }, (_, i) => ((n >> BigInt((7 - i) * 16)) & 0xffffn).toString(16));
  let best = [-1, 0];
  for (let i = 0; i < 8; ) {
    if (groups[i] !== "0") {
      i++;
      continue;
    }
    let j = i;
    while (j < 8 && groups[j] === "0") j++;
    if (j - i > best[1] && j - i > 1) best = [i, j - i];
    i = j;
  }
  if (best[0] < 0) return groups.join(":");
  return `${groups.slice(0, best[0]).join(":")}::${groups.slice(best[0] + best[1]).join(":")}`;
}

export type Prefix = { v6: boolean; net: bigint; len: number };

export function parsePrefix(raw: string): Prefix {
  const s = raw.trim();
  const [addr, lenText, extra] = s.split("/");
  if (extra !== undefined || s.includes("%")) throw new Error(`bad prefix ${quote(s)}`);
  const kind = net.isIP(addr);
  if (!kind) throw new Error(`bad address ${quote(s)}`);
  if (addr.includes(".") && kind === 6) throw new Error(`mapped IPv4 address ${quote(s)}`);
  const v6 = kind === 6;
  const max = v6 ? 128 : 32;
  const len = lenText === undefined ? max : Number(lenText);
  if (!/^\d+$/.test(lenText ?? String(max)) || len > max) throw new Error(`bad prefix length ${quote(s)}`);
  const mask = ((1n << BigInt(len)) - 1n) << BigInt(max - len);
  return { v6, len, net: bits(addr, v6) & mask };
}

export function prefixText(p: Prefix): string {
  return `${format(p.net, p.v6)}/${p.len}`;
}

function inside(p: Prefix, cidr: string): boolean {
  const r = parsePrefix(cidr);
  if (r.v6 !== p.v6 || p.len < r.len) return false;
  const max = p.v6 ? 128 : 32;
  return p.net >> BigInt(max - r.len) === r.net >> BigInt(max - r.len);
}

export function rejectPrefix(p: Prefix): string {
  if (!p.v6 && p.len < 16) return "wider than /16";
  if (p.v6 && p.len < 28) return "wider than /28";
  if (p.v6 && !inside(p, "2000::/3")) return "not a global unicast IPv6 range";
  if ((p.v6 ? reserved6 : reserved4).some((r) => inside(p, r))) return "reserved range";
  return "";
}

export function size(prefixes: string[]): { v4: bigint; v6: bigint } {
  let v4 = 0n;
  let v6 = 0n;
  for (const t of prefixes) {
    const p = parsePrefix(t);
    if (p.v6) v6 += 1n << BigInt(Math.max(0, 64 - p.len));
    else v4 += 1n << BigInt(32 - p.len);
  }
  return { v4, v6 };
}
