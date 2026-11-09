import * as dns from "node:dns/promises";
import * as fs from "node:fs";
import * as path from "node:path";
import { parseArgs } from "node:util";
import {
  loadBots,
  parsePrefix,
  prefixText,
  quote,
  rejectPrefix,
  select,
  size,
  subnets24,
  verifiedSubnets,
  type DnsSource,
  type HttpSource,
  type Prefix,
  type Source,
} from "./lib.ts";

const staleLimit = 14 * 24 * 3600 * 1000;

type BotOut = { categories: string[]; sources: string[]; prefixes: string[]; stale_since?: string };
type Output = { generated_at: string; bots: Record<string, BotOut> };

const { values } = parseArgs({
  options: {
    previous: { type: "string" },
    out: { type: "string", default: "dist" },
    "allow-growth": { type: "boolean", default: false },
  },
});

const now = new Date().toISOString();
const problems: string[] = [];
const previous: Output | undefined =
  values.previous && fs.existsSync(values.previous) ? JSON.parse(fs.readFileSync(values.previous, "utf-8")) : undefined;

const { bots, problems: catalogProblems } = loadBots();
problems.push(...catalogProblems);

async function download(url: string): Promise<string> {
  const res = await fetch(url, {
    redirect: "error",
    signal: AbortSignal.timeout(30_000),
    headers: { "user-agent": "trusted-bots-builder (+https://github.com/ingrest-dev/trusted-bots)" },
  });
  if (!res.ok || !res.body) throw new Error(`HTTP ${res.status}`);
  const max = 4 << 20;
  const chunks: Uint8Array[] = [];
  let size = 0;
  for await (const chunk of res.body) {
    size += chunk.length;
    if (size > max) throw new Error("larger than 4 MiB");
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString("utf-8");
}

function entries(src: HttpSource, body: string): string[] {
  if (src.type === "http-text") {
    return body
      .split("\n")
      .map((l) => l.replace(/#.*/, "").trim())
      .filter(Boolean);
  }
  return select(JSON.parse(body), src.selector ?? "").filter((v): v is string => typeof v === "string");
}

const fetched = new Map<string, Promise<string>>();
function label(src: Source): string {
  return src.type === "asn-rdns" ? `AS${src.asn} reverse DNS ${src.ptr.join(" ")}` : src.url;
}

async function fromDns(src: DnsSource): Promise<Prefix[]> {
  const body = await download(`https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS${src.asn}`);
  const announced = select(JSON.parse(body), "$.data.prefixes[*].prefix").filter((v): v is string => {
    if (typeof v !== "string") return false;
    try {
      parsePrefix(v);
      return true;
    } catch {
      return false;
    }
  });
  const resolver = new dns.Resolver({ timeout: 3000, tries: 2 });
  const found = await verifiedSubnets(
    subnets24(announced),
    src.ptr,
    {
      reverse: (ip) => resolver.reverse(ip),
      resolve4: (name) => resolver.resolve4(name),
      resolveCname: (name) => resolver.resolveCname(name),
    },
    { deadline: Date.now() + 20 * 60_000 },
  ).finally(() => resolver.cancel());
  if (found.errors > found.lookups / 100) {
    throw new Error(`${found.errors} of ${found.lookups} DNS lookups failed`);
  }
  if (!found.subnets.length) throw new Error(`no address of AS${src.asn} has a confirmed ${src.ptr.join(" or ")} name`);
  return found.subnets.map(parsePrefix);
}

async function fromSource(src: Source): Promise<Prefix[]> {
  if (src.type === "asn-rdns") return fromDns(src);
  return fromHttp(src);
}

async function fromHttp(src: HttpSource): Promise<Prefix[]> {
  const key = `${src.url}\n${src.selector ?? ""}`;
  if (!fetched.has(src.url)) fetched.set(src.url, download(src.url));
  const out: Prefix[] = [];
  let bad = 0;
  for (const raw of entries(src, await fetched.get(src.url)!)) {
    let p: Prefix;
    try {
      p = parsePrefix(raw);
    } catch (e) {
      bad++;
      if (bad <= 10) problems.push(`${src.url}: ${(e as Error).message}`);
      continue;
    }
    const why = rejectPrefix(p);
    if (why) {
      if (++bad <= 10) problems.push(`${src.url}: ${prefixText(p)} skipped, ${why}`);
      continue;
    }
    out.push(p);
  }
  if (bad > 10) problems.push(`${src.url}: ${bad - 10} more bad entries`);
  if (!out.length) throw new Error(`no usable ranges (${key.replace("\n", " ")})`);
  return out;
}

function order(a: Prefix, b: Prefix): number {
  if (a.v6 !== b.v6) return a.v6 ? 1 : -1;
  if (a.net !== b.net) return a.net < b.net ? -1 : 1;
  return a.len - b.len;
}

function sortUnique(list: string[]): string[] {
  const seen = new Map(list.map((t) => [t, parsePrefix(t)] as const));
  return [...seen.entries()].sort((a, b) => order(a[1], b[1])).map(([t]) => t);
}

const result: Output = { generated_at: now, bots: {} };
for (const bot of bots) {
  const base = { categories: bot.categories, sources: [...new Set(bot.sources.map(label))] };
  const got = await Promise.allSettled(bot.sources.map(fromSource));
  const failed = got.flatMap((g, i) => (g.status === "rejected" ? [`${label(bot.sources[i])}: ${quote((g.reason as Error).message)}`] : []));
  if (bot.sources.length && !failed.length) {
    const prefixes = got.flatMap((g) => (g.status === "fulfilled" ? g.value.map(prefixText) : []));
    result.bots[bot.id] = { ...base, prefixes: sortUnique(prefixes) };
    continue;
  }
  problems.push(...failed.map((f) => `${bot.id}: ${f}`));
  const old = previous?.bots?.[bot.id];
  if (!old?.prefixes?.length) continue;
  const since = String(old.stale_since ?? previous!.generated_at);
  if (!(Date.now() - Date.parse(since) <= staleLimit)) {
    problems.push(`${bot.id}: dropped, its sources failed since ${quote(since)}`);
    continue;
  }
  const kept = old.prefixes.filter((t) => {
    try {
      return !rejectPrefix(parsePrefix(t)) && prefixText(parsePrefix(t)) === t;
    } catch {
      return false;
    }
  });
  if (kept.length !== old.prefixes.length) problems.push(`${bot.id}: ${old.prefixes.length - kept.length} kept ranges failed the checks and were dropped`);
  problems.push(`${bot.id}: kept ${kept.length} ranges from ${quote(since)}`);
  if (kept.length) result.bots[bot.id] = { ...base, prefixes: sortUnique(kept), stale_since: since };
}

const all = sortUnique(Object.values(result.bots).flatMap((b) => b.prefixes));
const before = sortUnique(Object.values(previous?.bots ?? {}).flatMap((b) => b.prefixes));
const grown = (now: bigint, then: bigint) => then > 0n && now > then * 2n;
const [cur, old] = [size(all), size(before)];
const refused = (!values["allow-growth"] && (grown(cur.v4, old.v4) || grown(cur.v6, old.v6))) || !all.length;

fs.mkdirSync(values.out!, { recursive: true });
const report = [
  ...problems.map((p) => `- ${p}`),
  ...(refused ? [`- Refused to publish: ${all.length} ranges (IPv4 ${cur.v4} addresses, IPv6 ${cur.v6} /64s), before ${before.length} (IPv4 ${old.v4}, IPv6 ${old.v6}). Check the new ranges, then run the workflow with allow_growth`] : []),
].join("\n").slice(0, 50_000);
fs.writeFileSync(path.join(values.out!, "report.md"), report ? report + "\n" : "");
if (report) console.error(report);

const changed = !refused && all.join("\n") !== before.join("\n");
const resignAfter = 3 * 24 * 3600 * 1000;
const publish = !refused && (changed || !previous || Date.now() - Date.parse(previous.generated_at) > resignAfter);
if (!refused) {
  const header = [
    `# Trusted bot IP ranges, generated ${now}`,
    "# https://github.com/ingrest-dev/trusted-bots",
    `# ${Object.keys(result.bots).length} bots: ${Object.keys(result.bots).join(" ")}`,
  ];
  fs.writeFileSync(path.join(values.out!, "trusted-bots.txt"), [...header, ...all].join("\n") + "\n");
  fs.writeFileSync(path.join(values.out!, "trusted-bots.json"), JSON.stringify(result, null, 2) + "\n");
}
console.log(`${all.length} ranges from ${Object.keys(result.bots).length} bots, changed: ${changed}, publish: ${publish}`);
if (process.env.GITHUB_OUTPUT) fs.appendFileSync(process.env.GITHUB_OUTPUT, `changed=${changed}\npublish=${publish}\nrefused=${refused}\n`);
process.exit(refused ? 3 : 0);
