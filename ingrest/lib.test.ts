import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { test } from "node:test";
import { catalogDrift, loadBots, parsePrefix, subnets24, verifiedSubnets, prefixText, rejectPrefix, select, size } from "./lib.ts";

test("selectors used by the catalog", () => {
  const google = { prefixes: [{ ipv4Prefix: "1.2.3.0/24" }, { ipv6Prefix: "2001:4860::/32" }] };
  assert.deepEqual(select(google, '$.prefixes[*]["ipv6Prefix","ipv4Prefix"]'), ["1.2.3.0/24", "2001:4860::/32"]);
  assert.deepEqual(select(google, "$.prefixes[*].ipv4Prefix"), ["1.2.3.0/24"]);
  assert.deepEqual(select({ a: ["1.1.1.1"], b: ["2.2.2.2"] }, "$.*[*]"), ["1.1.1.1", "2.2.2.2"]);
  assert.deepEqual(select([{ ip: "3.3.3.3" }, { ip: 4 }], "$[*].ip"), ["3.3.3.3", 4]);
  const aws = { prefixes: [{ service: "ROUTE53_HEALTHCHECKS", ip_prefix: "5.5.5.0/24" }, { service: "EC2", ip_prefix: "6.0.0.0/8" }] };
  assert.deepEqual(select(aws, '$.prefixes[?(@.service=="ROUTE53_HEALTHCHECKS")].ip_prefix'), ["5.5.5.0/24"]);
  for (const bad of ["prefixes", "$..ip", "$.a[0]", "$.prefixes[*]['ip']"]) {
    assert.throws(() => select({}, bad), /unsupported selector/);
  }
});

test("prefixes are normalized and checked", () => {
  assert.equal(prefixText(parsePrefix("1.2.3.4/24")), "1.2.3.0/24");
  assert.equal(prefixText(parsePrefix("1.2.3.4")), "1.2.3.4/32");
  assert.equal(prefixText(parsePrefix("2001:0db9:0000:0000:0001::/80")), "2001:db9:0:0:1::/80");
  assert.equal(prefixText(parsePrefix("2a0a:a440::1/29")), "2a0a:a440::/29");
  for (const bad of ["1.2.3/24", "1.2.3.4/33", "1.2.3.4/x", "::ffff:1.2.3.4", "1.2.3.4/24/1", "nope", "1:2:3:4:5:6:7:8%a:b", "2a00::%x"]) {
    assert.throws(() => parsePrefix(bad), bad);
  }
  assert.equal(rejectPrefix(parsePrefix("8.0.0.0/8")), "wider than /16");
  assert.equal(rejectPrefix(parsePrefix("10.1.0.0/16")), "reserved range");
  assert.equal(rejectPrefix(parsePrefix("192.168.1.0/24")), "reserved range");
  assert.equal(rejectPrefix(parsePrefix("fd00::/48")), "not a global unicast IPv6 range");
  assert.equal(rejectPrefix(parsePrefix("2001:db8::/48")), "reserved range");
  assert.equal(rejectPrefix(parsePrefix("2001:0:1::/48")), "reserved range");
  assert.equal(rejectPrefix(parsePrefix("192.88.99.0/24")), "reserved range");
  assert.equal(rejectPrefix(parsePrefix("2a00::/16")), "wider than /28");
  assert.equal(rejectPrefix(parsePrefix("66.249.64.0/27")), "");
  assert.deepEqual(size(["1.2.3.0/24", "1.2.4.4/32", "2001:4860::/63"]), { v4: 257n, v6: 2n });
});

test("pinned sources are checked and catalog changes are only reported", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "trusted-bots-"));
  const pinnedFile = path.join(dir, "bots.json");
  const catalogFile = path.join(dir, "catalog.json");
  const ours = JSON.parse(fs.readFileSync(path.join(import.meta.dirname, "bots.json"), "utf-8"));
  const real = JSON.parse(fs.readFileSync(path.join(import.meta.dirname, "..", "well-known-bots.json"), "utf-8"));
  const pinned = (edit: (bots: any) => void) => {
    const copy = structuredClone(ours);
    edit(copy);
    fs.writeFileSync(pinnedFile, JSON.stringify(copy));
    return loadBots(pinnedFile).problems.join();
  };
  assert.equal(pinned(() => {}), "");
  assert.match(pinned((b) => (b["google-crawler"].sources[0].url = "http://developers.google.com/x.json")), /plain https URL/);
  assert.match(pinned((b) => (b["google-crawler"].sources[0].url = "https://u:p@developers.google.com/x.json")), /plain https URL/);
  assert.match(pinned((b) => (b["google-crawler"].sources[0].selector = "$..ip")), /unsupported selector/);
  assert.match(pinned((b) => (b["google-crawler"].sources = [])), /google-crawler: has no IP range source/);

  const { bots } = loadBots();
  const drift = (edit: (bots: { id: string; verification: any[] }[]) => void) => {
    const copy = structuredClone(real);
    edit(copy);
    fs.writeFileSync(catalogFile, JSON.stringify(copy));
    return catalogDrift(bots, catalogFile);
  };
  const google = (b: { id: string; verification: any[] }[]) => b.find((x) => x.id === "google-crawler")!;
  assert.deepEqual(drift(() => {}), []);
  assert.match(drift((b) => (google(b).verification[0].sources[0].url = "https://duckduckgo.com/ac/?q=45.1.0.0/16")).join(), /google-crawler: the catalog lists other sources: .*duckduckgo/);
  assert.match(drift((b) => (google(b).verification[0].sources[0].selector = "$.*[*]")).join(), /google-crawler: the catalog lists other sources/);
  assert.match(drift((b) => google(b).verification[0].sources.push({ type: "http-text", url: "https://evil.example/x" })).join(), /google-crawler/);
  assert.match(drift((b) => b.splice(b.indexOf(google(b)), 1)).join(), /google-crawler: removed from the catalog/);
  fs.rmSync(dir, { recursive: true });
});

test("reverse DNS keeps only /24s with confirmed robot names", async () => {
  assert.equal(subnets24(["198.51.100.0/24", "5.255.252.0/23", "10.0.0.0/22", "5.255.253.0/25", "2a02:6b8::/32"]).length, 2);
  assert.equal(subnets24(["37.9.64.0/18", "37.9.87.0/24"], 64).length, 64);
  assert.throws(() => subnets24(["5.0.0.0/16"], 100), /more than 100/);
  const robot = (ip: string) => `${ip.replaceAll(".", "-")}.spider.yandex.com`;
  const ptr: Record<string, string[]> = {
    "5.255.252.1": [robot("5.255.252.1") + "."],
    "5.255.252.17": [robot("5.255.252.17")],
    "5.255.253.1": ["fake.spider.yandex.com.evil.example"],
    "5.255.253.17": ["evil\\.spider.yandex.com"],
    "5.255.253.33": [robot("5.255.253.33")],
    "5.255.253.49": [robot("5.255.253.49")],
    "77.88.5.1": [robot("77.88.5.1")],
    "77.88.5.17": [robot("77.88.5.17")],
    "77.88.4.1": [robot("77.88.4.1")],
    "77.88.4.17": [robot("77.88.4.17")],
  };
  const forward: Record<string, string[]> = {
    [robot("5.255.252.1")]: ["5.255.252.1"],
    [robot("5.255.252.17")]: ["5.255.252.17"],
    "evil\\.spider.yandex.com": ["5.255.253.17"],
    [robot("5.255.253.33")]: ["9.9.9.9"],
    [robot("5.255.253.49")]: ["5.255.253.49"],
    [robot("77.88.5.1")]: ["77.88.5.1"],
    [robot("77.88.5.17")]: ["77.88.5.17"],
    [robot("77.88.4.1")]: ["77.88.4.1"],
    [robot("77.88.4.17")]: ["77.88.4.17"],
  };
  const cname: Record<string, string[]> = { [robot("77.88.4.17")]: ["t.evil.example"] };
  const fail = (code: string) => Object.assign(new Error(code), { code });
  let outage = false;
  const lookup = {
    reverse: async (ip: string) => {
      if (outage && ip.endsWith(".33")) throw fail("ETIMEOUT");
      if (!ptr[ip]) throw fail("ENOTFOUND");
      return ptr[ip];
    },
    resolve4: async (name: string) => {
      if (!forward[name]) throw fail("ENOTFOUND");
      return forward[name];
    },
    resolveCname: async (name: string) => {
      if (!cname[name]) throw fail("ENODATA");
      return cname[name];
    },
  };
  const nets = subnets24(["5.255.252.0/23", "77.88.4.0/23"]);
  const got = await verifiedSubnets(nets, [".spider.yandex.com"], lookup, { workers: 3 });
  assert.deepEqual(got.subnets, ["5.255.252.0/24", "77.88.5.0/24"]);
  assert.equal(got.errors, 0);
  outage = true;
  const down = await verifiedSubnets(nets, [".spider.yandex.com"], lookup, { workers: 3 });
  assert.ok(down.errors > 0);
  await assert.rejects(verifiedSubnets(nets, [".spider.yandex.com"], lookup, { deadline: Date.now() - 1 }), /ran out of time/);
});

test("reverse DNS sources are validated", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "trusted-bots-"));
  const file = path.join(dir, "bots.json");
  const check = (src: unknown) => {
    fs.writeFileSync(file, JSON.stringify({ y: { categories: [], sources: [src] } }));
    return loadBots(file).problems.join();
  };
  assert.equal(check({ type: "asn-rdns", asn: 13238, ptr: [".spider.yandex.com"] }), "");
  assert.match(check({ type: "asn-rdns", asn: "13238", ptr: [".spider.yandex.com"] }), /bad AS number/);
  assert.match(check({ type: "asn-rdns", asn: 13238, ptr: ["yandex.com"] }), /ptr must list/);
  assert.match(check({ type: "asn-rdns", asn: 13238, ptr: [".com"] }), /ptr must list/);
  assert.match(check({ type: "asn-rdns", asn: 13238, ptr: [] }), /ptr must list/);
  fs.rmSync(dir, { recursive: true });
});
