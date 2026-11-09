import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { test } from "node:test";
import { catalogDrift, loadBots, parsePrefix, prefixText, rejectPrefix, select, size } from "./lib.ts";

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
