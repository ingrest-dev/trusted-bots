import assert from "node:assert/strict";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { test } from "node:test";
import { loadBots, parsePrefix, prefixText, rejectPrefix, select, size } from "./lib.ts";

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
  for (const bad of ["1.2.3/24", "1.2.3.4/33", "1.2.3.4/x", "::ffff:1.2.3.4", "1.2.3.4/24/1", "nope"]) {
    assert.throws(() => parsePrefix(bad), bad);
  }
  assert.equal(rejectPrefix(parsePrefix("8.0.0.0/8")), "wider than /16");
  assert.equal(rejectPrefix(parsePrefix("10.1.0.0/16")), "reserved range");
  assert.equal(rejectPrefix(parsePrefix("192.168.1.0/24")), "reserved range");
  assert.equal(rejectPrefix(parsePrefix("fd00::/48")), "not a global unicast IPv6 range");
  assert.equal(rejectPrefix(parsePrefix("2001:db8::/48")), "reserved range");
  assert.equal(rejectPrefix(parsePrefix("2a00::/16")), "wider than /28");
  assert.equal(rejectPrefix(parsePrefix("66.249.64.0/27")), "");
  assert.deepEqual(size(["1.2.3.0/24", "1.2.4.4/32", "2001:4860::/63"]), { v4: 257n, v6: 2n });
});

test("catalog changes to our bots are refused", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "trusted-bots-"));
  const file = path.join(dir, "catalog.json");
  const real = JSON.parse(fs.readFileSync(path.join(import.meta.dirname, "..", "well-known-bots.json"), "utf-8"));
  const write = (edit: (bots: { id: string; verification: any[] }[]) => void) => {
    const copy = structuredClone(real);
    edit(copy);
    fs.writeFileSync(file, JSON.stringify(copy));
    return loadBots(file).problems;
  };
  assert.deepEqual(write(() => {}), []);
  const google = (bots: { id: string; verification: any[] }[]) => bots.find((b) => b.id === "google-crawler")!;
  assert.match(write((b) => (google(b).verification[0].sources[0].url = "https://evil.example/ranges.json")).join(), /google-crawler: source host evil.example is not allowed/);
  assert.match(write((b) => (google(b).verification[0].sources[0].url = "http://developers.google.com/x.json")).join(), /plain https/);
  assert.match(write((b) => (google(b).verification[0].sources[0].selector = "$..ip")).join(), /unsupported selector/);
  assert.match(write((b) => (google(b).verification = [{ type: "dns", masks: ["*.googlebot.com"] }])).join(), /google-crawler: has no IP range source/);
  assert.match(write((b) => b.splice(b.indexOf(google(b)), 1)).join(), /google-crawler: not in the catalog any more/);
  fs.rmSync(dir, { recursive: true });
});
