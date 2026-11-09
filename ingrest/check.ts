import * as fs from "node:fs";
import { parseArgs } from "node:util";
import { catalogDrift, loadBots } from "./lib.ts";

const { values } = parseArgs({ options: { catalog: { type: "string" }, drift: { type: "string" } } });
const { bots, problems } = loadBots();
if (problems.length) {
  console.error(problems.map((p) => `- ${p}`).join("\n"));
  process.exit(1);
}
const drift = catalogDrift(bots, values.catalog);
if (values.drift) fs.writeFileSync(values.drift, drift.map((d) => `- ${d}`).join("\n") + (drift.length ? "\n" : ""));
console.log(`${bots.length} bots, ${bots.reduce((n, b) => n + b.sources.length, 0)} sources: ok, ${drift.length} differ from the catalog`);
