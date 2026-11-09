import { loadBots } from "./lib.ts";

const { bots, problems } = loadBots(process.argv[2]);
if (problems.length) {
  console.error(problems.map((p) => `- ${p}`).join("\n"));
  process.exit(1);
}
console.log(`${bots.length} bots, ${bots.reduce((n, b) => n + b.sources.length, 0)} sources: ok`);
