# Trusted bots

Signed IP ranges of search engines, AI crawlers, link preview bots, uptime monitors and webhook senders, rebuilt daily from the lists that the bot operators publish themselves.

The list is made for firewalls: if a server blocks countries by IP, Googlebot from a blocked country never reaches the site and indexing stops. A User-Agent can be faked, an IP range from the operator's own list cannot.

This repository is a fork of [arcjet/well-known-bots](https://github.com/arcjet/well-known-bots) (MIT). The catalog there holds no addresses, only where each operator publishes its ranges. We take a short, reviewed selection of it and build the address list from those first-party sources only.

## Download

Release [`bots`](https://github.com/ingrest-dev/trusted-bots/releases/tag/bots), always the latest build:

| File | Content |
| --- | --- |
| [`trusted-bots.txt`](https://github.com/ingrest-dev/trusted-bots/releases/download/bots/trusted-bots.txt) | One CIDR per line, IPv4 then IPv6, `#` comments |
| [`trusted-bots.json`](https://github.com/ingrest-dev/trusted-bots/releases/download/bots/trusted-bots.json) | Per bot: categories, sources, ranges, `stale_since` when a source failed |
| `*.minisig` | [minisign](https://jedisct1.github.io/minisign/) signatures |

Verify a download before use:

```
minisign -Vm trusted-bots.txt -P RWTL/AmYyVkstBnn2TyPujxju9+AjhF7C/NxS4rnLh2IDsUm5xKXurJX
```

The trusted comment carries `timestamp:<unix time>`. Reject a file older than the one you already have, so an old list cannot be replayed.

## What is in the list

The selection lives in [`ingrest/bots.json`](../ingrest/bots.json): each bot id from the catalog with its categories and the exact sources (type, URL, selector) we download. The build reads only this file, never the upstream catalog, so a catalog change cannot add a source.

- Search engines: Google (crawlers, inspection tool, feed fetcher, site verification), Bing, Apple, DuckDuckGo, Mojeek, Yandex (IPv4)
- AI crawlers and fetchers: Anthropic, OpenAI, Perplexity, DuckAssist, Common Crawl
- Link previews: Bing and Microsoft previews, Telegram
- Uptime monitors: UptimeRobot, Better Stack, Pingdom, StatusCake, Checkly, Sentry
- Webhooks: GitHub, Stripe

Left out on purpose: lists that cover a whole cloud or company network rather than a bot (Cloudflare, AWS Route 53 health checks, Meta, New Relic on a shared S3 bucket), scanners (Censys), SEO and ad bots, small bots nobody vouches for. Yandex publishes no ranges: its robots are found by reverse DNS instead. The build takes the IPv4 networks announced by Yandex's own AS13238 (RIPEstat; Yandex Cloud is a separate AS), checks 16 addresses in every /24, and keeps a /24 only if an address has a `*.spider.yandex.com` name that resolves back to it. IPv6 is too large to sample, so Yandex over IPv6 is not covered. Baidu and Seznam are not listed yet.

## How a build stays trustworthy

A daily workflow ([`trusted-bots.yml`](workflows/trusted-bots.yml)):

1. Merges new upstream commits, always keeping our own `.github/` and `ingrest/` (upstream workflows never land here); merges with other conflicts, symlinks or submodules are held. Code from upstream is never run: our scripts run from a copy taken before the merge. When the catalog lists other sources for one of our bots than `ingrest/bots.json`, the run reports it so a maintainer can review and update the pinned entry.
2. Downloads every pinned source and keeps a range only if it is valid, not reserved, and no wider than /16 (IPv4) or /28 (IPv6). A source that fails keeps that bot's ranges from the previous build, checked again and marked `stale_since`, for 14 days at most. The previous build is used only after its signature checks out.
3. Refuses to publish when the address count more than doubles; a maintainer checks the change and reruns with `allow_growth`.
4. Signs both files with minisign and replaces the release assets when the ranges changed, and at least every 3 days so a signature is never old. Consumers should reject a file signed more than 14 days ago: it means the builds stopped. Assets are replaced one by one, so a download during an upload can fail verification: keep the previous copy then.

Problems of the last run are kept in one open issue labeled `build-report`, closed after a clean run.

## Local run

Node.js 26, no dependencies:

```
node --test ingrest/lib.test.ts
node ingrest/check.ts
node ingrest/build.ts --out dist [--previous old/trusted-bots.json]
```

## License

MIT, see [LICENSE](../LICENSE). The bot catalog is by Arcjet; the IP ranges belong to their operators and are published by them for this use.
