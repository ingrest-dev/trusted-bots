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

The selection lives in [`ingrest/bots.json`](../ingrest/bots.json): each bot id from the catalog with the hosts it may download ranges from.

- Search engines: Google (crawlers, inspection tool, feed fetcher, site verification), Bing, Apple, DuckDuckGo, Mojeek
- AI crawlers and fetchers: Anthropic, OpenAI, Perplexity, DuckAssist, Common Crawl
- Link previews: Bing and Microsoft previews, Telegram
- Uptime monitors: UptimeRobot, Better Stack, Pingdom, StatusCake, Checkly, Sentry
- Webhooks: GitHub, Stripe

Left out on purpose: lists that cover a whole cloud or company network rather than a bot (Cloudflare, AWS Route 53 health checks, Meta, New Relic on a shared S3 bucket), scanners (Censys), SEO and ad bots, small bots nobody vouches for. Bots that publish no ranges and offer only reverse DNS checks (Yandex, Baidu, Seznam) cannot be listed.

## How a build stays trustworthy

A daily workflow ([`trusted-bots.yml`](workflows/trusted-bots.yml)):

1. Merges new upstream commits only if they touch neither `.github/` nor `ingrest/` and every source of our bots stays plain https on its allowed host with a supported selector (`ingrest/check.ts`). Anything else is held and reported in an issue. Code from upstream is never run.
2. Downloads every source and keeps a range only if it is valid, not reserved, and no wider than /16 (IPv4) or /28 (IPv6) (`ingrest/build.ts`). A source that fails keeps that bot's ranges from the previous build, marked `stale_since`.
3. Refuses to publish when the address count more than doubles; a maintainer checks the change and reruns with `allow_growth`.
4. Signs both files with minisign and replaces the release assets when the ranges changed, and at least every 3 days so a signature is never old. Consumers should reject a file signed more than 14 days ago: it means the builds stopped.

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
