# Network Rate Limiter (Progressive, Time-Aware) - Fighting bots and abuse on WordPress

![WP Rate Limiter](https://blog.greggant.com/images/posts/2025-09-24-ratelimiter.png)

## What This Plugin Does

If you want a more digestable version, I wrotea  [blog post with a more in depth explanation](https://blog.greggant.com/posts/2025/09/24/wordpress-rate-limter.html)

This WordPress plugin protects your site from abuse by limiting how many requests each visitor can make to sensitive endpoints like login pages, admin interfaces, and APIs. Think of it as a smart bouncer that:

- **Watches the door**: Monitors requests to `/wp-login.php`, `/xmlrpc.php`, `/admin-ajax.php`, and `/wp-json/*` endpoints
- **Counts carefully**: Tracks each IP address separately using sophisticated counting that works like a sliding window
- **Gets stricter over time**: Uses progressive penalties—first-time offenders get shorter blocks, repeat offenders get longer ones
- **Knows the difference**: Automatically allows legitimate search engine bots (Google, Bing) and trusted monitoring tools
- **Adapts to your schedule**: Enforces stricter limits during busy "daytime" hours, relaxes them at night

## Why You Need This

Without rate limiting, attackers can:
- **Brute force login attempts** at unlimited speed
- **Overwhelm your XML-RPC interface** with spam or attack requests  
- **Flood your REST API** causing performance issues
- **Exhaust server resources** through rapid-fire requests, leading to downtime or degraded performance

This plugin stops these attacks while allowing normal users and legitimate bots to access your site without interference.

---

## Core Features

### Smart Request Monitoring
- **Protected endpoints**: Automatically monitors `wp-login.php`, `xmlrpc.php`, `admin-ajax.php`, `wp-json/*`
- **Accurate counting**: Uses sophisticated two-bucket system that approximates a sliding window for precise rate measurement
- **Time-aware limits**: Enforces stricter "daytime" thresholds, relaxed limits at night (configurable per-site hours)
- **Global protection**: Prevents any single IP from overwhelming your server across all protected endpoints

### Progressive Enforcement
- **Escalating penalties**: First violations get short blocks (2 minutes), repeat offenses get exponentially longer blocks (up to 60 minutes)
- **Smart probation**: Violation "heat" automatically decays after a configurable probation period if IP behaves
- **Immediate blocking**: Severe violations (hard limits) trigger instant blocks without warnings

### Intelligent Exemptions
- **Verified search engines**: Automatically allows legitimate Google/Bing bots using reverse DNS verification
- **Flexible allowlists**: Skip rate limiting for specific IPs, user agents, DNS suffixes, REST API endpoints, or admin-ajax actions
- **Secret header bypass**: Trusted monitoring tools can use a custom header to bypass all limits
- **Built-in exceptions**: Logged-in admins, WordPress cron jobs, and site health checks are automatically exempted

### Network Features
- **WordPress Multisite support**: Network-wide defaults with per-site overrides
- **Comprehensive logging**: Optional JSON logging to error log plus action hooks for external systems
- **Production-ready**: Supports Redis/Memcached for atomic counters in high-traffic environments

## How It Works (Technical Overview)

### The Two-Bucket Counting System
Instead of a simple counter, this plugin uses two overlapping 1-minute "buckets" to approximate a sliding window:
- **Current bucket**: Counts requests in the current minute
- **Previous bucket**: Retains counts from the previous minute
- **Weighted calculation**: Combines both buckets using time-based weighting for smooth, accurate rate limiting

This approach prevents the "reset spike" problem where attackers could send bursts of requests right after a fixed window resets.

### Progressive Penalty System
When an IP violates rate limits:
1. **First offense**: 2-minute block
2. **Second offense**: 4-minute block (2 × 2¹)
3. **Third offense**: 8-minute block (2 × 2²)
4. **Continues doubling** up to maximum of 60 minutes

The violation "score" automatically decays after a probation period (default 6 hours) if the IP behaves properly.

### Atomic vs Non-Atomic Counting
- **With object cache (Redis/Memcached)**: Atomic increments prevent race conditions where multiple requests might read-modify-write simultaneously
- **Without object cache (transients fallback)**: Non-atomic but acceptable for soft rate limiting scenarios

---

## Requirements

- WordPress 5.8+ (PHP 7.4+)
- Recommended: persistent object cache (Redis/Memcached) for atomic counters
- Works without object cache using transients (non-atomic but acceptable for soft rate limiting)

---

## Installation

1. Create (or use) the **mu-plugins** directory:

   ```
   wp-content/mu-plugins/
   ```

2. Place the plugin file as:

   ```
   wp-content/mu-plugins/netrl.php
   ```

   If you keep the code in a subfolder, add a loader in the mu-plugins root:

   ```php
   <?php
   // wp-content/mu-plugins/netrl-loader.php
   require_once __DIR__ . '/netrl/netrl.php';
   ```

3. Multisite only: ensure you are a **Super Admin** to access Network Admin.

---

## Admin UI

### Per-site (Settings → Rate Limiter)

- **Enable limiter**: on/off for this site
- **Daytime window**: start/end hour in site timezone
- **Violation probation (hours)**: how long violation “heat” is retained before decaying
- **Allowlist**
  - **User-Agents**: one per line (substring match)
  - **rDNS suffixes**: one per line (e.g. `.uptimerobot.com`); forward DNS re-check required
  - **IPs/CIDRs**: IPv4/IPv6; single IP or CIDR (e.g. `203.0.113.0/24`, `2a00:1a48::/32`)
  - **REST prefixes**: path prefixes under `/wp-json/` to skip (e.g. `/wp-json/oembed/`)
  - **admin-ajax actions**: e.g. `heartbeat`
- **Secret header bypass**
  - **Header name** (e.g. `X-NetRL-Bypass`)
  - **Header value** (shared secret)
- **Logging**
  - **Blocks / throttles**
  - **Bypasses** (secret, allowlist, verified bots)

### Network Admin (Network Admin → Rate Limiter)

- Same fields as per-site page, applied as **defaults**. Individual sites can override.

---

## How It Works

- **Scope**: The limiter runs early (`muplugins_loaded`) and only inspects protected endpoints. Public page views are not affected.
- **Exemptions**: Logged-in admins with `manage_options`, WP-Cron, Site Health endpoint, and **HTTP OPTIONS/HEAD** are skipped.
- **Time-aware thresholds**:
  - Endpoints have baseline “daytime” *soft*/*hard* thresholds.
  - At night (outside configured hours) thresholds are doubled.
- **Counting**:
  - Two 1-minute buckets (current/previous) combined with time-weighted overlap ≈ sliding window.
  - Uses `wp_cache_*` when available for atomic increments; falls back to transients (non-atomic but acceptable for soft limits).
- **Blocking**:
  - If count exceeds **soft** → progressive 429 with backoff.
  - If count exceeds **hard** → immediate block with backoff.
  - **Global clamp** (per-IP across all protected endpoints) is also enforced.
  - Backoff escalates: `base × 2^violations` up to max (exponential backoff increases penalty time); violation score decays after **probation** period.
- **Headers**:
  - Always sets `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Window`
  - On block, sets `Retry-After` and `X-RateLimit-Reset`

---

## Verified Bot Handling (Google/Bing)

A request is exempted **only if**:

1. UA string contains a known Google/Bing bot identifier (e.g., `Googlebot`, `bingbot`)
2. Reverse DNS of the source IP ends with an expected domain (e.g., `.googlebot.com`, `.search.msn.com`)
3. Forward DNS of that hostname resolves back to the same source IP

Result is cached per-site for 7 days. UA must still match on subsequent requests.

---

## Secret Header Bypass

Use for synthetic monitoring or trusted integrations.

- Configure **Header name** and **Header value** in settings.
- Requests carrying an exact match bypass rate limiting.
- Example (curl):

  ```bash
  curl -H 'X-NetRL-Bypass: YOUR_LONG_RANDOM_SECRET' https://example.com/wp-json/
  ```

---

## Allowlist

- **User-Agent substrings**: simple contains check (spoofable; pair with rDNS/IP or header)
- **rDNS suffixes**: e.g., `.uptimerobot.com` (reverse lookup + forward confirmation)
- **IP/CIDR**: IPv4/IPv6 supported via `inet_pton` masking
- **REST prefixes**: skip selected API namespaces
- **admin-ajax actions**: skip specific `action` names

> Default UA list is pre-populated with common crawlers and monitoring tools. Adjust to your environment.

---

## Logging

- Optional JSON lines to the PHP error log; minimal fields, no bodies.
- Event types include:
  - `block_soft`, `block_hard`, `block_global`, `blocked_fast_deny`
  - `bypass_secret`, `bypass_allowlist`, `bypass_verified_bot`
- Hook for external shipping:

  ```php
  add_action('netrl_log_event', function($siteId, $payload){
    // Send to your logger / APM
  }, 10, 2);
  ```

Example log line:

```
[netrl] {"ts":1732483200,"site":3,"type":"block_hard","ip":"203.0.113.5","uri":"/wp-login.php","method":"POST","rule":"login","count":19,"soft":6,"hard":12,"until":1732483500}
```

---

## Configuration Notes

- **Probation window**: longer values keep abusive IPs “hot” longer; shorter values forgive quicker.
- **Network vs Site**: Site options override Network defaults; unspecified fields inherit.
- **Timezone**: Uses the site’s `timezone_string`; defaults to `America/Los_Angeles` if unset.
- **Object cache**: Strongly recommended in production for accurate atomic counters (Redis/Memcached prevent race conditions).

---

## Security Considerations

- **Trusting client IP**: The plugin tries `CF-Connecting-IP`, `X-Real-IP`, then `X-Forwarded-For` (left-most public IP), then `REMOTE_ADDR`. In proxy/CDN setups, ensure your stack only forwards trusted headers and ideally verify the edge proxy IP before trusting X-Forwarded-For.
- **UA allowlists**: UA strings are spoofable; prefer rDNS/IP rules or a **secret header** for monitors.
- **Bypass header**: Treat the header value as a secret. Rotate periodically.

---

## Testing

### Trigger a soft block

```
for i in {1..50}; do curl -s -o /dev/null -w "%{http_code}
" https://example.com/wp-login.php; done
```

Expect `429 Too Many Requests` after crossing the soft/hard thresholds.

### Confirm headers

```
curl -I https://example.com/wp-json/
```

Look for `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Window`.

### Verify bypass (secret header)

```
curl -I -H 'X-NetRL-Bypass: YOUR_SECRET' https://example.com/wp-json/
```

Request should not be rate limited.

---

## Troubleshooting

- **Network settings page not visible**: Ensure file is in `wp-content/mu-plugins/` root (or use a loader) and you are **Super Admin**.
- **Unexpected blocks**:
  - Check `Retry-After`, `X-RateLimit-Reset`, and error log for `block_*` entries.
  - Confirm time window and thresholds (day vs night).
  - Review allowlist settings and verified bot rules.
- **Behind reverse proxy/CDN**:
  - Validate which IP header is trusted and confirm edge addresses.

---

## Extensibility

- **Action**: `netrl_log_event` for shipping logs elsewhere.
- The code is organized to allow swapping rule tables, thresholds, or adding new protected endpoints.

---

## Limitations

- Transient fallback isn't atomic under heavy concurrency (multiple requests can read-modify-write the same counter simultaneously, causing inaccurate counts). Use a persistent object cache in production.
- Only a fixed set of endpoints are protected by default (adjust in code if needed).

---

## Changelog (high-level)

- Add per-site and network settings pages
- Add allowlist (UA, rDNS, IP/CIDR, REST, ajax actions)
- Add secret header bypass
- Add verified-bot checks with rDNS + forward confirmation
- Add logging and `netrl_log_event` hook
- Add configurable probation window
- OPTIONS/HEAD bypass, Site Health bypass
- Two-bucket counters; global clamp

---

## License

Choose and include a license appropriate for your use (e.g., MIT).
