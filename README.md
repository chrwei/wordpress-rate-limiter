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
- **Guards by region**: Blocks or penalizes traffic from high-risk countries with configurable policies

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

### Regional Traffic Controls
- **GeoIP detection**: Uses CloudFlare's `CF-IPCountry` header with fallback to ip-api.com (cached 24 hours)
- **Blocked countries**: Completely block traffic from specified countries with 403 Forbidden
- **Penalized countries**: Apply dual penalties to high-risk regions:
  - **Reduced rate limits**: Cut soft/hard thresholds by configurable percentage (default 50%)
  - **Initial violations**: Start with pre-existing violation score for faster escalation (default 2)
- **Default lists**: North Korea and Syria blocked; Russia, China, Iran, and Belarus penalized
- **Fully configurable**: Per-site and network-wide settings for country lists and penalty severity

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

### Regional Traffic Control System
When regional controls are enabled, the plugin applies geography-based policies:

1. **Country Detection** (hierarchical with caching):
   - First: Check CloudFlare's `CF-IPCountry` header (instant, no latency)
   - Fallback: Query ip-api.com free API (45 req/min limit)
   - Cache result for 24 hours to minimize API calls

2. **Blocked Countries** (complete access denial):
   - Requests from blocked countries receive immediate 403 Forbidden
   - No rate limit evaluation—blocked before any counting occurs
   - Default: North Korea (KP), Syria (SY)

3. **Penalized Countries** (dual penalty system):
   - **Penalty 1—Reduced Limits**: Rate limits multiplied by `(100 - penalty_pct) / 100`
     - Example: 50% penalty on login (6/12 req/min) → 3/6 req/min
     - Applies to both endpoint-specific and global per-IP limits
   - **Penalty 2—Initial Violations**: Violation score pre-set (default: 2)
     - Clean IP: 1st block = 2 min, 2nd = 4 min, 3rd = 8 min
     - Penalized IP: Starts with 2 violations, so 1st block = 8 min, 2nd = 16 min
   - Default: Russia (RU), China (CN), Iran (IR), Belarus (BY)

Combined effect: Penalized countries hit rate limits faster AND get longer blocks when they do.

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
- **Violation probation (hours)**: how long violation "heat" is retained before decaying
- **Regional Traffic Controls**
  - **Enable regional limits**: toggle country-based blocking/penalties
  - **Blocked countries**: ISO 3166-1 alpha-2 codes (e.g. `KP`, `SY`), one per line
  - **Penalized countries**: ISO codes for reduced limits (e.g. `RU`, `CN`, `IR`, `BY`)
  - **Penalty: limit reduction (%)**: percentage to reduce rate limits (0-100)
  - **Penalty: initial violations**: starting violation score for penalized countries (0-10)
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
- **Regional controls** (if enabled):
  - GeoIP lookup via CloudFlare header or ip-api.com (cached 24h)
  - **Blocked countries** → immediate 403 Forbidden, no further processing
  - **Penalized countries** → reduced rate limits + initial violation score applied
- **Time-aware thresholds**:
  - Endpoints have baseline "daytime" *soft*/*hard* thresholds.
  - At night (outside configured hours) thresholds are doubled.
  - Penalized countries get additional reduction (configurable %, default 50%).
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
  - `block_soft`, `block_hard`, `block_global`, `blocked_fast_deny`, `block_country`
  - `bypass_secret`, `bypass_allowlist`, `bypass_verified_bot`
- Hook for external shipping:

  ```php
  add_action('netrl_log_event', function($siteId, $payload){
    // Send to your logger / APM
  }, 10, 2);
  ```

Example log lines:

```
[netrl] {"ts":1732483200,"site":3,"type":"block_hard","ip":"203.0.113.5","uri":"/wp-login.php","method":"POST","rule":"login","count":19,"soft":6,"hard":12,"until":1732483500}
[netrl] {"ts":1732483245,"site":3,"type":"block_country","ip":"185.220.101.45","uri":"/wp-login.php","method":"POST","country":"RU"}
```

---

## Configuration Notes

- **Probation window**: longer values keep abusive IPs "hot" longer; shorter values forgive quicker.
- **Network vs Site**: Site options override Network defaults; unspecified fields inherit.
- **Timezone**: Uses the site's `timezone_string`; defaults to `America/Los_Angeles` if unset.
- **Object cache**: Strongly recommended in production for accurate atomic counters (Redis/Memcached prevent race conditions).
- **Regional controls**:
  - **GeoIP source**: Best performance behind CloudFlare (instant header lookup). Without CloudFlare, relies on ip-api.com with 24h caching.
  - **Country codes**: Use ISO 3166-1 alpha-2 format (e.g., `US`, `GB`, `RU`). Codes are case-insensitive but stored uppercase.
  - **Penalty tuning**: Start with 50% reduction and 2 initial violations, adjust based on your threat landscape.
  - **Privacy note**: GeoIP lookups may be subject to data privacy regulations in some jurisdictions.

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

### Test regional controls (CloudFlare)

When behind CloudFlare, you can test by spoofing the country header locally:

```bash
# Test blocked country (should get 403)
curl -I -H 'CF-IPCountry: KP' https://example.com/wp-login.php

# Test penalized country (should have stricter limits)
curl -I -H 'CF-IPCountry: RU' https://example.com/wp-login.php
```

Without CloudFlare, the plugin will use ip-api.com based on your actual IP. Use a VPN or proxy to test from different countries, or temporarily add your IP to the penalized/blocked list for testing.

---

## Troubleshooting

- **Network settings page not visible**: Ensure file is in `wp-content/mu-plugins/` root (or use a loader) and you are **Super Admin**.
- **Unexpected blocks**:
  - Check `Retry-After`, `X-RateLimit-Reset`, and error log for `block_*` entries.
  - Confirm time window and thresholds (day vs night).
  - Review allowlist settings and verified bot rules.
  - If regional controls are enabled, verify country detection in logs (look for `country` field).
- **Behind reverse proxy/CDN**:
  - Validate which IP header is trusted and confirm edge addresses.
  - For CloudFlare: Ensure `CF-IPCountry` header is being passed through.
- **Regional controls not working**:
  - Check if CloudFlare's `CF-IPCountry` header is present: `curl -I https://yoursite.com | grep -i cf-ipcountry`
  - Without CloudFlare: Verify ip-api.com is accessible (not blocked by firewall)
  - Check error logs for GeoIP lookup failures
  - Test with known country codes in settings
- **False GeoIP detection**:
  - GeoIP databases can be inaccurate, especially for VPNs, cloud providers, or mobile carriers
  - Consider using IP allowlist for known good IPs that are misclassified
  - GeoIP cache is 24 hours; clear transients to force refresh: `wp transient delete netrl:geo:*`

---

## Extensibility

- **Action**: `netrl_log_event` for shipping logs elsewhere.
- The code is organized to allow swapping rule tables, thresholds, or adding new protected endpoints.

---

## Limitations

- Transient fallback isn't atomic under heavy concurrency (multiple requests can read-modify-write the same counter simultaneously, causing inaccurate counts). Use a persistent object cache in production.
- Only a fixed set of endpoints are protected by default (adjust in code if needed).
- **Regional controls**:
  - GeoIP accuracy varies; VPNs, proxies, and cloud providers can be misclassified
  - Without CloudFlare, relies on external API (ip-api.com) with rate limits (45 req/min)
  - Initial GeoIP lookup adds latency (2s timeout) if CloudFlare header absent and cache miss
  - Sophisticated attackers can use VPNs or proxies in non-penalized countries

---

## Changelog (high-level)

- **Regional traffic controls**: GeoIP-based blocking and penalties for high-risk countries
  - CloudFlare header + ip-api.com fallback with 24h caching
  - Blocked countries list (complete 403 denial)
  - Penalized countries list (dual penalty: reduced limits + initial violations)
  - Configurable penalty severity and violation scores
- Per-site and network settings pages
- Allowlist (UA, rDNS, IP/CIDR, REST, ajax actions)
- Secret header bypass
- Verified-bot checks with rDNS + forward confirmation
- Logging and `netrl_log_event` hook
- Configurable probation window
- OPTIONS/HEAD bypass, Site Health bypass
- Two-bucket counters; global clamp

---

## License

Choose and include a license appropriate for your use (e.g., MIT).
