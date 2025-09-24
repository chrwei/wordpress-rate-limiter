<?php
/**
 * Plugin Name: Network Rate Limiter (Progressive, Time-Aware)
 * Description: Per-IP progressive, time-aware rate limiting for sensitive endpoints. Per-site controls (enable + hours + allowlist + logging + probation), Network Defaults, verified-bot exemptions.
 * Must Use: yes
 */

if (defined('WP_CLI') && WP_CLI) return;

/* =========================================
 * ============= RUNTIME HOOK ==============
 * ========================================= */
add_action('muplugins_loaded', function () {
  // --- Exemptions: admins / cron / health checks ---
  if (function_exists('is_user_logged_in') && is_user_logged_in() && current_user_can('manage_options')) return;
  if (defined('DOING_CRON') && DOING_CRON) return;
  if (isset($_SERVER['REQUEST_URI']) && strpos($_SERVER['REQUEST_URI'], '/wp-json/wp-site-health') === 0) return;

  $reqUri  = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';
  $method  = $_SERVER['REQUEST_METHOD'] ?? 'GET';

  // Do not rate-limit preflight or HEAD requests
  if ($method === 'OPTIONS' || $method === 'HEAD') return;

  $ip      = network_rate_limiter_real_ip();
  $ua      = $_SERVER['HTTP_USER_AGENT'] ?? '';
  $siteKey = is_multisite() ? get_current_blog_id() : 0;

  // Load per-site settings (merged with network defaults)
  $settings = netrl_get_settings($siteKey);
  if (empty($settings['enabled'])) return;

  // --- Secret header bypass (for monitors/synthetics) ---
  if (netrl_secret_header_bypass($settings)) {
    netrl_log($siteKey, 'bypass_secret', [
      'ip'=>$ip,'ua'=>$ua,'uri'=>$reqUri,'method'=>$method
    ], $settings);
    return;
  }

  // --- Allowlist (IP/CIDR, rDNS suffix w/ forward-confirm, UA, REST prefixes, ajax actions) ---
  if (netrl_is_allowlisted($settings, $siteKey, $ip, $ua, $reqUri, $method)) {
    netrl_log($siteKey, 'bypass_allowlist', [
      'ip'=>$ip,'ua'=>$ua,'uri'=>$reqUri,'method'=>$method
    ], $settings);
    return;
  }

  // Allow verified Google/Bing bots (UA + rDNS + forward-confirm), cached per-site
  if (network_rate_limiter_is_verified_bot($siteKey, $ip, $ua)) {
    netrl_log($siteKey, 'bypass_verified_bot', [
      'ip'=>$ip,'ua'=>$ua,'uri'=>$reqUri,'method'=>$method
    ], $settings);
    return;
  }

  // Map to compact rule IDs (keeps key cardinality low)
  $ruleId = netrl_rule_id($reqUri, $method);
  if (!$ruleId) return; // not a protected endpoint

  // Daytime window (site timezone → stricter by day, relaxed by night)
  $tz  = netrl_site_timezone();
  $hr  = (int)(new DateTime('now', $tz))->format('G');
  $isDaytime = netrl_is_daytime((int)$settings['day_start'], (int)$settings['day_end'], $hr);

  // Rule-based limits (daytime baseline, doubled at night)
  $limits = [
    'login:POST'   => ['soft'=>6,   'hard'=>12],
    'login:GET'    => ['soft'=>20,  'hard'=>40],
    'xmlrpc:POST'  => ['soft'=>4,   'hard'=>8],
    'xmlrpc:GET'   => ['soft'=>10,  'hard'=>20],
    'ajax:GET'     => ['soft'=>60,  'hard'=>120],
    'ajax:POST'    => ['soft'=>30,  'hard'=>60],
    'rest:GET'     => ['soft'=>120, 'hard'=>300],
    'rest:POST'    => ['soft'=>20,  'hard'=>40],
  ];
  $key   = $ruleId . ':' . $method;
  $base  = $limits[$key] ?? ['soft'=>60,'hard'=>120];
  $soft  = $isDaytime ? $base['soft'] : $base['soft'] * 2;
  $hard  = $isDaytime ? $base['hard'] : $base['hard'] * 2;

  // Progressive backoff settings (probation TTL is configurable)
  $baseBlock    = 120; // 2 minutes
  $maxBlock     = 3600; // 60 minutes
  $probationHrs = max(1, min(72, (int)($settings['probation_hours'] ?? 6))); // 1..72h
  $probationSec = $probationHrs * HOUR_IN_SECONDS;

  $blockKey = netrl_key('block', $siteKey, $ip);

  // Fast deny if currently blocked
  $blockedUntil = (int) get_transient($blockKey);
  if ($blockedUntil && time() < $blockedUntil) {
    netrl_log($siteKey, 'blocked_fast_deny', [
      'ip'=>$ip,'ua'=>$ua,'uri'=>$reqUri,'method'=>$method,'until'=>$blockedUntil
    ], $settings);
    network_rate_limiter_deny($blockedUntil);
  }

  // Atomic two-bucket counts
  $count       = netrl_minute_count($siteKey, $ruleId, $ip, 60);
  $globalCount = netrl_minute_count($siteKey, 'any',   $ip, 60);
  $globalLimit = $isDaytime ? 120 : 240; // per-minute clamp across all protected endpoints

  // Debug headers
  $remaining = max(0, (int) floor($hard - $count));
  header('X-RateLimit-Limit: ' . (int)$hard);
  header('X-RateLimit-Remaining: ' . $remaining);
  header('X-RateLimit-Window: 60');

  // Global limit check
  if ($globalCount > $globalLimit) {
    $blockSeconds = netrl_next_block_secs($siteKey, $ip, $baseBlock, $maxBlock, $probationSec);
    $until = time() + $blockSeconds;
    set_transient($blockKey, $until, $blockSeconds);
    header('X-RateLimit-Reset: ' . $until);
    netrl_log($siteKey, 'block_global', [
      'ip'=>$ip,'ua'=>$ua,'uri'=>$reqUri,'method'=>$method,
      'count'=>$globalCount,'limit'=>$globalLimit,'until'=>$until
    ], $settings);
    network_rate_limiter_deny($until);
  }

  // Hard burst -> immediate block
  if ($count > $hard) {
    $blockSeconds = netrl_next_block_secs($siteKey, $ip, $baseBlock, $maxBlock, $probationSec);
    $until = time() + $blockSeconds;
    set_transient($blockKey, $until, $blockSeconds);
    header('X-RateLimit-Reset: ' . $until);
    netrl_log($siteKey, 'block_hard', [
      'ip'=>$ip,'ua'=>$ua,'uri'=>$reqUri,'method'=>$method,
      'rule'=>$ruleId,'count'=>$count,'soft'=>$soft,'hard'=>$hard,'until'=>$until
    ], $settings);
    network_rate_limiter_deny($until);
  }

  // Soft threshold -> progressive 429
  if ($count > $soft) {
    $blockSeconds = netrl_next_block_secs($siteKey, $ip, $baseBlock, $maxBlock, $probationSec);
    $until = time() + $blockSeconds;
    set_transient($blockKey, $until, $blockSeconds);
    header('X-RateLimit-Reset: ' . $until);
    netrl_log($siteKey, 'block_soft', [
      'ip'=>$ip,'ua'=>$ua,'uri'=>$reqUri,'method'=>$method,
      'rule'=>$ruleId,'count'=>$count,'soft'=>$soft,'hard'=>$hard,'until'=>$until
    ], $settings);
    network_rate_limiter_deny($until);
  }
}, 1);

/* =========================================
 * ============ ADMIN UI (SITE) ============
 * ========================================= */
add_action('admin_menu', function () {
  add_options_page(
    'Rate Limiter',
    'Rate Limiter',
    'manage_options',
    'netrl_rate_limiter',
    'netrl_render_site_settings_page'
  );
});

/* =========================================
 * ========= ADMIN UI (NETWORK) ============
 * ========================================= */
add_action('network_admin_menu', function () {
  if (!is_multisite()) return;
  $cap = 'manage_network_options';

  add_menu_page(
    'Rate Limiter (Network Defaults)',
    'Rate Limiter',
    $cap,
    'netrl_rate_limiter_network',
    'netrl_render_network_settings_page',
    'dashicons-shield-alt',
    59
  );
  add_submenu_page(
    'settings.php',
    'Rate Limiter (Network Defaults)',
    'Rate Limiter',
    $cap,
    'netrl_rate_limiter_network',
    'netrl_render_network_settings_page'
  );
});

/* =========================================
 * ================ HELPERS ================
 * ========================================= */

function netrl_key(string $suffix, int $site, string $ip): string {
  return "netrl:$suffix:$site:$ip";
}

/** Get merged settings for a site: site option → network defaults → hard defaults */
function netrl_get_settings(int $siteKey): array {
  // Prepopulated defaults (safe starters)
  $hard = [
    'enabled'          => 1,
    'day_start'        => 5,
    'day_end'          => 22, // 5:00–21:59 daytime
    'probation_hours'  => 6,  // violation auto-decay window
    // Allowlist (newline or comma separated)
    'allow_uas'        => "UptimeRobot/2.0\nPingdom.com_bot\npingbot/2.0\nNewRelicPinger\nGhost Inspector\nGooglebot\nGooglebot-Image\nGooglebot-News\nGooglebot-Video\nAdsBot-Google\nAdsBot-Google-Mobile\nGoogle-InspectionTool\nGoogleOther\nGoogle-Read-Aloud\nGoogle-Extended\nbingbot\nBingPreview\nadidxbot\nMicrosoftPreview\nmsnbot\nmsnbot-media\nDuckDuckBot\nDuckDuckGo-Favicons-Bot\nYandexBot\nYandexImages\nSlurp\nApplebot\nBaiduspider\nSeznamBot\nfacebot\nfacebookexternalhit\nTwitterbot\nLinkedInBot\nWhatsApp\nSkypeUriPreview\nTelegramBot\nSemrushBot\nAhrefsBot\nMJ12bot\nDotBot\nStatusCake\nSite24x7\nGTmetrix\nia_archiver\narchive.org_bot\nCCBot",
    'allow_hosts'      => ".uptimerobot.com",
    'allow_ips'        => "",
    'allow_ajax'       => "heartbeat",
    'allow_rest'       => "",
    // Secret header bypass (leave blank to disable)
    'bypass_header'    => "",
    'bypass_value'     => "",
    // Logging
    'log_bypass'       => 0,  // log allowlist/secret/bot bypasses
    'log_blocks'       => 1,  // log soft/hard/global blocks
  ];
  $net  = is_multisite() ? (array) get_site_option('netrl_defaults', []) : [];
  $site = (array) get_option('netrl_settings', []);
  $merged = array_merge($hard, $net, $site);

  // Normalize types
  $merged['enabled']         = !empty($merged['enabled']) ? 1 : 0;
  $merged['day_start']       = max(0, min(23, (int)$merged['day_start']));
  $merged['day_end']         = max(0, min(23, (int)$merged['day_end']));
  $merged['probation_hours'] = max(1, min(72, (int)$merged['probation_hours']));
  $merged['log_bypass']      = !empty($merged['log_bypass']) ? 1 : 0;
  $merged['log_blocks']      = !empty($merged['log_blocks']) ? 1 : 0;
  return $merged;
}

/** Site timezone if set; else America/Los_Angeles (matches prior behavior) */
function netrl_site_timezone(): DateTimeZone {
  $tz = get_option('timezone_string');
  if ($tz && @timezone_open($tz)) return new DateTimeZone($tz);
  return new DateTimeZone('America/Los_Angeles');
}

/** Is current hour within the "daytime" window, supporting wrap-around (e.g., 22→6). */
function netrl_is_daytime(int $start, int $end, int $hour): bool {
  if ($start === $end) return true; // treat as always-day if equal
  if ($start < $end) return ($hour >= $start && $hour < $end);
  return ($hour >= $start || $hour < $end); // wraps midnight
}

/** Secret header bypass */
function netrl_secret_header_bypass(array $settings): bool {
  $h = trim((string)($settings['bypass_header'] ?? ''));
  $v = (string)($settings['bypass_value'] ?? '');
  if ($h === '' || $v === '') return false;
  $key = 'HTTP_' . strtoupper(str_replace('-', '_', $h));
  return isset($_SERVER[$key]) && hash_equals($v, (string)$_SERVER[$key]);
}

/** Is this request allowlisted by any rule? */
function netrl_is_allowlisted(array $settings, int $siteKey, string $ip, string $ua, string $uri, string $method): bool {
  // 1) IP / CIDR (IPv4/IPv6)
  $cidrs = netrl_list($settings['allow_ips'] ?? '');
  if ($cidrs && netrl_ip_matches($ip, $cidrs)) return true;

  // 2) rDNS suffix (w/ forward confirm)
  $suffixes = netrl_list($settings['allow_hosts'] ?? '');
  if ($suffixes && netrl_rdns_suffix_allows($ip, $suffixes)) return true;

  // 3) UA substring
  $uas = netrl_list($settings['allow_uas'] ?? '');
  if ($uas) {
    $u = strtolower($ua);
    foreach ($uas as $needle) {
      $needle = strtolower($needle);
      if ($needle !== '' && strpos($u, $needle) !== false) return true;
    }
  }

  // 4) REST prefixes (path-based)
  if (stripos($uri, '/wp-json/') === 0) {
    $restPrefixes = netrl_list($settings['allow_rest'] ?? '');
    foreach ($restPrefixes as $pfx) {
      if ($pfx !== '' && strpos($uri, $pfx) === 0) return true;
    }
  }

  // 5) admin-ajax actions
  if (stripos($uri, '/wp-admin/admin-ajax.php') === 0) {
    $allowedActions = array_map('trim', netrl_list($settings['allow_ajax'] ?? ''));
    $action = isset($_REQUEST['action']) ? (string)$_REQUEST['action'] : '';
    if ($action !== '' && in_array($action, $allowedActions, true)) return true;
  }

  return false;
}

/** Parse newline/comma separated list to array */
function netrl_list($raw): array {
  $raw = (string)$raw;
  $raw = str_replace(["\r\n", "\r"], "\n", $raw);
  $parts = preg_split('/[\n,]+/', $raw);
  $out = [];
  foreach ($parts as $p) {
    $p = trim($p);
    if ($p !== '') $out[] = $p;
  }
  return $out;
}

/** Public wrapper (IPv4/IPv6, single-IP or CIDR) */
function netrl_ip_matches(string $ip, array $cidrs): bool {
  return netrl_ip_in_any_cidr($ip, $cidrs);
}

/** IP in any CIDR (IPv4/IPv6) */
function netrl_ip_in_any_cidr(string $ip, array $cidrs): bool {
  foreach ($cidrs as $cidr) {
    if (netrl_ip_in_cidr($ip, $cidr)) return true;
  }
  return false;
}
function netrl_ip_in_cidr(string $ip, string $cidr): bool {
  // supports single IP or x.x.x.x/nn and IPv6 ::/nn
  if (strpos($cidr, '/') === false) {
    return (strcasecmp($ip, $cidr) === 0);
  }
  list($subnet, $mask) = explode('/', $cidr, 2);
  $ip_bin = @inet_pton($ip);
  $subnet_bin = @inet_pton($subnet);
  if ($ip_bin === false || $subnet_bin === false) return false;
  $len = strlen($ip_bin); // 4 (v4) or 16 (v6)
  $mask = (int)$mask;
  if ($len !== strlen($subnet_bin)) return false;
  $fullBytes = intdiv($mask, 8);
  $remBits   = $mask % 8;

  if ($fullBytes && substr($ip_bin, 0, $fullBytes) !== substr($subnet_bin, 0, $fullBytes)) return false;
  if ($remBits === 0) return true;

  $ipByte   = ord($ip_bin[$fullBytes]);
  $subByte  = ord($subnet_bin[$fullBytes]);
  $maskByte = (0xFF << (8 - $remBits)) & 0xFF;
  return (($ipByte & $maskByte) === ($subByte & $maskByte));
}

/** Reverse-DNS suffix allow with forward confirm (PHP 7/8 safe) */
function netrl_rdns_suffix_allows(string $ip, array $suffixes): bool {
  $ptr = @gethostbyaddr($ip);
  if (!$ptr || $ptr === $ip) return false;
  $ptrLower = strtolower($ptr);
  foreach ($suffixes as $sfx) {
    $sfxLower = ltrim(strtolower($sfx), '.');
    if ($sfxLower === '') continue;
    // check ".host.tld" ends with ".suffix"
    $needle = '.' . $sfxLower;
    if (substr('.' . $ptrLower, -strlen($needle)) === $needle) {
      $ips = @gethostbynamel($ptr);
      if ($ips && in_array($ip, $ips, true)) return true;
    }
  }
  return false;
}

/**
 * Atomic increment helper (prefers object cache over transients)
 */
function netrl_atomic_incr(string $key, int $ttl, int $by = 1): int {
  if (function_exists('wp_cache_add') && function_exists('wp_cache_incr')) {
    if (!wp_cache_add($key, 0, '', $ttl)) { /* existed */ }
    $val = wp_cache_incr($key, $by);
    if ($val === false) {
      wp_cache_add($key, 0, '', $ttl);
      $val = wp_cache_incr($key, $by);
      if ($val === false) $val = 1;
    }
    return (int)$val;
  }
  // Fallback: transient (non-atomic)
  $v = (int) get_transient($key);
  $v += $by;
  set_transient($key, $v, $ttl);
  return $v;
}

/** Read helper that works on both object cache and transients */
function netrl_cache_get(string $key) {
  if (function_exists('wp_cache_get')) {
    $v = wp_cache_get($key);
    if ($v !== false) return $v;
  }
  return get_transient($key);
}

/** Two-bucket fixed-window counter (1-minute buckets), per-site. */
function netrl_minute_count(int $siteKey, string $ruleId, string $ip, int $windowSec = 60): float {
  $now     = time();
  $currBucketStart = (int)(floor($now / $windowSec) * $windowSec);
  $prevBucketStart = (int)(floor(($now - $windowSec) / $windowSec) * $windowSec);

  $currKey = "netrl:cnt:$siteKey:$ruleId:$ip:$currBucketStart";
  $prevKey = "netrl:cnt:$siteKey:$ruleId:$ip:$prevBucketStart";

  $curr = netrl_atomic_incr($currKey, $windowSec + 65, 1);
  $prev = (int) (netrl_cache_get($prevKey) ?: 0);

  $currBucketEndsAt = $currBucketStart + $windowSec;
  $overlap          = max(0, min(1, ($currBucketEndsAt - $now) / $windowSec));

  return $curr + ($prev * $overlap);
}

/** Violation score with auto-decay via expiry (probation window), per-site. */
function netrl_next_block_secs(int $siteKey, string $ip, int $baseBlock = 120, int $maxBlock = 3600, int $probationSec = 21600): int {
  $violKey = "netrl:viol:$siteKey:$ip";
  $v = (int) get_transient($violKey);
  $seconds = (int) min($baseBlock * (2 ** max(0, $v)), $maxBlock);
  set_transient($violKey, $v + 1, $probationSec);
  return max($baseBlock, $seconds);
}

/** Map requests to rule IDs to reduce key cardinality */
function netrl_rule_id(string $uri, string $method): ?string {
  if ($uri === '/wp-login.php') return 'login';
  if ($uri === '/xmlrpc.php')   return 'xmlrpc';
  if (strpos($uri, '/wp-admin/admin-ajax.php') === 0) return 'ajax';
  if (strpos($uri, '/wp-json/') === 0) return 'rest';
  return null;
}

/**
 * Derive real client IP (be cautious trusting XFF unless behind known proxy/CDN).
 */
function network_rate_limiter_real_ip(): string {
  $candidates = [];
  if (!empty($_SERVER['HTTP_CF_CONNECTING_IP'])) $candidates[] = $_SERVER['HTTP_CF_CONNECTING_IP'];
  if (!empty($_SERVER['HTTP_X_REAL_IP']))        $candidates[] = $_SERVER['HTTP_X_REAL_IP'];
  if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
    $parts = array_map('trim', explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']));
    foreach ($parts as $p) {
      if (filter_var($p, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE|FILTER_FLAG_NO_RES_RANGE)) { $candidates[] = $p; break; }
    }
    if (!empty($parts[0])) $candidates[] = trim($parts[0]);
  }
  if (!empty($_SERVER['REMOTE_ADDR'])) $candidates[] = $_SERVER['REMOTE_ADDR'];
  foreach ($candidates as $ip) if (filter_var($ip, FILTER_VALIDATE_IP)) return $ip;
  return '0.0.0.0';
}

/**
 * Verified bot detection for Google/Bing (UA + reverse DNS + forward-confirm).
 * Results cached per IP *and site* for 7 days. UA hint still required even if cached.
 */
function network_rate_limiter_is_verified_bot(int $siteKey, string $ip, string $ua): bool {
  $ua = strtolower($ua);
  $isGoogleUA = (
    strpos($ua, 'googlebot') !== false
    || strpos($ua, 'google-inspectiontool') !== false
    || strpos($ua, 'googleother') !== false
    || strpos($ua, 'adsbot-google') !== false
    || strpos($ua, 'googlebot-image') !== false
    || strpos($ua, 'google-read-aloud') !== false
  );
  $isBingUA = (
    strpos($ua, 'bingbot') !== false
    || strpos($ua, 'adidxbot') !== false
    || strpos($ua, 'bingpreview') !== false
  );
  if (!$isGoogleUA && !$isBingUA) return false;

  $cacheKey = 'netrl:botip:' . $siteKey . ':' . md5($ip);
  $cached = get_transient($cacheKey);
  if (($cached === 'g' && $isGoogleUA) || ($cached === 'b' && $isBingUA)) return true;
  if ($cached === 'n') return false;

  $ptr = @gethostbyaddr($ip);
  if (!$ptr || $ptr === $ip) { set_transient($cacheKey, 'n', WEEK_IN_SECONDS); return false; }

  $ok = false;
  if ($isGoogleUA && (substr($ptr, -strlen('.googlebot.com')) === '.googlebot.com' || substr($ptr, -strlen('.google.com')) === '.google.com')) {
    $ok = network_rate_limiter_forward_confirms($ptr, $ip);
    set_transient($cacheKey, $ok ? 'g' : 'n', WEEK_IN_SECONDS);
  } elseif ($isBingUA && (substr($ptr, -strlen('.search.msn.com')) === '.search.msn.com' || substr($ptr, -strlen('.bing.com')) === '.bing.com')) {
    $ok = network_rate_limiter_forward_confirms($ptr, $ip);
    set_transient($cacheKey, $ok ? 'b' : 'n', WEEK_IN_SECONDS);
  } else {
    set_transient($cacheKey, 'n', WEEK_IN_SECONDS);
  }
  return $ok;
}

function network_rate_limiter_forward_confirms(string $host, string $ip): bool {
  $ips = @gethostbynamel($host);
  if (!$ips) return false;
  return in_array($ip, $ips, true);
}

/** 429 helper */
function network_rate_limiter_deny($untilTs) {
  if (function_exists('http_response_code')) http_response_code(429);
  else header('HTTP/1.1 429 Too Many Requests');
  $retry = max(1, (int)$untilTs - time());
  header('Retry-After: ' . $retry);
  header('Content-Type: text/plain; charset=UTF-8');
  echo "Too many requests. Try again after " . gmdate(DATE_RFC7231, (int)$untilTs) . ".";
  exit;
}

/* =========================================
 * =============== LOGGING =================
 * ========================================= */

/** Basic JSON logger + hook. Toggle via site settings (log_bypass / log_blocks). */
function netrl_log(int $siteKey, string $type, array $data, array $settings): void {
  $payload = [
    'ts'   => time(),
    'site' => $siteKey,
    'type' => $type,
  ] + $data;

  $isBypass = in_array($type, ['bypass_secret','bypass_allowlist','bypass_verified_bot'], true);
  $isBlock  = (strpos($type, 'block') === 0 || $type === 'blocked_fast_deny');

  if (($isBypass && !empty($settings['log_bypass'])) || ($isBlock && !empty($settings['log_blocks']))) {
    // Keep it small; avoid dumping bodies
    @error_log('[netrl] ' . json_encode($payload));
  }
  /**
   * Action: netrl_log_event
   * Allows external systems to capture events.
   * @param int   $siteKey
   * @param array $payload
   */
  do_action('netrl_log_event', $siteKey, $payload);
}

/* =========================================
 * =========== SETTINGS SCREENS ============
 * ========================================= */

/** Render per-site settings page */
function netrl_render_site_settings_page() {
  if (!current_user_can('manage_options')) return;

  if ($_SERVER['REQUEST_METHOD'] === 'POST' && check_admin_referer('netrl_save_site_settings')) {
    $saved = [
      'enabled'         => isset($_POST['netrl_enabled']) ? 1 : 0,
      'day_start'       => isset($_POST['netrl_day_start']) ? max(0, min(23, (int)$_POST['netrl_day_start'])) : 5,
      'day_end'         => isset($_POST['netrl_day_end'])   ? max(0, min(23, (int)$_POST['netrl_day_end']))   : 22,
      'probation_hours' => max(1, min(72, (int)($_POST['netrl_probation_hours'] ?? 6))),
      'allow_uas'       => (string)($_POST['netrl_allow_uas'] ?? ''),
      'allow_hosts'     => (string)($_POST['netrl_allow_hosts'] ?? ''),
      'allow_ips'       => (string)($_POST['netrl_allow_ips'] ?? ''),
      'allow_ajax'      => (string)($_POST['netrl_allow_ajax'] ?? ''),
      'allow_rest'      => (string)($_POST['netrl_allow_rest'] ?? ''),
      'bypass_header'   => sanitize_text_field((string)($_POST['netrl_bypass_header'] ?? '')),
      'bypass_value'    => (string)($_POST['netrl_bypass_value'] ?? ''),
      'log_bypass'      => isset($_POST['netrl_log_bypass']) ? 1 : 0,
      'log_blocks'      => isset($_POST['netrl_log_blocks']) ? 1 : 0,
    ];
    update_option('netrl_settings', $saved);
    echo '<div class="updated notice is-dismissible"><p>Rate Limiter settings saved.</p></div>';
  }

  $settings = netrl_get_settings(is_multisite() ? get_current_blog_id() : 0);
  $tz = netrl_site_timezone();
  ?>
  <div class="wrap">
    <h1>Rate Limiter</h1>
    <form method="post">
      <?php wp_nonce_field('netrl_save_site_settings'); ?>
      <table class="form-table" role="presentation">
        <tr>
          <th scope="row"><label for="netrl_enabled">Enable limiter</label></th>
          <td>
            <label>
              <input type="checkbox" id="netrl_enabled" name="netrl_enabled" value="1" <?php checked(1, (int)$settings['enabled']); ?>>
              Turn on per-IP rate limiting for protected endpoints
            </label>
          </td>
        </tr>
        <tr>
          <th scope="row">Daytime window</th>
          <td>
            <select name="netrl_day_start" id="netrl_day_start"><?php echo netrl_hour_options((int)$settings['day_start']); ?></select>
            &nbsp;to&nbsp;
            <select name="netrl_day_end" id="netrl_day_end"><?php echo netrl_hour_options((int)$settings['day_end']); ?></select>
            <p class="description">
              Uses the site timezone (<?php echo esc_html($tz->getName()); ?>).
              Requests inside this window use stricter limits; outside use relaxed limits.
              If start equals end, the daytime profile is always used.
            </p>
          </td>
        </tr>

        <tr>
          <th scope="row"><label for="netrl_probation_hours">Violation probation (hours)</label></th>
          <td>
            <input type="number" min="1" max="72" step="1" id="netrl_probation_hours" name="netrl_probation_hours" value="<?php echo esc_attr((int)$settings['probation_hours']); ?>">
            <p class="description">Duration of “probation” window; if the IP behaves during this period, violation score decays.</p>
          </td>
        </tr>

        <tr><th colspan="2"><h2>Allowlist</h2></th></tr>
        <tr>
          <th scope="row"><label for="netrl_allow_uas">Allowed User-Agents</label></th>
          <td>
            <textarea name="netrl_allow_uas" id="netrl_allow_uas" rows="4" cols="60"><?php echo esc_textarea($settings['allow_uas']); ?></textarea>
            <p class="description">Substring match; one per line. Spoofable—prefer pairing with rDNS/IP or the secret header below.</p>
          </td>
        </tr>
        <tr>
          <th scope="row"><label for="netrl_allow_hosts">Allowed rDNS suffixes</label></th>
          <td>
            <textarea name="netrl_allow_hosts" id="netrl_allow_hosts" rows="3" cols="60"><?php echo esc_textarea($settings['allow_hosts']); ?></textarea>
            <p class="description">e.g. <code>.uptimerobot.com</code>. We reverse-lookup IP → host and forward-confirm host → IP.</p>
          </td>
        </tr>
        <tr>
          <th scope="row"><label for="netrl_allow_ips">Allowed IPs/CIDRs</label></th>
          <td>
            <textarea name="netrl_allow_ips" id="netrl_allow_ips" rows="4" cols="60"><?php echo esc_textarea($settings['allow_ips']); ?></textarea>
            <p class="description">One per line; IPv4 or IPv6 with optional CIDR (e.g. <code>152.38.128.0/19</code>, <code>2a00:1a48::/32</code>).</p>
          </td>
        </tr>
        <tr>
          <th scope="row"><label for="netrl_allow_rest">Allowed REST prefixes</label></th>
          <td>
            <textarea name="netrl_allow_rest" id="netrl_allow_rest" rows="2" cols="60"><?php echo esc_textarea($settings['allow_rest']); ?></textarea>
            <p class="description">Path prefixes to skip under <code>/wp-json/</code>, one per line (e.g. <code>/wp-json/oembed/</code>).</p>
          </td>
        </tr>
        <tr>
          <th scope="row"><label for="netrl_allow_ajax">Allowed admin-ajax actions</label></th>
          <td>
            <textarea name="netrl_allow_ajax" id="netrl_allow_ajax" rows="2" cols="60"><?php echo esc_textarea($settings['allow_ajax']); ?></textarea>
            <p class="description">Action names (e.g. <code>heartbeat</code>), one per line.</p>
          </td>
        </tr>

        <tr><th colspan="2"><h2>Secret Header Bypass</h2></th></tr>
        <tr>
          <th scope="row"><label for="netrl_bypass_header">Header name</label></th>
          <td><input type="text" name="netrl_bypass_header" id="netrl_bypass_header" value="<?php echo esc_attr($settings['bypass_header']); ?>" class="regular-text" placeholder="X-NetRL-Bypass"></td>
        </tr>
        <tr>
          <th scope="row"><label for="netrl_bypass_value">Header value (secret)</label></th>
          <td><input type="text" name="netrl_bypass_value" id="netrl_bypass_value" value="<?php echo esc_attr($settings['bypass_value']); ?>" class="regular-text" placeholder="use a long random token"></td>
        </tr>

        <tr><th colspan="2"><h2>Logging</h2></th></tr>
        <tr>
          <th scope="row">What to log</th>
          <td>
            <label><input type="checkbox" name="netrl_log_blocks" value="1" <?php checked(1, (int)$settings['log_blocks']); ?>> Blocks / throttles</label><br>
            <label><input type="checkbox" name="netrl_log_bypass" value="1" <?php checked(1, (int)$settings['log_bypass']); ?>> Bypasses (secret, allowlist, verified bots)</label>
            <p class="description">Logs to PHP error log as JSON and emits <code>netrl_log_event</code> action.</p>
          </td>
        </tr>
      </table>
      <?php submit_button('Save Changes'); ?>
    </form>
  </div>
  <?php
}

/** Render network defaults page (multisite) */
function netrl_render_network_settings_page() {
  if (!current_user_can('manage_network_options')) return;

  if ($_SERVER['REQUEST_METHOD'] === 'POST' && check_admin_referer('netrl_save_network_settings')) {
    $saved = [
      'enabled'         => isset($_POST['netrl_enabled']) ? 1 : 0,
      'day_start'       => isset($_POST['netrl_day_start']) ? max(0, min(23, (int)$_POST['netrl_day_start'])) : 5,
      'day_end'         => isset($_POST['netrl_day_end'])   ? max(0, min(23, (int)$_POST['netrl_day_end']))   : 22,
      'probation_hours' => max(1, min(72, (int)($_POST['netrl_probation_hours'] ?? 6))),
      'allow_uas'       => (string)($_POST['netrl_allow_uas'] ?? ''),
      'allow_hosts'     => (string)($_POST['netrl_allow_hosts'] ?? ''),
      'allow_ips'       => (string)($_POST['netrl_allow_ips'] ?? ''),
      'allow_ajax'      => (string)($_POST['netrl_allow_ajax'] ?? ''),
      'allow_rest'      => (string)($_POST['netrl_allow_rest'] ?? ''),
      'bypass_header'   => sanitize_text_field((string)($_POST['netrl_bypass_header'] ?? '')),
      'bypass_value'    => (string)($_POST['netrl_bypass_value'] ?? ''),
      'log_bypass'      => isset($_POST['netrl_log_bypass']) ? 1 : 0,
      'log_blocks'      => isset($_POST['netrl_log_blocks']) ? 1 : 0,
    ];
    update_site_option('netrl_defaults', $saved);
    echo '<div class="updated notice is-dismissible"><p>Network defaults saved. Individual sites can override on their own Settings → Rate Limiter page.</p></div>';
  }

  $defaults = (array) get_site_option('netrl_defaults', netrl_get_settings(0));
  ?>
  <div class="wrap">
    <h1>Rate Limiter (Network Defaults)</h1>
    <form method="post">
      <?php wp_nonce_field('netrl_save_network_settings'); ?>
      <table class="form-table" role="presentation">
        <tr>
          <th scope="row"><label for="netrl_enabled">Default: enable limiter</label></th>
          <td>
            <label>
              <input type="checkbox" id="netrl_enabled" name="netrl_enabled" value="1" <?php checked(1, (int)$defaults['enabled']); ?>>
              Enable by default for sites that haven’t set their own preference
            </label>
          </td>
        </tr>
        <tr>
          <th scope="row">Default daytime window</th>
          <td>
            <select name="netrl_day_start" id="netrl_day_start"><?php echo netrl_hour_options((int)$defaults['day_start']); ?></select>
            &nbsp;to&nbsp;
            <select name="netrl_day_end" id="netrl_day_end"><?php echo netrl_hour_options((int)$defaults['day_end']); ?></select>
          </td>
        </tr>

        <tr>
          <th scope="row"><label for="netrl_probation_hours">Default violation probation (hours)</label></th>
          <td><input type="number" min="1" max="72" step="1" id="netrl_probation_hours" name="netrl_probation_hours" value="<?php echo esc_attr((int)$defaults['probation_hours']); ?>"></td>
        </tr>

        <tr><th colspan="2"><h2>Allowlist (Defaults)</h2></th></tr>
        <tr>
          <th scope="row"><label for="netrl_allow_uas">Allowed User-Agents</label></th>
          <td><textarea name="netrl_allow_uas" id="netrl_allow_uas" rows="4" cols="60"><?php echo esc_textarea($defaults['allow_uas']); ?></textarea></td>
        </tr>
        <tr>
          <th scope="row"><label for="netrl_allow_hosts">Allowed rDNS suffixes</label></th>
          <td><textarea name="netrl_allow_hosts" id="netrl_allow_hosts" rows="3" cols="60"><?php echo esc_textarea($defaults['allow_hosts']); ?></textarea></td>
        </tr>
        <tr>
          <th scope="row"><label for="netrl_allow_ips">Allowed IPs/CIDRs</label></th>
          <td><textarea name="netrl_allow_ips" id="netrl_allow_ips" rows="4" cols="60"><?php echo esc_textarea($defaults['allow_ips']); ?></textarea></td>
        </tr>
        <tr>
          <th scope="row"><label for="netrl_allow_rest">Allowed REST prefixes</label></th>
          <td><textarea name="netrl_allow_rest" id="netrl_allow_rest" rows="2" cols="60"><?php echo esc_textarea($defaults['allow_rest']); ?></textarea></td>
        </tr>
        <tr>
          <th scope="row"><label for="netrl_allow_ajax">Allowed admin-ajax actions</label></th>
          <td><textarea name="netrl_allow_ajax" id="netrl_allow_ajax" rows="2" cols="60"><?php echo esc_textarea($defaults['allow_ajax']); ?></textarea></td>
        </tr>

        <tr><th colspan="2"><h2>Secret Header Bypass (Defaults)</h2></th></tr>
        <tr>
          <th scope="row"><label for="netrl_bypass_header">Header name</label></th>
          <td><input type="text" name="netrl_bypass_header" id="netrl_bypass_header" value="<?php echo esc_attr($defaults['bypass_header']); ?>" class="regular-text" placeholder="X-NetRL-Bypass"></td>
        </tr>
        <tr>
          <th scope="row"><label for="netrl_bypass_value">Header value (secret)</label></th>
          <td><input type="text" name="netrl_bypass_value" id="netrl_bypass_value" value="<?php echo esc_attr($defaults['bypass_value']); ?>" class="regular-text" placeholder="use a long random token"></td>
        </tr>

        <tr><th colspan="2"><h2>Logging (Defaults)</h2></th></tr>
        <tr>
          <th scope="row">What to log</th>
          <td>
            <label><input type="checkbox" name="netrl_log_blocks" value="1" <?php checked(1, (int)$defaults['log_blocks']); ?>> Blocks / throttles</label><br>
            <label><input type="checkbox" name="netrl_log_bypass" value="1" <?php checked(1, (int)$defaults['log_bypass']); ?>> Bypasses (secret, allowlist, verified bots)</label>
          </td>
        </tr>
      </table>
      <?php submit_button('Save Network Defaults'); ?>
    </form>
  </div>
  <?php
}

/** Hour dropdown options helper */
function netrl_hour_options(int $selected): string {
  $out = '';
  for ($h = 0; $h <= 23; $h++) {
    $label = sprintf('%02d:00', $h);
    $out .= sprintf('<option value="%d"%s>%s</option>', $h, selected($selected, $h, false), esc_html($label));
  }
  return $out;
}