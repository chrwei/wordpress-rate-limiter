<?php
/**
 * Plugin Name: Network Rate Limiter (Progressive, Time-Aware)
 * Description: Per-IP progressive, time-aware rate limiting for sensitive endpoints. Per-site controls (enable + hours + allowlist + logging + probation), Network Defaults, verified-bot exemptions.
 * Must Use: yes
 * Author: Greg Gant
 * Author URI: https://blockstacklabs.com/
 * Version: 1.1
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
  $siteKey = is_multisite() ? get_current_blog_id() : 0;
  $settings = netrl_get_settings($siteKey);

  // Do not rate-limit preflight or HEAD requests
  if ($method === 'OPTIONS' || $method === 'HEAD') return;

  if (empty($settings['enabled'])) return;

  $ip      = network_rate_limiter_real_ip($settings);
  $ua      = $_SERVER['HTTP_USER_AGENT'] ?? '';

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

  // --- Regional traffic controls (GeoIP-based blocking/penalties) ---
  $countryCode = '';
  $isPenalizedCountry = false;
  if (!empty($settings['enable_region'])) {
    $countryCode = netrl_get_country_code($siteKey, $ip, $settings);
    if ($countryCode) {
      // Check if country is completely blocked
      $blockedCountries = netrl_list($settings['blocked_countries'] ?? '');
      if ($blockedCountries && in_array($countryCode, $blockedCountries, true)) {
        netrl_log($siteKey, 'block_country', [
          'ip'=>$ip,'ua'=>$ua,'uri'=>$reqUri,'method'=>$method,'country'=>$countryCode
        ], $settings);
        if (function_exists('http_response_code')) http_response_code(403);
        else header('HTTP/1.1 403 Forbidden');
        header('Content-Type: text/plain; charset=UTF-8');
        echo "Access from your region is not permitted.";
        exit;
      }

      // Check if country is penalized (will apply harsher limits below)
      $penalizedCountries = netrl_list($settings['penalized_countries'] ?? '');
      if ($penalizedCountries && in_array($countryCode, $penalizedCountries, true)) {
        $isPenalizedCountry = true;
        // Apply initial violation penalty if configured
        if (!empty($settings['penalty_violations'])) {
          $violKey = "netrl:viol:$siteKey:$ip";
          $existingViolations = (int) get_transient($violKey);
          // Only set initial violations if they don't already have a worse record
          if ($existingViolations < (int)$settings['penalty_violations']) {
            $probationHrs = max(1, min(72, (int)($settings['probation_hours'] ?? 6)));
            $probationSec = $probationHrs * HOUR_IN_SECONDS;
            set_transient($violKey, (int)$settings['penalty_violations'], $probationSec);
          }
        }
      }
    }
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

  // Apply penalty reduction for penalized countries
  if ($isPenalizedCountry && !empty($settings['penalty_reduction_pct'])) {
    $reductionPct = (int)$settings['penalty_reduction_pct'];
    $multiplier = max(0.01, (100 - $reductionPct) / 100);
    $soft = max(1, (int)($soft * $multiplier));
    $hard = max(1, (int)($hard * $multiplier));
  }

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

  // Apply penalty reduction to global limit for penalized countries
  if ($isPenalizedCountry && !empty($settings['penalty_reduction_pct'])) {
    $reductionPct = (int)$settings['penalty_reduction_pct'];
    $multiplier = max(0.01, (100 - $reductionPct) / 100);
    $globalLimit = max(1, (int)($globalLimit * $multiplier));
  }

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
    'trusted_proxy_ips'=> "",
    // Secret header bypass (leave blank to disable)
    'bypass_header'    => "",
    'bypass_value'     => "",
    // Logging
    'log_bypass'       => 0,  // log allowlist/secret/bot bypasses
    'log_blocks'       => 1,  // log soft/hard/global blocks
    // Regional traffic controls (country codes: ISO 3166-1 alpha-2)
    'enable_region'         => 1,  // enable regional traffic controls
    'blocked_countries'     => "KP\nSY",  // completely blocked: North Korea, Syria
    'penalized_countries'   => "RU\nCN\nIR\nBY",  // penalized: Russia, China, Iran, Belarus
    'penalty_reduction_pct' => 50,  // reduce soft/hard limits by this % for penalized countries
    'penalty_violations'    => 2,   // initial violation score for penalized countries (0-5)
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
  // Regional controls
  $merged['enable_region']         = !empty($merged['enable_region']) ? 1 : 0;
  $merged['penalty_reduction_pct'] = max(0, min(100, (int)$merged['penalty_reduction_pct']));
  $merged['penalty_violations']    = max(0, min(10, (int)$merged['penalty_violations']));
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
    $action = isset($_REQUEST['action']) ? sanitize_key($_REQUEST['action']) : '';
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

/** ISO 3166-1 alpha-2 country catalog */
function netrl_country_catalog(): array {
  return [
    'AF'=>'Afghanistan','AX'=>'Aland Islands','AL'=>'Albania','DZ'=>'Algeria','AS'=>'American Samoa',
    'AD'=>'Andorra','AO'=>'Angola','AI'=>'Anguilla','AQ'=>'Antarctica','AG'=>'Antigua and Barbuda',
    'AR'=>'Argentina','AM'=>'Armenia','AW'=>'Aruba','AU'=>'Australia','AT'=>'Austria',
    'AZ'=>'Azerbaijan','BS'=>'Bahamas','BH'=>'Bahrain','BD'=>'Bangladesh','BB'=>'Barbados',
    'BY'=>'Belarus','BE'=>'Belgium','BZ'=>'Belize','BJ'=>'Benin','BM'=>'Bermuda',
    'BT'=>'Bhutan','BO'=>'Bolivia','BQ'=>'Bonaire, Saint Eustatius and Saba','BA'=>'Bosnia and Herzegovina',
    'BW'=>'Botswana','BV'=>'Bouvet Island','BR'=>'Brazil','IO'=>'British Indian Ocean Territory',
    'BN'=>'Brunei Darussalam','BG'=>'Bulgaria','BF'=>'Burkina Faso','BI'=>'Burundi','KH'=>'Cambodia',
    'CM'=>'Cameroon','CA'=>'Canada','CV'=>'Cape Verde','KY'=>'Cayman Islands','CF'=>'Central African Republic',
    'TD'=>'Chad','CL'=>'Chile','CN'=>'China','CX'=>'Christmas Island','CC'=>'Cocos (Keeling) Islands',
    'CO'=>'Colombia','KM'=>'Comoros','CG'=>'Congo','CD'=>'Congo, Democratic Republic',
    'CK'=>'Cook Islands','CR'=>'Costa Rica','CI'=>'Cote d\'Ivoire','HR'=>'Croatia','CU'=>'Cuba','CW'=>'Curacao',
    'CY'=>'Cyprus','CZ'=>'Czech Republic','DK'=>'Denmark','DJ'=>'Djibouti','DM'=>'Dominica',
    'DO'=>'Dominican Republic','EC'=>'Ecuador','EG'=>'Egypt','SV'=>'El Salvador','GQ'=>'Equatorial Guinea',
    'ER'=>'Eritrea','EE'=>'Estonia','ET'=>'Ethiopia','FK'=>'Falkland Islands (Malvinas)',
    'FO'=>'Faroe Islands','FJ'=>'Fiji','FI'=>'Finland','FR'=>'France','GF'=>'French Guiana',
    'PF'=>'French Polynesia','TF'=>'French Southern Territories','GA'=>'Gabon','GM'=>'Gambia',
    'GE'=>'Georgia','DE'=>'Germany','GH'=>'Ghana','GI'=>'Gibraltar','GR'=>'Greece','GL'=>'Greenland',
    'GD'=>'Grenada','GP'=>'Guadeloupe','GU'=>'Guam','GT'=>'Guatemala','GG'=>'Guernsey','GN'=>'Guinea',
    'GW'=>'Guinea-Bissau','GY'=>'Guyana','HT'=>'Haiti','HM'=>'Heard and McDonald Islands',
    'VA'=>'Holy See (Vatican City State)','HN'=>'Honduras','HK'=>'Hong Kong','HU'=>'Hungary','IS'=>'Iceland',
    'IN'=>'India','ID'=>'Indonesia','IR'=>'Iran','IQ'=>'Iraq','IE'=>'Ireland','IM'=>'Isle of Man',
    'IL'=>'Israel','IT'=>'Italy','JM'=>'Jamaica','JP'=>'Japan','JE'=>'Jersey','JO'=>'Jordan','KZ'=>'Kazakhstan',
    'KE'=>'Kenya','KI'=>'Kiribati','KP'=>'Korea, Democratic People\'s Republic','KR'=>'Korea, Republic of',
    'KW'=>'Kuwait','KG'=>'Kyrgyzstan','LA'=>'Lao People\'s Democratic Republic','LV'=>'Latvia','LB'=>'Lebanon',
    'LS'=>'Lesotho','LR'=>'Liberia','LY'=>'Libya','LI'=>'Liechtenstein','LT'=>'Lithuania','LU'=>'Luxembourg',
    'MO'=>'Macao','MK'=>'Macedonia','MG'=>'Madagascar','MW'=>'Malawi','MY'=>'Malaysia','MV'=>'Maldives',
    'ML'=>'Mali','MT'=>'Malta','MH'=>'Marshall Islands','MQ'=>'Martinique','MR'=>'Mauritania','MU'=>'Mauritius',
    'YT'=>'Mayotte','MX'=>'Mexico','FM'=>'Micronesia','MD'=>'Moldova','MC'=>'Monaco','MN'=>'Mongolia',
    'ME'=>'Montenegro','MS'=>'Montserrat','MA'=>'Morocco','MZ'=>'Mozambique','MM'=>'Myanmar',
    'NA'=>'Namibia','NR'=>'Nauru','NP'=>'Nepal','NL'=>'Netherlands','NC'=>'New Caledonia','NZ'=>'New Zealand',
    'NI'=>'Nicaragua','NE'=>'Niger','NG'=>'Nigeria','NU'=>'Niue','NF'=>'Norfolk Island','MP'=>'Northern Mariana Islands',
    'NO'=>'Norway','OM'=>'Oman','PK'=>'Pakistan','PW'=>'Palau','PS'=>'Palestine, State of','PA'=>'Panama',
    'PG'=>'Papua New Guinea','PY'=>'Paraguay','PE'=>'Peru','PH'=>'Philippines','PN'=>'Pitcairn',
    'PL'=>'Poland','PT'=>'Portugal','PR'=>'Puerto Rico','QA'=>'Qatar','RE'=>'Reunion','RO'=>'Romania',
    'RU'=>'Russian Federation','RW'=>'Rwanda','BL'=>'Saint Barthelemy','SH'=>'Saint Helena','KN'=>'Saint Kitts and Nevis',
    'LC'=>'Saint Lucia','MF'=>'Saint Martin','PM'=>'Saint Pierre and Miquelon','VC'=>'Saint Vincent and the Grenadines',
    'WS'=>'Samoa','SM'=>'San Marino','ST'=>'Sao Tome and Principe','SA'=>'Saudi Arabia','SN'=>'Senegal',
    'RS'=>'Serbia','SC'=>'Seychelles','SL'=>'Sierra Leone','SG'=>'Singapore','SX'=>'Sint Maarten','SK'=>'Slovakia',
    'SI'=>'Slovenia','SB'=>'Solomon Islands','SO'=>'Somalia','ZA'=>'South Africa','GS'=>'South Georgia and Sandwich Isl.',
    'SS'=>'South Sudan','ES'=>'Spain','LK'=>'Sri Lanka','SD'=>'Sudan','SR'=>'Suriname','SJ'=>'Svalbard and Jan Mayen',
    'SZ'=>'Swaziland','SE'=>'Sweden','CH'=>'Switzerland','SY'=>'Syrian Arab Republic','TW'=>'Taiwan','TJ'=>'Tajikistan',
    'TZ'=>'Tanzania','TH'=>'Thailand','TL'=>'Timor-Leste','TG'=>'Togo','TK'=>'Tokelau','TO'=>'Tonga',
    'TT'=>'Trinidad and Tobago','TN'=>'Tunisia','TR'=>'Turkey','TM'=>'Turkmenistan','TC'=>'Turks and Caicos Islands',
    'TV'=>'Tuvalu','UG'=>'Uganda','UA'=>'Ukraine','AE'=>'United Arab Emirates','GB'=>'United Kingdom','US'=>'United States',
    'UM'=>'United States Minor Outlying Islands','UY'=>'Uruguay','UZ'=>'Uzbekistan','VU'=>'Vanuatu','VE'=>'Venezuela',
    'VN'=>'Vietnam','VG'=>'Virgin Islands, British','VI'=>'Virgin Islands, U.S.','WF'=>'Wallis and Futuna',
    'EH'=>'Western Sahara','YE'=>'Yemen','ZM'=>'Zambia','ZW'=>'Zimbabwe',
  ];
}

/** Default "bad actor" preset for quick-pick */
function netrl_bad_actor_countries(): array {
  return [
    'blocked'   => ['KP','SY'],
    'penalized' => ['RU','CN','IR','BY'],
  ];
}

/** Render options for country multi-select */
function netrl_country_options(array $selected): string {
  $catalog = netrl_country_catalog();
  $selectedMap = [];
  foreach ($selected as $c) $selectedMap[strtoupper($c)] = true;
  $out = '';
  foreach ($catalog as $code => $name) {
    $sel = isset($selectedMap[$code]) ? ' selected' : '';
    $out .= sprintf(
      '<option value="%s"%s>%s — %s</option>',
      esc_attr($code),
      $sel,
      esc_html($code),
      esc_html($name)
    );
  }
  return $out;
}

/** Sanitize country codes (array or string) into newline-separated ISO codes */
function netrl_sanitize_country_codes($raw): string {
  $catalog = netrl_country_catalog();
  $codes = [];
  if (is_array($raw)) {
    $codes = $raw;
  } else {
    $codes = netrl_list($raw);
  }
  $valid = [];
  foreach ($codes as $code) {
    $code = strtoupper(trim((string)$code));
    if (strlen($code) === 2 && isset($catalog[$code])) {
      $valid[$code] = true;
    }
  }
  return implode("\n", array_keys($valid));
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

/**
 * DNS lookup circuit breaker and rate limiter.
 * Returns true if DNS lookups are currently allowed.
 */
function netrl_can_do_dns_lookup(): bool {
  $now = time();
  $minute = floor($now / 60);

  // Check circuit breaker (disabled after too many failures)
  $breakerKey = 'netrl:dns_breaker';
  $breakerUntil = (int) get_transient($breakerKey);
  if ($breakerUntil && $now < $breakerUntil) {
    return false; // Circuit breaker is open
  }

  // Rate limit: max 20 DNS lookups per minute globally
  $rateLimitKey = 'netrl:dns_limit:' . $minute;
  $count = 0;
  if (function_exists('wp_cache_get')) {
    $count = (int) wp_cache_get($rateLimitKey);
    if ($count >= 20) return false;
    wp_cache_set($rateLimitKey, $count + 1, '', 65);
  } else {
    $count = (int) get_transient($rateLimitKey);
    if ($count >= 20) return false;
    set_transient($rateLimitKey, $count + 1, 65);
  }

  return true;
}

/**
 * Track DNS lookup failures and trigger circuit breaker if needed.
 */
function netrl_track_dns_failure(): void {
  $minute = floor(time() / 60);
  $failureKey = 'netrl:dns_failures:' . $minute;

  if (function_exists('wp_cache_get')) {
    $failures = (int) wp_cache_get($failureKey);
    $failures++;
    wp_cache_set($failureKey, $failures, '', 65);
  } else {
    $failures = (int) get_transient($failureKey);
    $failures++;
    set_transient($failureKey, $failures, 65);
  }

  // If 5+ failures in this minute, open circuit breaker for 5 minutes
  if ($failures >= 5) {
    set_transient('netrl:dns_breaker', time() + 300, 300);
    error_log('[netrl] DNS circuit breaker triggered: 5+ failures in 60s, disabling DNS lookups for 5min');
  }
}

/** Reverse-DNS suffix allow with forward confirm (PHP 7/8 safe) */
function netrl_rdns_suffix_allows(string $ip, array $suffixes): bool {
  if (!netrl_can_do_dns_lookup()) {
    return false; // Circuit breaker or rate limit active
  }

  $ptr = gethostbyaddr($ip);
  if (!$ptr || $ptr === $ip) {
    netrl_track_dns_failure();
    return false;
  }

  $ptrLower = strtolower($ptr);
  foreach ($suffixes as $sfx) {
    $sfxLower = ltrim(strtolower($sfx), '.');
    if ($sfxLower === '') continue;
    // check ".host.tld" ends with ".suffix"
    $needle = '.' . $sfxLower;
    if (substr('.' . $ptrLower, -strlen($needle)) === $needle) {
      $ips = gethostbynamel($ptr);
      if (!$ips) {
        netrl_track_dns_failure();
        return false;
      }
      if (in_array($ip, $ips, true)) return true;
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
 * Derive real client IP, trusting proxy headers only when the request comes from a trusted proxy.
 */
function network_rate_limiter_real_ip(array $settings): string {
  $trustedProxies = netrl_list($settings['trusted_proxy_ips'] ?? '');
  $remoteAddr = $_SERVER['REMOTE_ADDR'] ?? '';
  $isTrustedProxy = ($remoteAddr && $trustedProxies) ? netrl_ip_matches($remoteAddr, $trustedProxies) : false;

  $candidates = [];

  // Only trust proxy headers if the immediate client is trusted
  if ($isTrustedProxy) {
    if (!empty($_SERVER['HTTP_CF_CONNECTING_IP'])) $candidates[] = $_SERVER['HTTP_CF_CONNECTING_IP'];
    if (!empty($_SERVER['HTTP_X_REAL_IP']))        $candidates[] = $_SERVER['HTTP_X_REAL_IP'];
    if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
      $parts = array_map('trim', explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']));
      foreach ($parts as $p) {
        if (filter_var($p, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE|FILTER_FLAG_NO_RES_RANGE)) { $candidates[] = $p; break; }
      }
      if (!empty($parts[0])) $candidates[] = trim($parts[0]);
    }
  }

  if ($remoteAddr !== '') $candidates[] = $remoteAddr;
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

  // Check DNS rate limits before expensive lookups
  if (!netrl_can_do_dns_lookup()) {
    return false; // Circuit breaker active, deny bot verification
  }

  $ptr = gethostbyaddr($ip);
  if (!$ptr || $ptr === $ip) {
    netrl_track_dns_failure();
    set_transient($cacheKey, 'n', WEEK_IN_SECONDS);
    return false;
  }

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
  $ips = gethostbynamel($host);
  if (!$ips) {
    netrl_track_dns_failure();
    return false;
  }
  return in_array($ip, $ips, true);
}

/**
 * Get country code for an IP address.
 * Tries CloudFlare header first (with validation), then falls back to ip-api.com with caching and rate limiting.
 *
 * @param int $siteKey Site ID for cache scoping
 * @param string $ip IP address to lookup
 * @param array $settings Settings array for trusted proxy validation
 * @return string Two-letter country code (uppercase) or empty string if unknown
 */
function netrl_get_country_code(int $siteKey, string $ip, array $settings = []): string {
  // 1) Try CloudFlare header first (instant, no API call needed)
  // But only trust it if request came from a trusted proxy (CloudFlare)
  if (!empty($_SERVER['HTTP_CF_IPCOUNTRY'])) {
    $remoteAddr = $_SERVER['REMOTE_ADDR'] ?? '';
    $trustedProxies = !empty($settings) ? netrl_list($settings['trusted_proxy_ips'] ?? '') : [];
    $isTrustedProxy = ($remoteAddr && $trustedProxies) ? netrl_ip_matches($remoteAddr, $trustedProxies) : false;

    if ($isTrustedProxy) {
      $cc = strtoupper(trim($_SERVER['HTTP_CF_IPCOUNTRY']));
      // CloudFlare returns 'XX' for unknown, 'T1' for Tor, etc.
      if ($cc && strlen($cc) === 2 && $cc !== 'XX') {
        return $cc;
      }
    }
  }

  // 2) Check cache (24 hour TTL to avoid hammering API)
  $cacheKey = 'netrl:geo:' . $siteKey . ':' . md5($ip);
  $cached = get_transient($cacheKey);
  if ($cached !== false) {
    return (string)$cached;
  }

  // 3) Check API rate limit (max 40/minute to stay under ip-api.com free tier of 45/min)
  $minute = floor(time() / 60);
  $apiRateLimitKey = 'netrl:geoapi_limit:' . $minute;
  if (function_exists('wp_cache_get')) {
    $apiCount = (int) wp_cache_get($apiRateLimitKey);
    if ($apiCount >= 40) {
      // API quota exhausted - cache empty result and return
      set_transient($cacheKey, '', DAY_IN_SECONDS);
      error_log('[netrl] GeoIP API rate limit reached (40/min), caching empty result for IP: ' . $ip);
      return '';
    }
    wp_cache_set($apiRateLimitKey, $apiCount + 1, '', 65);
  } else {
    $apiCount = (int) get_transient($apiRateLimitKey);
    if ($apiCount >= 40) {
      set_transient($cacheKey, '', DAY_IN_SECONDS);
      error_log('[netrl] GeoIP API rate limit reached (40/min), caching empty result for IP: ' . $ip);
      return '';
    }
    set_transient($apiRateLimitKey, $apiCount + 1, 65);
  }

  // 4) Fallback to ip-api.com (free tier: 45 requests/minute)
  // Use fields parameter to minimize response size
  $apiUrl = 'https://ip-api.com/json/' . urlencode($ip) . '?fields=status,countryCode';
  $response = file_get_contents($apiUrl, false, stream_context_create([
    'http' => [
      'timeout' => 0.5,
      'ignore_errors' => true,
      'user_agent' => 'WordPress-NetRL/1.0'
    ]
  ]));

  $countryCode = '';
  if ($response !== false) {
    $data = json_decode($response, true);
    if ($data && isset($data['status']) && $data['status'] === 'success' && !empty($data['countryCode'])) {
      $countryCode = strtoupper(trim($data['countryCode']));
    } elseif ($data && isset($data['status']) && $data['status'] === 'fail') {
      error_log('[netrl] GeoIP API lookup failed for IP ' . $ip . ': ' . ($data['message'] ?? 'unknown error'));
    }
  } else {
    error_log('[netrl] GeoIP API request failed for IP: ' . $ip);
  }

  // Cache result for 24 hours (even if empty to avoid repeated failures)
  set_transient($cacheKey, $countryCode, DAY_IN_SECONDS);
  return $countryCode;
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

/**
 * Check if persistent object cache is available and properly configured.
 */
function netrl_has_object_cache(): bool {
  return (function_exists('wp_cache_incr') && function_exists('wp_cache_add'));
}

/**
 * Detect if proxy headers are present but trusted_proxy_ips is not configured.
 */
function netrl_detect_unconfigured_proxy(): bool {
  return (!empty($_SERVER['HTTP_CF_CONNECTING_IP']) ||
          !empty($_SERVER['HTTP_X_FORWARDED_FOR']) ||
          !empty($_SERVER['HTTP_X_REAL_IP']));
}

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
    $old = (array) get_option('netrl_settings', []);
    $saved = [
      'enabled'         => isset($_POST['netrl_enabled']) ? 1 : 0,
      'day_start'       => isset($_POST['netrl_day_start']) ? max(0, min(23, (int)$_POST['netrl_day_start'])) : 5,
      'day_end'         => isset($_POST['netrl_day_end'])   ? max(0, min(23, (int)$_POST['netrl_day_end']))   : 22,
      'probation_hours' => max(1, min(72, (int)($_POST['netrl_probation_hours'] ?? 6))),
      'allow_uas'       => (string)($_POST['netrl_allow_uas'] ?? ''),
      'allow_hosts'     => (string)($_POST['netrl_allow_hosts'] ?? ''),
      'allow_ips'       => (string)($_POST['netrl_allow_ips'] ?? ''),
      'trusted_proxy_ips'=> (string)($_POST['netrl_trusted_proxy_ips'] ?? ''),
      'allow_ajax'      => (string)($_POST['netrl_allow_ajax'] ?? ''),
      'allow_rest'      => (string)($_POST['netrl_allow_rest'] ?? ''),
      'bypass_header'   => sanitize_text_field((string)($_POST['netrl_bypass_header'] ?? '')),
      'bypass_value'    => (string)($_POST['netrl_bypass_value'] ?? ''),
      'log_bypass'      => isset($_POST['netrl_log_bypass']) ? 1 : 0,
      'log_blocks'      => isset($_POST['netrl_log_blocks']) ? 1 : 0,
      // Regional traffic controls
      'enable_region'         => isset($_POST['netrl_enable_region']) ? 1 : 0,
      'blocked_countries'     => netrl_sanitize_country_codes($_POST['netrl_blocked_countries'] ?? ''),
      'penalized_countries'   => netrl_sanitize_country_codes($_POST['netrl_penalized_countries'] ?? ''),
      'penalty_reduction_pct' => max(0, min(100, (int)($_POST['netrl_penalty_reduction_pct'] ?? 50))),
      'penalty_violations'    => max(0, min(10, (int)($_POST['netrl_penalty_violations'] ?? 2))),
    ];
    update_option('netrl_settings', $saved);

    // Audit log: track configuration changes
    $user = wp_get_current_user();
    $changed = array_diff_assoc($saved, $old);
    if ($changed) {
      error_log(sprintf(
        '[netrl] Settings changed by user %s (ID: %d, Site: %d): %s',
        $user->user_login,
        $user->ID,
        is_multisite() ? get_current_blog_id() : 0,
        json_encode($changed)
      ));
    }

    echo '<div class="updated notice is-dismissible"><p>Rate Limiter settings saved.</p></div>';
  }

  $settings = netrl_get_settings(is_multisite() ? get_current_blog_id() : 0);
  $tz = netrl_site_timezone();
  $blockedSelected = netrl_list($settings['blocked_countries']);
  $penalizedSelected = netrl_list($settings['penalized_countries']);
  $badActors = netrl_bad_actor_countries();
  ?>
  <div class="wrap">
    <h1>Rate Limiter</h1>

    <?php
    // Critical warning: no object cache
    if (!netrl_has_object_cache()) {
      echo '<div class="notice notice-error"><p><strong>Critical:</strong> No persistent object cache detected (Redis/Memcached). Rate limiting counters are non-atomic and vulnerable to race conditions. <a href="https://wordpress.org/support/article/optimization/#persistent-object-cache" target="_blank">Install object cache</a> before using in production.</p></div>';
    }

    // Warning: proxy headers detected but not configured
    if (empty($settings['trusted_proxy_ips']) && netrl_detect_unconfigured_proxy()) {
      echo '<div class="notice notice-warning"><p><strong>Warning:</strong> Proxy headers detected (CF-Connecting-IP, X-Forwarded-For, or X-Real-IP) but no trusted proxy IPs configured. All users will be rate-limited as a single IP address. <a href="#netrl_trusted_proxy_ips">Configure trusted proxies below</a>.</p></div>';
    }
    ?>

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
            <p class="description">Duration of "probation" window; if the IP behaves during this period, violation score decays.</p>
          </td>
        </tr>

        <tr><th colspan="2"><h2>Regional Traffic Controls</h2></th></tr>
        <tr>
          <th scope="row"><label for="netrl_enable_region">Enable regional limits</label></th>
          <td>
            <label>
              <input type="checkbox" id="netrl_enable_region" name="netrl_enable_region" value="1" <?php checked(1, (int)$settings['enable_region']); ?>>
              Enable country-based blocking and penalties (uses CloudFlare header + ip-api.com fallback)
            </label>
          </td>
        </tr>
        <tr>
          <th scope="row"><label for="netrl_blocked_countries">Blocked countries</label></th>
          <td>
            <select name="netrl_blocked_countries[]" id="netrl_blocked_countries" multiple size="10" style="min-width:260px">
              <?php echo netrl_country_options($blockedSelected); ?>
            </select>
            <p><button type="button" class="button netrl-bad-actor-btn" data-target-blocked="netrl_blocked_countries" data-target-penalized="netrl_penalized_countries" data-blocked="<?php echo esc_attr(implode(',', $badActors['blocked'])); ?>" data-penalized="<?php echo esc_attr(implode(',', $badActors['penalized'])); ?>">Apply “Nefarious countries” preset</button></p>
            <p class="description">Hold Cmd/Ctrl to select multiple. ISO codes (e.g., <code>RU</code>, <code>CN</code>, <code>KP</code>). Requests from these countries receive 403 Forbidden.</p>
          </td>
        </tr>
        <tr>
          <th scope="row"><label for="netrl_penalized_countries">Penalized countries</label></th>
          <td>
            <select name="netrl_penalized_countries[]" id="netrl_penalized_countries" multiple size="10" style="min-width:260px">
              <?php echo netrl_country_options($penalizedSelected); ?>
            </select>
            <p class="description">Hold Cmd/Ctrl to select multiple. ISO codes. These countries receive reduced rate limits and initial violation penalties.</p>
          </td>
        </tr>
        <tr>
          <th scope="row"><label for="netrl_penalty_reduction_pct">Penalty: limit reduction (%)</label></th>
          <td>
            <input type="number" min="0" max="100" step="1" id="netrl_penalty_reduction_pct" name="netrl_penalty_reduction_pct" value="<?php echo esc_attr((int)$settings['penalty_reduction_pct']); ?>">
            <p class="description">Reduce soft/hard limits by this percentage for penalized countries (0-100). E.g., 50% means they get half the normal limits.</p>
          </td>
        </tr>
        <tr>
          <th scope="row"><label for="netrl_penalty_violations">Penalty: initial violations</label></th>
          <td>
            <input type="number" min="0" max="10" step="1" id="netrl_penalty_violations" name="netrl_penalty_violations" value="<?php echo esc_attr((int)$settings['penalty_violations']); ?>">
            <p class="description">Initial violation score for penalized countries (0-10). Higher scores mean longer blocks on first offense.</p>
          </td>
        </tr>

        <tr><th colspan="2"><h2>Allowlist</h2></th></tr>
        <tr>
          <th scope="row"><label for="netrl_trusted_proxy_ips">Trusted proxy IPs/CIDRs</label></th>
          <td>
            <textarea name="netrl_trusted_proxy_ips" id="netrl_trusted_proxy_ips" rows="2" cols="60"><?php echo esc_textarea($settings['trusted_proxy_ips']); ?></textarea>
            <p class="description">Only trust CF-Connecting-IP / X-Real-IP / X-Forwarded-For when the request comes from these proxy IPs (one per line, IPv4/IPv6 CIDR).</p>
          </td>
        </tr>
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
  <script>
    document.addEventListener('DOMContentLoaded', function () {
      var buttons = document.querySelectorAll('.netrl-bad-actor-btn');
      buttons.forEach(function (btn) {
        btn.addEventListener('click', function () {
          var blockedCodes = (btn.getAttribute('data-blocked') || '').split(',').filter(Boolean);
          var penalizedCodes = (btn.getAttribute('data-penalized') || '').split(',').filter(Boolean);
          var setSelected = function(id, codes) {
            var sel = document.getElementById(id);
            if (!sel) return;
            var map = {};
            codes.forEach(function(c){ map[c.trim().toUpperCase()] = true; });
            for (var i = 0; i < sel.options.length; i++) {
              var opt = sel.options[i];
              if (map[opt.value.toUpperCase()]) opt.selected = true;
            }
          };
          setSelected(btn.getAttribute('data-target-blocked'), blockedCodes);
          setSelected(btn.getAttribute('data-target-penalized'), penalizedCodes);
        });
      });
    });
  </script>
  <?php
}

/** Render network defaults page (multisite) */
function netrl_render_network_settings_page() {
  if (!current_user_can('manage_network_options')) return;

  if ($_SERVER['REQUEST_METHOD'] === 'POST' && check_admin_referer('netrl_save_network_settings')) {
    $old = (array) get_site_option('netrl_defaults', []);
    $saved = [
      'enabled'         => isset($_POST['netrl_enabled']) ? 1 : 0,
      'day_start'       => isset($_POST['netrl_day_start']) ? max(0, min(23, (int)$_POST['netrl_day_start'])) : 5,
      'day_end'         => isset($_POST['netrl_day_end'])   ? max(0, min(23, (int)$_POST['netrl_day_end']))   : 22,
      'probation_hours' => max(1, min(72, (int)($_POST['netrl_probation_hours'] ?? 6))),
      'allow_uas'       => (string)($_POST['netrl_allow_uas'] ?? ''),
      'allow_hosts'     => (string)($_POST['netrl_allow_hosts'] ?? ''),
      'allow_ips'       => (string)($_POST['netrl_allow_ips'] ?? ''),
      'trusted_proxy_ips'=> (string)($_POST['netrl_trusted_proxy_ips'] ?? ''),
      'allow_ajax'      => (string)($_POST['netrl_allow_ajax'] ?? ''),
      'allow_rest'      => (string)($_POST['netrl_allow_rest'] ?? ''),
      'bypass_header'   => sanitize_text_field((string)($_POST['netrl_bypass_header'] ?? '')),
      'bypass_value'    => (string)($_POST['netrl_bypass_value'] ?? ''),
      'log_bypass'      => isset($_POST['netrl_log_bypass']) ? 1 : 0,
      'log_blocks'      => isset($_POST['netrl_log_blocks']) ? 1 : 0,
      // Regional traffic controls
      'enable_region'         => isset($_POST['netrl_enable_region']) ? 1 : 0,
      'blocked_countries'     => netrl_sanitize_country_codes($_POST['netrl_blocked_countries'] ?? ''),
      'penalized_countries'   => netrl_sanitize_country_codes($_POST['netrl_penalized_countries'] ?? ''),
      'penalty_reduction_pct' => max(0, min(100, (int)($_POST['netrl_penalty_reduction_pct'] ?? 50))),
      'penalty_violations'    => max(0, min(10, (int)($_POST['netrl_penalty_violations'] ?? 2))),
    ];
    update_site_option('netrl_defaults', $saved);

    // Audit log: track configuration changes
    $user = wp_get_current_user();
    $changed = array_diff_assoc($saved, $old);
    if ($changed) {
      error_log(sprintf(
        '[netrl] Network defaults changed by user %s (ID: %d): %s',
        $user->user_login,
        $user->ID,
        json_encode($changed)
      ));
    }

    echo '<div class="updated notice is-dismissible"><p>Network defaults saved. Individual sites can override on their own Settings → Rate Limiter page.</p></div>';
  }

  $defaults = (array) get_site_option('netrl_defaults', netrl_get_settings(0));
  $blockedDefaults = netrl_list($defaults['blocked_countries']);
  $penalizedDefaults = netrl_list($defaults['penalized_countries']);
  $badActors = netrl_bad_actor_countries();
  ?>
  <div class="wrap">
    <h1>Rate Limiter (Network Defaults)</h1>

    <?php
    // Critical warning: no object cache
    if (!netrl_has_object_cache()) {
      echo '<div class="notice notice-error"><p><strong>Critical:</strong> No persistent object cache detected (Redis/Memcached). Rate limiting counters are non-atomic and vulnerable to race conditions. <a href="https://wordpress.org/support/article/optimization/#persistent-object-cache" target="_blank">Install object cache</a> before using in production.</p></div>';
    }

    // Warning: proxy headers detected but not configured
    if (empty($defaults['trusted_proxy_ips']) && netrl_detect_unconfigured_proxy()) {
      echo '<div class="notice notice-warning"><p><strong>Warning:</strong> Proxy headers detected (CF-Connecting-IP, X-Forwarded-For, or X-Real-IP) but no trusted proxy IPs configured. All users will be rate-limited as a single IP address. <a href="#netrl_trusted_proxy_ips">Configure trusted proxies below</a>.</p></div>';
    }
    ?>

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

        <tr><th colspan="2"><h2>Regional Traffic Controls (Defaults)</h2></th></tr>
        <tr>
          <th scope="row"><label for="netrl_enable_region">Default: enable regional limits</label></th>
          <td>
            <label>
              <input type="checkbox" id="netrl_enable_region" name="netrl_enable_region" value="1" <?php checked(1, (int)$defaults['enable_region']); ?>>
              Enable country-based blocking and penalties by default
            </label>
          </td>
        </tr>
        <tr>
          <th scope="row"><label for="netrl_blocked_countries">Default blocked countries</label></th>
          <td>
            <select name="netrl_blocked_countries[]" id="netrl_blocked_countries" multiple size="10" style="min-width:260px">
              <?php echo netrl_country_options($blockedDefaults); ?>
            </select>
            <p><button type="button" class="button netrl-bad-actor-btn" data-target-blocked="netrl_blocked_countries" data-target-penalized="netrl_penalized_countries" data-blocked="<?php echo esc_attr(implode(',', $badActors['blocked'])); ?>" data-penalized="<?php echo esc_attr(implode(',', $badActors['penalized'])); ?>">Apply “Nefarious countries” preset</button></p>
          </td>
        </tr>
        <tr>
          <th scope="row"><label for="netrl_penalized_countries">Default penalized countries</label></th>
          <td>
            <select name="netrl_penalized_countries[]" id="netrl_penalized_countries" multiple size="10" style="min-width:260px">
              <?php echo netrl_country_options($penalizedDefaults); ?>
            </select>
          </td>
        </tr>
        <tr>
          <th scope="row"><label for="netrl_penalty_reduction_pct">Default penalty: limit reduction (%)</label></th>
          <td><input type="number" min="0" max="100" step="1" id="netrl_penalty_reduction_pct" name="netrl_penalty_reduction_pct" value="<?php echo esc_attr((int)$defaults['penalty_reduction_pct']); ?>"></td>
        </tr>
        <tr>
          <th scope="row"><label for="netrl_penalty_violations">Default penalty: initial violations</label></th>
          <td><input type="number" min="0" max="10" step="1" id="netrl_penalty_violations" name="netrl_penalty_violations" value="<?php echo esc_attr((int)$defaults['penalty_violations']); ?>"></td>
        </tr>

        <tr><th colspan="2"><h2>Allowlist (Defaults)</h2></th></tr>
        <tr>
          <th scope="row"><label for="netrl_trusted_proxy_ips">Trusted proxy IPs/CIDRs</label></th>
          <td><textarea name="netrl_trusted_proxy_ips" id="netrl_trusted_proxy_ips" rows="2" cols="60"><?php echo esc_textarea($defaults['trusted_proxy_ips']); ?></textarea></td>
        </tr>
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
  <script>
    document.addEventListener('DOMContentLoaded', function () {
      var buttons = document.querySelectorAll('.netrl-bad-actor-btn');
      buttons.forEach(function (btn) {
        btn.addEventListener('click', function () {
          var blockedCodes = (btn.getAttribute('data-blocked') || '').split(',').filter(Boolean);
          var penalizedCodes = (btn.getAttribute('data-penalized') || '').split(',').filter(Boolean);
          var setSelected = function(id, codes) {
            var sel = document.getElementById(id);
            if (!sel) return;
            var map = {};
            codes.forEach(function(c){ map[c.trim().toUpperCase()] = true; });
            for (var i = 0; i < sel.options.length; i++) {
              var opt = sel.options[i];
              if (map[opt.value.toUpperCase()]) opt.selected = true;
            }
          };
          setSelected(btn.getAttribute('data-target-blocked'), blockedCodes);
          setSelected(btn.getAttribute('data-target-penalized'), penalizedCodes);
        });
      });
    });
  </script>
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
