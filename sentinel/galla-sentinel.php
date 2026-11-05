<?php
/**
 * Galla Ops host sentinel. Read-only integrity collector for WordPress installs.
 *
 * Runs hourly from cron ON the host and POSTs a signed JSON report to Galla Ops.
 * The agent never logs into the host; this script pushes.
 *
 * SAFETY:
 *  - Never loads WordPress (no include of wp-load.php / wp-config.php). An infected functions.php or
 *    db.php drop-in runs on every WordPress bootstrap, including WP-CLI, and could hide itself from
 *    a sentinel that boots WP. This script reads wp-config.php as TEXT and queries MySQL directly.
 *  - Read-only: it never modifies, deletes or quarantines anything. The only file it writes is its own
 *    cache in state_dir (outside the web root). SQL is limited to SELECT/SHOW and the session is set READ ONLY.
 *  - Never collects secrets: no password hashes, no application-password hashes, no wp-config values.
 *
 * Usage: php galla-sentinel.php --config=/home/USER/galla-sentinel/config.json [--dry-run] [--ps=/path/ps.txt]
 * Requires PHP 7.4+ (mysqli or pdo_mysql). No other dependencies.
 */

declare(strict_types=1);
error_reporting(E_ALL & ~E_DEPRECATED & ~E_NOTICE);
@ini_set('memory_limit', '512M');
@set_time_limit(0);

const SENTINEL_VERSION = '1.0.0';
const MAX_SCAN_BYTES = 25 * 1024 * 1024;

const MARKERS = [
    'SC_TH_BEGIN', 'SC_DB_BEGIN', 'haven-engine-go', 'unity-recorder-evo', 'lunar-cache-ops',
    'trace-updater-go', 'surge-panel', 'craft-keeper-ink', 'vital-publisher', 'getServers(', 'cfm-main', 'admetricslab',
];
const DROPINS = [
    'advanced-cache.php', 'db.php', 'db-error.php', 'install.php', 'maintenance.php', 'object-cache.php',
    'php-error.php', 'fatal-error-handler.php', 'sunrise.php', 'blog-deleted.php', 'blog-inactive.php', 'blog-suspended.php',
];
const PHP_EXT = '/\.(php\d?|phtml|phar|pht|inc)$/i';

// ───────────────────────── helpers ─────────────────────────

function out_err(string $m): void { fwrite(STDERR, '[galla-sentinel] ' . $m . PHP_EOL); }

function opt(array $argv, string $name, $default = null) {
    foreach ($argv as $a) {
        if ($a === "--$name") return true;
        if (strpos($a, "--$name=") === 0) return substr($a, strlen($name) + 3);
    }
    return $default;
}

function rel(string $root, string $path): string { return ltrim(substr($path, strlen($root)), '/'); }

/** Parse define('X', 'v') and $table_prefix from wp-config.php WITHOUT executing it. */
function parse_wp_config(string $file): array {
    $src = @file_get_contents($file);
    if ($src === false) throw new RuntimeException("cannot read $file");
    $cfg = [];
    if (preg_match_all('/define\s*\(\s*[\'"]([A-Z_]+)[\'"]\s*,\s*(?:[\'"]((?:[^\'"\\\\]|\\\\.)*)[\'"]|(true|false|\d+))\s*\)/i', $src, $m, PREG_SET_ORDER)) {
        foreach ($m as $d) $cfg[$d[1]] = isset($d[3]) && $d[3] !== '' ? strtolower($d[3]) : stripcslashes($d[2]);
    }
    $cfg['table_prefix'] = preg_match('/\$table_prefix\s*=\s*[\'"]([A-Za-z0-9_]+)[\'"]/', $src, $p) ? $p[1] : 'wp_';
    return $cfg;
}

final class RoDb {
    private $my = null; private $pdo = null;
    public function __construct(array $cfg) {
        $host = $cfg['DB_HOST'] ?? 'localhost'; $port = null; $socket = null;
        if (preg_match('/^(.*?):(\d+)$/', $host, $m)) { $host = $m[1]; $port = (int)$m[2]; }
        elseif (preg_match('/^(.*?):(\/.+)$/', $host, $m)) { $host = $m[1]; $socket = $m[2]; }
        if (function_exists('mysqli_init')) {
            mysqli_report(MYSQLI_REPORT_OFF);
            $this->my = mysqli_init();
            $this->my->options(MYSQLI_OPT_CONNECT_TIMEOUT, 10);
            if (!@$this->my->real_connect($host, $cfg['DB_USER'] ?? '', $cfg['DB_PASSWORD'] ?? '', $cfg['DB_NAME'] ?? '', $port, $socket)) {
                throw new RuntimeException('db connect failed: ' . mysqli_connect_error());
            }
            $this->my->set_charset('utf8mb4');
            @$this->my->query('SET SESSION TRANSACTION READ ONLY');
        } elseif (class_exists('PDO')) {
            $dsn = 'mysql:dbname=' . ($cfg['DB_NAME'] ?? '') . ';charset=utf8mb4;' . ($socket ? "unix_socket=$socket" : "host=$host" . ($port ? ";port=$port" : ''));
            $this->pdo = new PDO($dsn, $cfg['DB_USER'] ?? '', $cfg['DB_PASSWORD'] ?? '', [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_TIMEOUT => 10]);
            @$this->pdo->exec('SET SESSION TRANSACTION READ ONLY');
        } else {
            throw new RuntimeException('neither mysqli nor pdo_mysql is available');
        }
    }
    /** SELECT/SHOW only. Anything else is refused before it reaches MySQL. */
    public function q(string $sql, array $params = []): array {
        if (!preg_match('/^\s*(SELECT|SHOW)\b/i', $sql) || preg_match('/;\s*\S/', $sql)) throw new LogicException('read-only: refused non-SELECT query');
        if ($this->my) {
            $st = $this->my->prepare($sql);
            if (!$st) throw new RuntimeException('query failed: ' . $this->my->error);
            if ($params) { $st->bind_param(str_repeat('s', count($params)), ...$params); }
            $st->execute();
            $res = $st->get_result();
            $rows = $res ? $res->fetch_all(MYSQLI_ASSOC) : [];
            $st->close();
            return $rows;
        }
        $st = $this->pdo->prepare($sql); $st->execute($params);
        return $st->fetchAll(PDO::FETCH_ASSOC);
    }
    public function tableExists(string $t): bool { return (bool)$this->q('SELECT 1 AS x FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = ? LIMIT 1', [$t]); }
}

function safe_unserialize($v) {
    if (!is_string($v)) return $v;
    $r = @unserialize($v, ['allowed_classes' => false]); // never instantiate objects from DB data
    return $r === false && $v !== 'b:0;' ? null : $r;
}

function file_header(string $file, array $fields): array {
    $data = @file_get_contents($file, false, null, 0, 8192);
    $out = [];
    if ($data === false) return $out;
    foreach ($fields as $k => $label) {
        if (preg_match('/^[ \t\/*#@]*' . preg_quote($label, '/') . ':(.*)$/mi', $data, $m)) $out[$k] = trim(preg_replace('/\s*(?:\*\/|\?>).*$/', '', $m[1]));
    }
    return $out;
}

/** Recursive walk without following symlinks. Calls $fn(path, SplFileInfo). Skips listed dirs (absolute). */
function walk(string $dir, callable $fn, array $skip = [], int $limit = 400000): int {
    if (!is_dir($dir)) return 0;
    $n = 0;
    try {
        $it = new RecursiveIteratorIterator(
            new RecursiveCallbackFilterIterator(
                new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS),
                function ($f) use ($skip) {
                    if ($f->isLink()) return false;
                    if ($f->isDir()) { foreach ($skip as $s) if (strpos($f->getPathname(), $s) === 0) return false; }
                    return true;
                }
            ),
            RecursiveIteratorIterator::LEAVES_ONLY,
            RecursiveIteratorIterator::CATCH_GET_CHILD
        );
        foreach ($it as $path => $f) { if (!$f->isFile()) continue; $fn($path, $f); if (++$n >= $limit) break; }
    } catch (Throwable $e) { out_err("walk $dir: " . $e->getMessage()); }
    return $n;
}

/** Cache keyed by path → ctime+size. ctime can't be forged with touch(), unlike mtime (the attacker spoofed mtimes). */
final class Cache {
    public array $data = []; private string $file; public array $used = [];
    public function __construct(string $file) { $this->file = $file; $j = @file_get_contents($file); if ($j) $this->data = json_decode($j, true) ?: []; }
    public function get(string $path, SplFileInfo $f, string $what, callable $compute) {
        $sig = $f->getCTime() . ':' . $f->getMTime() . ':' . $f->getSize();
        $k = $what . '|' . $path; $this->used[$k] = true;
        if (isset($this->data[$k]) && $this->data[$k][0] === $sig) return $this->data[$k][1];
        $v = $compute(); $this->data[$k] = [$sig, $v]; return $v;
    }
    public function save(): void {
        $this->data = array_intersect_key($this->data, $this->used);
        @file_put_contents($this->file . '.tmp', json_encode($this->data));
        @rename($this->file . '.tmp', $this->file);
    }
}

function scan_markers(string $path, SplFileInfo $f, Cache $cache): array {
    return $cache->get($path, $f, 'mk', function () use ($path, $f) {
        if ($f->getSize() > MAX_SCAN_BYTES) return ['__too_big__'];
        $s = @file_get_contents($path);
        if ($s === false) return [];
        $hits = [];
        foreach (MARKERS as $m) if (strpos($s, $m) !== false) $hits[] = $m;
        return $hits;
    });
}

function http_get(string $url, int $timeout = 30): ?string {
    if (function_exists('curl_init')) {
        $c = curl_init($url);
        curl_setopt_array($c, [CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => $timeout, CURLOPT_FOLLOWLOCATION => true, CURLOPT_USERAGENT => 'GallaSentinel/' . SENTINEL_VERSION]);
        $r = curl_exec($c); $code = curl_getinfo($c, CURLINFO_HTTP_CODE); curl_close($c);
        return ($r !== false && $code === 200) ? $r : null;
    }
    $r = @file_get_contents($url, false, stream_context_create(['http' => ['timeout' => $timeout, 'user_agent' => 'GallaSentinel/' . SENTINEL_VERSION]]));
    return $r === false ? null : $r;
}

// ───────────────────────── per-install collection ─────────────────────────

function collect_install(array $inst, Cache $cache, array $cfg): array {
    $root = rtrim($inst['path'], '/');
    $out = ['id' => $inst['id'], 'path' => $root, 'errors' => []];
    $wpc = file_exists("$root/wp-config.php") ? "$root/wp-config.php" : (file_exists(dirname($root) . '/wp-config.php') ? dirname($root) . '/wp-config.php' : null);
    if (!$wpc) { $out['errors'][] = 'wp-config.php not found'; return $out; }
    $content = "$root/wp-content";

    // core version (regex, not include)
    $ver = @file_get_contents("$root/wp-includes/version.php");
    $out['wp_version'] = ($ver && preg_match('/\$wp_version\s*=\s*[\'"]([^\'"]+)/', $ver, $m)) ? $m[1] : null;
    $out['wp_local_package'] = ($ver && preg_match('/\$wp_local_package\s*=\s*[\'"]([^\'"]+)/', $ver, $m)) ? $m[1] : null;

    $wc = parse_wp_config($wpc);
    $p = $wc['table_prefix'];
    $out['multisite'] = in_array(strtolower((string)($wc['MULTISITE'] ?? '')), ['true', '1'], true);
    $out['sites'] = []; $out['admins'] = []; $out['app_passwords'] = []; $out['cron_hooks'] = [];
    $out['suspicious_options'] = []; $out['active_plugins'] = []; $out['active_themes'] = [];

    // ── database (read-only) ──
    try {
        $db = new RoDb($wc);
        $blogs = [['blog_id' => '1', 'url' => '']];
        if ($out['multisite'] && $db->tableExists($p . 'blogs')) {
            $blogs = array_map(fn($b) => ['blog_id' => (string)$b['blog_id'], 'url' => $b['domain'] . $b['path']], $db->q("SELECT blog_id, domain, path FROM `{$p}blogs` WHERE deleted = 0 ORDER BY blog_id"));
        }
        $tp = fn(string $id) => $id === '1' ? $p : "{$p}{$id}_";
        foreach ($blogs as $b) {
            $op = $tp($b['blog_id']) . 'options';
            if (!$db->tableExists($op)) continue;
            $opts = [];
            foreach ($db->q("SELECT option_name, option_value FROM `$op` WHERE option_name IN ('siteurl','active_plugins','stylesheet','template','cron')") as $r) $opts[$r['option_name']] = $r['option_value'];
            $url = $opts['siteurl'] ?? $b['url'];
            $out['sites'][] = ['blog_id' => $b['blog_id'], 'url' => $url];
            $ap = safe_unserialize($opts['active_plugins'] ?? '') ?: [];
            $out['active_plugins'][$b['blog_id']] = array_values(array_filter(is_array($ap) ? $ap : [], 'is_string'));
            $out['active_themes'][$b['blog_id']] = ['stylesheet' => $opts['stylesheet'] ?? null, 'template' => $opts['template'] ?? null];
            $cron = safe_unserialize($opts['cron'] ?? '') ?: [];
            $hooks = [];
            if (is_array($cron)) foreach ($cron as $ts => $evs) if (is_array($evs)) foreach (array_keys($evs) as $h) $hooks[(string)$h] = true;
            foreach (array_keys($hooks) as $h) $out['cron_hooks'][] = ['blog_id' => $b['blog_id'], 'hook' => $h];
            // suspicious options: known payload names, markers inside values, and very large autoloaded options
            $markerLike = implode(' OR ', array_fill(0, count(MARKERS), 'option_value LIKE ?'));
            $params = array_map(fn($m) => '%' . $m . '%', MARKERS);
            $rows = $db->q("SELECT option_name, LENGTH(option_value) AS len, autoload FROM `$op` WHERE option_name LIKE 'wq\\_%' OR option_name LIKE '%\\_payload\\_persistent' OR $markerLike", $params);
            foreach ($rows as $r) $out['suspicious_options'][] = ['blog_id' => $b['blog_id'], 'name' => $r['option_name'], 'len' => (int)$r['len'], 'autoload' => $r['autoload'], 'reason' => 'pattern'];
            foreach ($db->q("SELECT option_name, LENGTH(option_value) AS len, autoload FROM `$op` WHERE autoload IN ('yes','on','auto','auto-on') AND LENGTH(option_value) > 262144 ORDER BY len DESC LIMIT 15") as $r)
                $out['suspicious_options'][] = ['blog_id' => $b['blog_id'], 'name' => $r['option_name'], 'len' => (int)$r['len'], 'autoload' => $r['autoload'], 'reason' => 'large_autoload'];
        }
        if ($out['multisite'] && $db->tableExists($p . 'sitemeta')) {
            $sw = $db->q("SELECT meta_value FROM `{$p}sitemeta` WHERE meta_key = 'active_sitewide_plugins' LIMIT 1");
            $v = $sw ? safe_unserialize($sw[0]['meta_value']) : [];
            $out['active_plugins']['network'] = is_array($v) ? array_keys($v) : [];
            $sa = $db->q("SELECT meta_value FROM `{$p}sitemeta` WHERE meta_key = 'site_admins' LIMIT 1");
            $out['super_admins'] = $sa ? (array)(safe_unserialize($sa[0]['meta_value']) ?: []) : [];
        }
        // administrators on every site (capabilities meta key per blog)
        $rows = $db->q("SELECT u.ID, u.user_login, u.user_email, u.user_registered, m.meta_key FROM `{$p}users` u JOIN `{$p}usermeta` m ON m.user_id = u.ID WHERE m.meta_key LIKE '%capabilities' AND m.meta_value LIKE '%\"administrator\"%'");
        $re = '/^' . preg_quote($p, '/') . '(?:(\d+)_)?capabilities$/';
        foreach ($rows as $r) {
            if (!preg_match($re, $r['meta_key'], $mm)) continue;
            $out['admins'][] = ['blog_id' => isset($mm[1]) && $mm[1] !== '' ? $mm[1] : '1', 'id' => (int)$r['ID'], 'login' => $r['user_login'], 'email' => $r['user_email'], 'registered' => $r['user_registered']];
        }
        // application passwords: metadata only, never the hash
        $rows = $db->q("SELECT u.ID, u.user_login, m.meta_value FROM `{$p}usermeta` m JOIN `{$p}users` u ON u.ID = m.user_id WHERE m.meta_key = '_application_passwords'");
        foreach ($rows as $r) {
            $list = safe_unserialize($r['meta_value']);
            if (!is_array($list)) continue;
            foreach ($list as $ap) {
                if (!is_array($ap)) continue;
                $out['app_passwords'][] = [
                    'user_id' => (int)$r['ID'], 'login' => $r['user_login'], 'uuid' => (string)($ap['uuid'] ?? ''), 'name' => (string)($ap['name'] ?? ''),
                    'created' => isset($ap['created']) ? gmdate('c', (int)$ap['created']) : null,
                    'last_used' => !empty($ap['last_used']) ? gmdate('c', (int)$ap['last_used']) : null,
                    'last_ip' => (string)($ap['last_ip'] ?? ''),
                ];
            }
        }
    } catch (Throwable $e) {
        $out['errors'][] = 'database: ' . $e->getMessage();
    }

    // ── mu-plugins and drop-ins ──
    $out['mu_plugins'] = [];
    walk("$content/mu-plugins", function ($path, $f) use (&$out, $content, $cache) {
        $out['mu_plugins'][] = ['file' => rel("$content/mu-plugins", $path), 'size' => $f->getSize(), 'sha256' => $cache->get($path, $f, 'h', fn() => hash_file('sha256', $path))];
    }, [], 5000);
    $out['dropins'] = [];
    foreach (DROPINS as $d) if (is_file("$content/$d")) { $f = new SplFileInfo("$content/$d"); $out['dropins'][] = ['file' => $d, 'size' => $f->getSize(), 'sha256' => $cache->get("$content/$d", $f, 'h', fn() => hash_file('sha256', "$content/$d"))]; }

    // ── plugins (installed + versions) and elFinder detection ──
    $out['plugins'] = []; $out['elfinder'] = [];
    foreach (glob("$content/plugins/*", GLOB_NOSORT) ?: [] as $pd) {
        $slug = basename($pd);
        if (is_dir($pd)) {
            $main = null; $hdr = [];
            foreach (glob("$pd/*.php", GLOB_NOSORT) ?: [] as $pf) { $h = file_header($pf, ['name' => 'Plugin Name', 'version' => 'Version']); if (!empty($h['name'])) { $main = basename($pf); $hdr = $h; break; } }
            $out['plugins'][] = ['slug' => $slug, 'file' => $main ? "$slug/$main" : null, 'name' => $hdr['name'] ?? null, 'version' => $hdr['version'] ?? null];
        } elseif (preg_match('/\.php$/', $slug)) {
            $h = file_header($pd, ['name' => 'Plugin Name', 'version' => 'Version']);
            if (!empty($h['name'])) $out['plugins'][] = ['slug' => basename($slug, '.php'), 'file' => $slug, 'name' => $h['name'], 'version' => $h['version'] ?? null];
        }
    }
    walk("$content/plugins", function ($path) use (&$out, $content) {
        $b = basename($path);
        if (preg_match('/^(elFinder\.class\.php|elFinderConnector\.class\.php|connector\.(minimal|maximal)\.php)$/i', $b)) $out['elfinder'][] = rel($content, $path);
    });

    // ── themes ──
    $out['themes'] = [];
    foreach (glob("$content/themes/*", GLOB_ONLYDIR | GLOB_NOSORT) ?: [] as $td) {
        $h = file_header("$td/style.css", ['name' => 'Theme Name', 'version' => 'Version', 'template' => 'Template']);
        $fn = "$td/functions.php";
        $out['themes'][] = ['stylesheet' => basename($td), 'name' => $h['name'] ?? null, 'version' => $h['version'] ?? null, 'template' => $h['template'] ?? null,
            'functions_sha256' => is_file($fn) ? $cache->get($fn, new SplFileInfo($fn), 'h', fn() => hash_file('sha256', $fn)) : null];
    }

    // ── one walk of wp-content: zips, PHP in uploads, hidden PHP, markers, root-owned files ──
    $out['zips'] = []; $out['uploads_php'] = []; $out['hidden_php'] = []; $out['markers'] = []; $out['root_owned'] = ['count' => 0, 'sample' => []];
    $checkRoot = !empty($cfg['check_root_owned']);
    $skip = ["$content/cache", "$content/wflogs", "$content/updraft", "$content/ai1wm-backups"];
    $files = walk($content, function ($path, $f) use (&$out, $content, $cache, $checkRoot) {
        $r = rel($content, $path); $b = basename($path);
        if (preg_match('/\.zip$/i', $b)) $out['zips'][] = ['file' => $r, 'size' => $f->getSize(), 'mtime' => gmdate('c', $f->getMTime())];
        $isPhp = (bool)preg_match(PHP_EXT, $b);
        if ($isPhp && strpos($r, 'uploads/') === 0) $out['uploads_php'][] = ['file' => $r, 'size' => $f->getSize(), 'mtime' => gmdate('c', $f->getMTime())];
        if ($isPhp && $b[0] === '.') $out['hidden_php'][] = $r;
        $isThemeAsset = (bool)preg_match('/\.(js|html?)$/i', $b) && strpos($r, 'themes/') === 0;
        if ($isPhp || $isThemeAsset) {
            foreach (scan_markers($path, $f, $cache) as $m) $out['markers'][] = ['file' => $r, 'marker' => $m];
        }
        foreach (['unity-recorder-evo', 'lunar-cache-ops', 'haven-engine-go', 'trace-updater-go', 'surge-panel', 'craft-keeper-ink', 'vital-publisher'] as $n)
            if (stripos($b, $n) !== false) $out['markers'][] = ['file' => $r, 'marker' => "filename:$n"];
        if ($checkRoot && $f->getOwner() === 0) { $out['root_owned']['count']++; if (count($out['root_owned']['sample']) < 300) $out['root_owned']['sample'][] = $r; }
    }, $skip);
    $out['wp_content_files'] = $files;
    // root PHP files (wp-config.php, index.php, ...) read as text for markers only
    foreach (glob("$root/*.php", GLOB_NOSORT) ?: [] as $f) foreach (scan_markers($f, new SplFileInfo($f), $cache) as $m) $out['markers'][] = ['file' => '../' . basename($f), 'marker' => $m];
    $out['wp_content_root'] = [];
    foreach (glob("$content/*", GLOB_NOSORT) ?: [] as $f) if (is_file($f)) $out['wp_content_root'][] = ['file' => basename($f), 'size' => filesize($f), 'sha256' => $cache->get($f, new SplFileInfo($f), 'h', fn() => hash_file('sha256', $f))];

    // ── core checksums against api.wordpress.org (no WP-CLI: WP-CLI boots WordPress) ──
    $out['core'] = ['ok' => null, 'modified' => [], 'missing' => [], 'extra' => [], 'error' => null];
    if ($out['wp_version']) {
        $locale = $out['wp_local_package'] ?: 'en_US';
        $j = http_get('https://api.wordpress.org/core/checksums/1.0/?version=' . urlencode($out['wp_version']) . '&locale=' . urlencode($locale));
        if ($j === null && $locale !== 'en_US') $j = http_get('https://api.wordpress.org/core/checksums/1.0/?version=' . urlencode($out['wp_version']) . '&locale=en_US');
        $sums = $j ? (json_decode($j, true)['checksums'] ?? null) : null;
        if (!is_array($sums) || !$sums) {
            $out['core']['error'] = 'could not fetch checksums from api.wordpress.org';
        } else {
            foreach ($sums as $file => $md5) {
                if (strpos($file, 'wp-content/') === 0) continue;
                $full = "$root/$file";
                if (!is_file($full)) { if (!preg_match('#^wp-admin/install|readme|license|wp-config-sample#i', $file)) $out['core']['missing'][] = $file; continue; }
                $actual = $cache->get($full, new SplFileInfo($full), 'md5', fn() => md5_file($full));
                if ($actual !== $md5) $out['core']['modified'][] = $file;
            }
            foreach (['wp-admin', 'wp-includes'] as $d) {
                walk("$root/$d", function ($path) use (&$out, $root, $sums) { $r = rel($root, $path); if (!isset($sums[$r])) $out['core']['extra'][] = $r; });
            }
            foreach (glob("$root/*.php", GLOB_NOSORT) ?: [] as $f) { $r = basename($f); if (!isset($sums[$r]) && $r !== 'wp-config.php') $out['core']['extra'][] = $r; }
            foreach ($out['core']['extra'] as $x) if (preg_match('#(^|/)\.[^/]+\.php$#', $x)) $out['hidden_php'][] = $x;
            $out['core']['ok'] = !$out['core']['modified'] && !$out['core']['extra'];
        }
    }
    // hidden .php files in core dirs (the .g_<hex>.php daemons) even when checksums couldn't be fetched
    foreach (['wp-admin', 'wp-includes'] as $d) {
        walk("$root/$d", function ($path) use (&$out, $root) { $r = rel($root, $path); if (preg_match('#(^|/)\.[^/]+\.php$#', $r) && !in_array($r, $out['hidden_php'], true)) $out['hidden_php'][] = $r; });
    }
    return $out;
}

// ───────────────────────── main ─────────────────────────

$cfgFile = opt($argv, 'config', __DIR__ . '/config.json');
$cfg = json_decode((string)@file_get_contents($cfgFile), true);
if (!is_array($cfg) || empty($cfg['host_id']) || empty($cfg['installs'])) { out_err("invalid or missing config: $cfgFile"); exit(2); }
$dry = (bool)opt($argv, 'dry-run', false);
if (!$dry && (empty($cfg['endpoint']) || empty($cfg['secret']) || strlen($cfg['secret']) < 32)) { out_err('config needs endpoint and a 32+ char secret'); exit(2); }

$stateDir = $cfg['state_dir'] ?? (__DIR__ . '/state');
if (!is_dir($stateDir)) @mkdir($stateDir, 0700, true);
$cache = new Cache("$stateDir/cache.json");

$report = [
    'v' => 1, 'sentinel_version' => SENTINEL_VERSION, 'host' => $cfg['host_id'], 'generated_at' => gmdate('c'),
    'hostname' => php_uname('n'), 'php_cli_version' => PHP_VERSION, 'sentinel_sha256' => hash_file('sha256', __FILE__), 'installs' => [], 'processes' => [], 'errors' => [],
];

// processes: provided by the bash wrapper (ps output), or read here if shell_exec is allowed
$psFile = opt($argv, 'ps');
$ps = $psFile && is_readable($psFile) ? file_get_contents($psFile) : (function_exists('shell_exec') ? (string)@shell_exec('ps -eo pid,ppid,user,etime,args 2>/dev/null') : '');
foreach (preg_split('/\R/', (string)$ps) as $line) {
    if (preg_match('/\.g_[0-9a-f]{4,}\.php|' . implode('|', array_map(fn($m) => preg_quote($m, '/'), ['haven-engine-go', 'unity-recorder-evo', 'lunar-cache-ops', 'trace-updater-go', 'surge-panel', 'craft-keeper-ink', 'vital-publisher'])) . '/i', $line)) {
        $report['processes'][] = substr(trim($line), 0, 300);
    }
}
if ($ps === '') $report['errors'][] = 'process list unavailable (ps not provided and shell_exec disabled)';

foreach ($cfg['installs'] as $inst) {
    try { $report['installs'][] = collect_install($inst, $cache, $cfg); }
    catch (Throwable $e) { $report['installs'][] = ['id' => $inst['id'] ?? '?', 'path' => $inst['path'] ?? '?', 'errors' => [$e->getMessage()]]; }
}
$cache->save();

$body = json_encode($report, JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
if ($dry) { echo $body, PHP_EOL; exit(0); }

$ts = (string)time();
$nonce = bin2hex(random_bytes(16));
$sig = hash_hmac('sha256', $ts . '.' . $nonce . '.' . hash('sha256', $body), $cfg['secret']);
$headers = ['Content-Type: application/json', 'X-Galla-Host: ' . $cfg['host_id'], "X-Galla-Timestamp: $ts", "X-Galla-Nonce: $nonce", "X-Galla-Signature: $sig"];

$code = 0; $resp = '';
if (function_exists('curl_init')) {
    $c = curl_init($cfg['endpoint']);
    curl_setopt_array($c, [CURLOPT_POST => true, CURLOPT_POSTFIELDS => $body, CURLOPT_HTTPHEADER => $headers, CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 60, CURLOPT_USERAGENT => 'GallaSentinel/' . SENTINEL_VERSION]);
    $resp = (string)curl_exec($c); $code = (int)curl_getinfo($c, CURLINFO_HTTP_CODE); curl_close($c);
} else {
    $resp = (string)@file_get_contents($cfg['endpoint'], false, stream_context_create(['http' => ['method' => 'POST', 'header' => implode("\r\n", $headers), 'content' => $body, 'timeout' => 60, 'ignore_errors' => true]]));
    if (isset($http_response_header[0]) && preg_match('/\s(\d{3})\s/', $http_response_header[0], $m)) $code = (int)$m[1];
}
if ($code !== 200) { out_err("ingest failed: HTTP $code " . substr($resp, 0, 200)); exit(1); }
echo '[galla-sentinel] report accepted (' . strlen($body) . " bytes)\n";
