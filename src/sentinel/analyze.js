// Warden · turns a host sentinel report into security findings.
// Two kinds of rules:
//   ALWAYS  — malware markers, banned file managers / elFinder, .g_*.php processes, payload options,
//             core checksum failures, hidden .php files. These alert whatever the baseline says.
//   BASELINE — things that are legitimate when Adham made them (admins, app passwords, mu-plugins,
//             drop-ins, theme functions.php, PHP in uploads, zips, cron hooks, wp-content root files,
//             installed plugins, root-owned files). These alert only when NEW or CHANGED vs the
//             baseline Adham accepted. Until a baseline exists, they are listed for review instead.
// Every finding carries exact verify/remediate commands for Adham to run himself. Nothing is fixed here.
import { shq } from '../util.js';

export const BANNED_PLUGINS = ['wp-file-manager', 'file-manager-advanced', 'file-manager', 'wp-file-manager-pro', 'fileorganizer', 'filester', 'advanced-file-manager'];
export const KNOWN_DROPIN_USERS = { 'object-cache.php': 'Redis Object Cache', 'advanced-cache.php': 'WP Rocket / page cache' };

const byKey = (arr, f) => Object.fromEntries((arr || []).map((x) => [f(x), x]));

/** The baselineable part of a report, per install. Stable ordering so its hash is stable. */
export function snapshotOf(report) {
  const installs = {};
  for (const i of report.installs || []) {
    const dbOk = !(i.errors || []).some((e) => String(e).startsWith('database'));
    installs[i.id] = {
      dbOk,
      admins: dbOk ? [...new Set((i.admins || []).map((a) => `${a.blog_id}:${a.login}`))].sort() : null,
      appPasswords: dbOk ? (i.app_passwords || []).map((a) => `${a.login}:${a.uuid}`).sort() : null,
      cronHooks: dbOk ? [...new Set((i.cron_hooks || []).map((c) => c.hook))].sort() : null,
      largeOptions: dbOk ? [...new Set((i.suspicious_options || []).filter((o) => o.reason === 'large_autoload').map((o) => `${o.blog_id}:${o.name}`))].sort() : null,
      muPlugins: Object.fromEntries((i.mu_plugins || []).map((m) => [m.file, m.sha256]).sort()),
      dropins: Object.fromEntries((i.dropins || []).map((d) => [d.file, d.sha256]).sort()),
      plugins: (i.plugins || []).map((p) => p.slug).sort(),
      themeFunctions: Object.fromEntries((i.themes || []).filter((t) => t.functions_sha256).map((t) => [t.stylesheet, t.functions_sha256]).sort()),
      uploadsPhp: (i.uploads_php || []).map((u) => u.file).sort(),
      zips: (i.zips || []).map((z) => z.file).sort(),
      contentRoot: Object.fromEntries((i.wp_content_root || []).map((f) => [f.file, f.sha256]).sort()),
      rootOwned: i.root_owned?.count ?? null,
    };
  }
  return { host: report.host, installs };
}

function wp(i, site) {
  const url = site && i.multisite ? ` --url=${shq(site)}` : '';
  return (cmd) => `wp ${cmd} --skip-plugins --skip-themes --path=${shq(i.path)}${url}`;
}
const siteUrl = (i, blogId) => (i.sites || []).find((s) => String(s.blog_id) === String(blogId))?.url || null;
const evidenceCopy = (file) => `mkdir -p ~/incident-evidence && cp -p ${shq(file)} ~/incident-evidence/`;

/**
 * Findings for one report vs (optional) baseline snapshot.
 * Each finding: { id, install, type, severity, title, where, evidence[], verify[], remediate[], todo, baseline: bool }
 */
export function analyzeReport(report, baseline = null, { expectedSentinelSha = null } = {}) {
  const out = [];
  const add = (f) => out.push({ severity: 'critical', evidence: [], verify: [], remediate: [], baseline: false, ...f });
  const hasBaseline = Boolean(baseline);
  if (expectedSentinelSha && report.sentinel_sha256 && report.sentinel_sha256 !== expectedSentinelSha) {
    add({ id: 'sentinel_tampered', install: null, type: 'sentinel_modified', severity: 'high', title: 'The host sentinel script differs from the version in the repo', where: report.hostname,
      evidence: [`reported ${report.sentinel_sha256}`, `expected ${expectedSentinelSha}`], todo: 'If you did not update it, someone edited the monitoring script on the host. Re-upload sentinel/galla-sentinel.php from the repo and check who can write to that folder.',
      verify: ['sha256sum ~/galla-sentinel/galla-sentinel.php'] });
  }
  for (const p of report.processes || []) {
    const pid = /^\s*(\d+)/.exec(p)?.[1];
    add({ id: `proc:${(/\.g_[0-9a-f]+\.php/.exec(p) || [p.slice(-40)])[0]}`, install: null, type: 'process', title: `Malware process running: ${p.slice(0, 120)}`, where: report.hostname,
      evidence: [p], todo: 'A self-spawned .g_<hex>.php daemon re-infects the site. Kill it, then find what spawns it (a mu-plugin, db.php, theme functions.php).',
      verify: ["ps -eo pid,ppid,user,lstart,args | grep -E '\\.g_[0-9a-f]+\\.php' | grep -v grep"],
      remediate: [pid ? `kill -9 ${pid}` : 'kill -9 <PID>', "find ~ -name '.g_*.php' -ls 2>/dev/null"] });
  }

  for (const i of report.installs || []) {
    const base = baseline?.installs?.[i.id] || null;
    const W = (blogId) => wp(i, siteUrl(i, blogId));
    const content = `${i.path}/wp-content`;
    const dbOk = !(i.errors || []).some((e) => String(e).startsWith('database'));

    for (const e of i.errors || []) add({ id: `error:${String(e).slice(0, 40)}`, install: i.id, type: 'sentinel_error', severity: 'medium', title: `Sentinel could not read part of ${i.id}: ${e}`, where: i.path,
      todo: 'Data unavailable for that section until this is fixed. Check the sentinel log in ~/galla-sentinel/state/sentinel.log.' });

    // ── ALWAYS ──
    const markerFiles = new Map();
    for (const m of i.markers || []) markerFiles.set(m.file, [...(markerFiles.get(m.file) || []), m.marker]);
    for (const [file, marks] of markerFiles) {
      const full = file.startsWith('../') ? `${i.path}/${file.slice(3)}` : `${content}/${file}`;
      const isFn = /functions\.php$/.test(file);
      add({ id: `marker:${file}`, install: i.id, type: 'marker', title: `Malware marker ${marks.join(', ')} in ${file}`, where: full, evidence: marks,
        todo: isFn ? 'This is the re-infection pattern from August: theme functions.php rewrites the mu-plugin backdoor on every request. Strip the block, then remove what it drops.' : 'Back up the file as evidence, then remove it. Check theme functions.php and db.php for whatever recreates it.',
        verify: [`grep -n -m5 -F ${shq(marks[0].replace(/^filename:/, ''))} ${shq(full)}`, `ls -la --time-style=full-iso ${shq(full)}`],
        remediate: isFn
          ? ['# block traffic while editing: add "RewriteRule .* - [R=503,L]" at the top of .htaccess', evidenceCopy(full), `sed -i '/SC_TH_BEGIN/,/SC_TH_END/d' ${shq(full)}`, `grep -c -E 'SC_TH_BEGIN|base64_decode|gzinflate' ${shq(full)}  # should print 0`]
          : [evidenceCopy(full), `rm -f ${shq(full)}`] });
    }
    for (const pl of (i.plugins || []).filter((p) => BANNED_PLUGINS.includes(p.slug))) {
      add({ id: `banned:${pl.slug}`, install: i.id, type: 'banned_plugin', title: `Banned plugin installed: ${pl.slug} ${pl.version || ''}`.trim(), where: `${content}/plugins/${pl.slug}`,
        todo: 'File-manager plugins bundle elFinder, the unauthenticated RCE that re-infected these sites. Remove it entirely (deactivating is not enough).',
        verify: [`ls -la ${shq(`${content}/plugins/${pl.slug}`)}`],
        remediate: [W()(`plugin deactivate ${pl.slug} --network`).replace(' --network', i.multisite ? ' --network' : ''), `rm -rf ${shq(`${content}/plugins/${pl.slug}`)}`] });
    }
    for (const f of (i.elfinder || []).filter((f) => !BANNED_PLUGINS.some((b) => f.startsWith(`plugins/${b}/`)))) {
      const slug = f.split('/')[1];
      add({ id: `elfinder:${f}`, install: i.id, type: 'banned_plugin', title: `elFinder connector bundled in plugin "${slug}"`, where: `${content}/${f}`,
        todo: 'Any plugin bundling elFinder is in the same risk class as wp-file-manager. Remove the plugin unless you are sure the connector is unreachable.',
        verify: [`ls -la ${shq(`${content}/${f}`)}`], remediate: [W()(`plugin deactivate ${slug}`), `rm -rf ${shq(`${content}/plugins/${slug}`)}`] });
    }
    for (const o of (i.suspicious_options || []).filter((o) => o.reason === 'pattern')) {
      const w = W(o.blog_id);
      add({ id: `option:${o.blog_id}:${o.name}`, install: i.id, type: 'option', title: `Payload-style option "${o.name}" (${o.len} bytes, autoload ${o.autoload}) on ${siteUrl(i, o.blog_id) || 'blog ' + o.blog_id}`, where: `${i.id} blog ${o.blog_id}`,
        todo: 'Options named wq_* / *_payload_persistent or containing malware markers were how the October reinfection persisted in the database.',
        verify: [`${w(`option get ${shq(o.name)}`)} | head -c 300`],
        remediate: [`${w(`option get ${shq(o.name)}`)} > ~/incident-evidence/${o.name.replace(/[^\w.-]/g, '_')}.txt`, w(`option delete ${shq(o.name)}`)] });
    }
    if (i.core?.modified?.length || i.core?.extra?.length) {
      const files = [...(i.core.modified || []).map((f) => `modified: ${f}`), ...(i.core.extra || []).map((f) => `extra: ${f}`)];
      add({ id: `core:${(i.core.modified || []).concat(i.core.extra || []).sort().join(',').slice(0, 200)}`, install: i.id, type: 'core_checksums', title: `WordPress core checksum failure on ${i.id}: ${i.core.modified.length} modified, ${i.core.extra.length} extra file(s)`, where: i.path,
        evidence: files.slice(0, 30), todo: 'Back up the extra files as evidence and delete them, then reinstall core files (content is untouched).',
        verify: [...(i.core.extra || []).slice(0, 10).map((f) => `ls -la --time-style=full-iso ${shq(`${i.path}/${f}`)} && head -c 400 ${shq(`${i.path}/${f}`)}`)],
        remediate: [...(i.core.extra || []).slice(0, 10).map((f) => `${evidenceCopy(`${i.path}/${f}`)} && rm -f ${shq(`${i.path}/${f}`)}`), W()(`core download --version=${i.wp_version} --force --skip-content`)] });
    } else if (i.core?.error) {
      add({ id: 'core_unverified', install: i.id, type: 'core_unverified', severity: 'medium', title: `Core checksums not verified on ${i.id}: ${i.core.error}`, where: i.path });
    }
    for (const h of (i.hidden_php || []).filter((h) => !(i.core?.extra || []).includes(h))) {
      const full = h.startsWith('wp-') ? `${i.path}/${h}` : `${content}/${h}`;
      add({ id: `hidden:${h}`, install: i.id, type: 'hidden_php', title: `Hidden PHP file ${h}`, where: full, verify: [`ls -la ${shq(full)} && head -c 400 ${shq(full)}`], remediate: [evidenceCopy(full), `rm -f ${shq(full)}`] });
    }

    // ── BASELINE ── (skipped for DB-derived items when the database couldn't be read)
    const diffSet = (now, was) => (was ? now.filter((x) => !was.includes(x)) : now);
    const changedMap = (now, was) => Object.entries(now).filter(([k, v]) => !was || was[k] !== v).map(([k, v]) => ({ k, v, isNew: !was || !(k in was) }));
    const B = (f) => add({ ...f, baseline: true, severity: hasBaseline ? f.severity || 'critical' : 'medium' });

    if (dbOk) {
      const admins = (i.admins || []);
      const newAdmins = diffSet([...new Set(admins.map((a) => `${a.blog_id}:${a.login}`))], base?.admins);
      for (const k of newAdmins) {
        const [blog, login] = [k.split(':')[0], k.split(':').slice(1).join(':')];
        const a = admins.find((x) => `${x.blog_id}:${x.login}` === k);
        const w = W(blog);
        B({ id: `admin:${k}`, install: i.id, type: 'admin', title: `${hasBaseline ? 'New' : 'Existing'} administrator "${login}" (${a?.email}, registered ${a?.registered}) on ${siteUrl(i, blog) || 'blog ' + blog}`, where: `${i.id} blog ${blog}`,
          todo: 'If you did not create this admin, delete it. The backdoor created admin_<hex> / administrator_<hex> accounts before.',
          verify: [w(`user get ${shq(login)} --fields=ID,user_login,user_email,user_registered,roles`), w(`user meta get ${shq(login)} session_tokens`)],
          remediate: [w(`user session destroy ${shq(login)} --all`), w(`user delete ${shq(login)} --reassign=<YOUR_ADMIN_ID>`)] });
      }
      const aps = i.app_passwords || [];
      for (const k of diffSet(aps.map((a) => `${a.login}:${a.uuid}`), base?.appPasswords)) {
        const a = aps.find((x) => `${x.login}:${x.uuid}` === k);
        B({ id: `apppw:${k}`, install: i.id, type: 'app_password', title: `${hasBaseline ? 'New' : 'Existing'} application password "${a.name}" for ${a.login} (created ${a.created || '?'}, last IP ${a.last_ip || 'never used'})`, where: i.id,
          todo: 'Application passwords give REST API access that survives password changes. The attacker used names like sentinel / wpmon / auto-bootstrap.',
          verify: [W()(`user application-password list ${shq(a.login)} --fields=uuid,name,created,last_used,last_ip`)],
          remediate: [W()(`user application-password delete ${shq(a.login)} ${a.uuid}`)] });
      }
      const hooks = diffSet([...new Set((i.cron_hooks || []).map((c) => c.hook))], base?.cronHooks);
      for (const hk of hooks) {
        const c = (i.cron_hooks || []).find((x) => x.hook === hk);
        const w = W(c?.blog_id);
        B({ id: `cron:${hk}`, install: i.id, type: 'cron', severity: /^[a-z0-9_]{12,}$/.test(hk) && /\d/.test(hk) && !/_/.test(hk.slice(0, 3)) ? 'critical' : 'high', title: `${hasBaseline ? 'Unknown' : 'Existing'} wp-cron hook "${hk}"`, where: `${i.id} blog ${c?.blog_id}`,
          todo: 'Random-string hooks with no handler were left by the attacker. Check nothing in the code registers it, then delete.',
          verify: [`${w('cron event list --fields=hook,next_run_relative,recurrence')} | grep -F ${shq(hk)}`, `grep -rn -F ${shq(hk)} ${shq(content)} --include=*.php | head`],
          remediate: [w(`cron event delete ${shq(hk)}`)] });
      }
      for (const k of diffSet([...new Set((i.suspicious_options || []).filter((o) => o.reason === 'large_autoload').map((o) => `${o.blog_id}:${o.name}`))], base?.largeOptions)) {
        const [blog, name] = [k.split(':')[0], k.split(':').slice(1).join(':')];
        const o = i.suspicious_options.find((x) => `${x.blog_id}:${x.name}` === k);
        B({ id: `bigopt:${k}`, install: i.id, type: 'large_option', severity: 'high', title: `${hasBaseline ? 'New' : 'Existing'} large autoloaded option "${name}" (${Math.round(o.len / 1024)} KB)`, where: `${i.id} blog ${blog}`,
          verify: [`${W(blog)(`option get ${shq(name)}`)} | head -c 300`], todo: 'Large autoloaded options slow every page and can hide payloads. Check what it is.' });
      }
    }
    for (const { k, isNew } of changedMap(Object.fromEntries((i.mu_plugins || []).map((m) => [m.file, m.sha256])), base?.muPlugins)) {
      const full = `${content}/mu-plugins/${k}`;
      B({ id: `mu:${k}`, install: i.id, type: 'mu_plugin', title: `${!hasBaseline ? 'Existing' : isNew ? 'New' : 'Changed'} mu-plugin ${k}`, where: full,
        todo: 'mu-plugins load on every request and cannot be disabled from wp-admin. The backdoors hid here (unity-recorder-evo.php, lunar-cache-ops.php).',
        verify: [`ls -la --time-style=full-iso ${shq(full)}`, `sha256sum ${shq(full)}`, `head -c 1500 ${shq(full)}`],
        remediate: [evidenceCopy(full), `rm -f ${shq(full)}`, '# then check theme functions.php and db.php: they recreated it last time'] });
    }
    for (const { k, isNew } of changedMap(Object.fromEntries((i.dropins || []).map((d) => [d.file, d.sha256])), base?.dropins)) {
      const full = `${content}/${k}`;
      B({ id: `dropin:${k}`, install: i.id, type: 'dropin', severity: k === 'db.php' ? 'critical' : 'high', title: `${!hasBaseline ? 'Existing' : isNew ? 'New' : 'Changed'} drop-in ${k}${KNOWN_DROPIN_USERS[k] ? ` (normally ${KNOWN_DROPIN_USERS[k]})` : ''}`, where: full,
        todo: k === 'db.php' ? 'db.php runs before WordPress on every request. Unless you installed W3TC/Query Monitor/HyperDB, it is a backdoor (it was in August).' : 'Check it belongs to the plugin you expect.',
        verify: [`ls -la --time-style=full-iso ${shq(full)}`, `head -c 1500 ${shq(full)}`], remediate: [evidenceCopy(full), `rm -f ${shq(full)}`] });
    }
    const activeThemes = new Set(Object.values(i.active_themes || {}).flatMap((t) => [t?.stylesheet, t?.template]).filter(Boolean));
    for (const { k, isNew } of changedMap(Object.fromEntries((i.themes || []).filter((t) => t.functions_sha256).map((t) => [t.stylesheet, t.functions_sha256])), base?.themeFunctions)) {
      const full = `${content}/themes/${k}/functions.php`;
      B({ id: `fn:${k}`, install: i.id, type: 'theme_functions', severity: activeThemes.has(k) ? 'critical' : 'high', title: `${!hasBaseline ? 'Existing' : isNew ? 'New' : 'Changed'} ${activeThemes.has(k) ? 'ACTIVE ' : ''}theme functions.php: ${k}`, where: full,
        todo: 'If you did not edit this theme, compare with your backup. The SC_TH_BEGIN block lived here.',
        verify: [`sha256sum ${shq(full)}`, `grep -n -E 'SC_TH_BEGIN|base64_decode|gzinflate|str_rot13|eval\\(|getServers' ${shq(full)} | head`, `tail -c 2000 ${shq(full)}`],
        remediate: [evidenceCopy(full), `# remove the injected block, e.g.: sed -i '/SC_TH_BEGIN/,/SC_TH_END/d' ${shq(full)}`] });
    }
    for (const f of diffSet((i.uploads_php || []).map((u) => u.file), base?.uploadsPhp)) {
      const full = `${content}/${f}`;
      B({ id: `upphp:${f}`, install: i.id, type: 'uploads_php', title: `${hasBaseline ? 'New' : 'Existing'} PHP file in uploads: ${f}`, where: full,
        todo: 'Uploads should never contain PHP. Exploit zips unpacked here before.', verify: [`ls -la ${shq(full)} && head -c 400 ${shq(full)}`],
        remediate: [evidenceCopy(full), `rm -f ${shq(full)}`, `printf '<FilesMatch "\\\\.(php|phtml|phar)$">\\nRequire all denied\\n</FilesMatch>\\n' >> ${shq(content + '/uploads/.htaccess')}`] });
    }
    for (const f of diffSet((i.zips || []).map((z) => z.file), base?.zips)) {
      const full = `${content}/${f}`;
      const hexName = /(^|\/)[0-9a-f]{8}\.zip$/.test(f);
      B({ id: `zip:${f}`, install: i.id, type: 'zip', severity: hexName ? 'critical' : 'high', title: `${hasBaseline ? 'New' : 'Existing'} zip in wp-content: ${f}${hexName ? ' (random-hex name like the exploit zips)' : ''}`, where: full,
        verify: [`unzip -l ${shq(full)} | head -30`], remediate: [`mkdir -p ~/incident-evidence && mv ${shq(full)} ~/incident-evidence/`] });
    }
    for (const { k, isNew } of changedMap(Object.fromEntries((i.wp_content_root || []).map((f) => [f.file, f.sha256])), base?.contentRoot)) {
      if (k in (Object.fromEntries((i.dropins || []).map((d) => [d.file, 1])))) continue; // reported as drop-in
      const full = `${content}/${k}`;
      B({ id: `croot:${k}`, install: i.id, type: 'content_root', severity: /\.php\d?$/i.test(k) ? 'critical' : 'high', title: `${!hasBaseline ? 'Existing' : isNew ? 'New' : 'Changed'} file in wp-content root: ${k}`, where: full,
        verify: [`ls -la ${shq(full)} && head -c 400 ${shq(full)}`], remediate: [evidenceCopy(full), `rm -f ${shq(full)}`] });
    }
    for (const slug of diffSet((i.plugins || []).map((p) => p.slug), base?.plugins)) {
      if (BANNED_PLUGINS.includes(slug)) continue;
      const pl = i.plugins.find((p) => p.slug === slug);
      B({ id: `plugin:${slug}`, install: i.id, type: 'plugin', severity: 'high', title: `${hasBaseline ? 'New' : 'Existing'} plugin installed: ${pl.name || slug} ${pl.version || ''}`.trim(), where: `${content}/plugins/${slug}`,
        verify: [W()(`plugin get ${slug} --fields=name,status,version`)], remediate: [W()(`plugin deactivate ${slug}`), W()(`plugin delete ${slug}`)] });
    }
    const ro = i.root_owned?.count;
    if (ro != null && hasBaseline && base?.rootOwned != null && ro > base.rootOwned) {
      add({ id: 'rootowned', install: i.id, type: 'root_owned', severity: 'high', title: `${ro - base.rootOwned} more root-owned file(s) under wp-content (${ro} total)`, where: content, baseline: true,
        evidence: (i.root_owned.sample || []).slice(0, 15), todo: 'Root-owned files mean something ran as root in the web root. Last time it broke WP Rocket\'s cache.',
        verify: [`find ${shq(content)} -user root -not -path '*/cache/*' -printf '%TY-%Tm-%Td %p\\n' | sort | tail -20`],
        remediate: [`chown -R www-data:www-data ${shq(content)}  # only after you know why root wrote there`] });
    }
  }
  return out;
}
