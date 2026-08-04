// ai_analyzer.js — AI-Powered Vulnerability Analysis Engine
import axios from 'axios';
import https from 'https';
import crypto from 'crypto';

const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36';
const httpsAgent = new https.Agent({ rejectUnauthorized: false });

// Vulnerability patterns database
const PATTERNS = {
  sqli: {
    name: 'SQL Injection',
    severity: 'critical',
    cvss: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    errors: [
      { r: /SQL syntax.*MySQL|mysql_|MySQLSyntaxErrorException/i, db: 'MySQL', c: 95 },
      { r: /PostgreSQL.*ERROR|PG::Error|PSQLException/i, db: 'PostgreSQL', c: 95 },
      { r: /Microsoft SQL Server|ODBC SQL Server|SQLServer JDBC/i, db: 'MSSQL', c: 95 },
      { r: /Oracle.*Error|ORA-[0-9]{5}/i, db: 'Oracle', c: 95 },
      { r: /SQLite.*Error|sqlite3\.OperationalError/i, db: 'SQLite', c: 95 },
      { r: /SQLSTATE\[[0-9]{5}\]|You have an error in your SQL/i, db: 'Unknown', c: 85 }
    ],
    timePayloads: ["' AND SLEEP(5)--", "' AND pg_sleep(5)--", "'; WAITFOR DELAY '0:0:5'--"],
    boolPayloads: { t: ["' AND '1'='1", "1 AND 1=1"], f: ["' AND '1'='2", "1 AND 1=2"] }
  },
  xss: {
    name: 'Cross-Site Scripting',
    severity: 'high',
    cvss: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N',
    patterns: [/<script[^>]*>.*?<\/script>/i, /javascript:/i, /on\w+\s*=/i, /<svg[^>]*onload/i, /<img[^>]*onerror/i],
    payloads: ['<script>alert(1)</script>', '<img src=x onerror=alert(1)>', '<svg onload=alert(1)>']
  },
  rce: {
    name: 'Remote Code Execution',
    severity: 'critical',
    cvss: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    indicators: [
      { r: /uid=\d+\(\w+\)\s+gid=\d+\(\w+\)/, cmd: 'id', c: 98 },
      { r: /root:.*:0:0:/, cmd: 'cat /etc/passwd', c: 98 },
      { r: /Linux\s+\w+\s+\d+\.\d+/, cmd: 'uname', c: 95 },
      { r: /total\s+\d+|drwxr-xr-x/, cmd: 'ls', c: 90 }
    ],
    payloads: ['; id', '| id', '$(id)', '`id`', '; whoami', '| whoami']
  },
  lfi: {
    name: 'Local File Inclusion',
    severity: 'high',
    cvss: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
    indicators: [
      { r: /root:.*:0:0:/, f: '/etc/passwd', c: 98 },
      { r: /<\?php.*\?>/s, f: 'php', c: 90 }
    ],
    payloads: ['../../../etc/passwd', '....//....//....//etc/passwd', '/proc/self/environ', 'php://filter/convert.base64-encode/resource=index.php']
  },
  ssti: {
    name: 'Server-Side Template Injection',
    severity: 'critical',
    cvss: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    engines: [
      { name: 'Jinja2', p: ['{{7*7}}', '{{7*\'7\'}}'], e: ['49', '7777777'] },
      { name: 'Freemarker', p: ['${7*7}'], e: ['49'] },
      { name: 'Velocity', p: ['#set($x=7*7)${x}'], e: ['49'] }
    ]
  },
  ssrf: {
    name: 'Server-Side Request Forgery',
    severity: 'high',
    cvss: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N',
    targets: ['http://127.0.0.1', 'http://localhost', 'http://169.254.169.254/latest/meta-data/'],
    indicators: [
      { r: /ami-id|instance-id|local-hostname/, s: 'AWS', c: 98 },
      { r: /root:.*:0:0:/, s: 'passwd', c: 98 }
    ]
  },
  info: {
    name: 'Information Disclosure',
    severity: 'medium',
    patterns: [
      { r: /AKIA[0-9A-Z]{16}/, t: 'AWS Key', c: 98 },
      { r: /ghp_[a-zA-Z0-9]{36}/, t: 'GitHub Token', c: 98 },
      { r: /sk_live_[0-9a-zA-Z]{24,}/, t: 'Stripe Key', c: 98 },
      { r: /-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----/, t: 'Private Key', c: 98 },
      { r: /internal server error|stack trace|debug mode/i, t: 'Debug Info', c: 80 }
    ]
  }
};

export class AIAnalyzer {
  constructor(opts = {}) {
    this.opts = { timeout: 10000, verify: true, threshold: 80, ...opts };
    this.cache = new Map();
  }

  createFingerprint(url, body, headers) {
    return `${url}|${body.length}|${Object.keys(headers).join(',')}`;
  }

  async analyze(url, response, ctx = {}) {
    const body = typeof response.data === 'string' ? response.data : JSON.stringify(response.data);
    const headers = response.headers || {};
    
    const fp = this.createFingerprint(url, body, headers);
    const key = crypto.createHash('md5').update(fp).digest('hex');
    if (this.cache.has(key)) return this.cache.get(key);

    const results = await Promise.all([
      this.detectSQLI(url, body, ctx),
      this.detectXSS(url, body, ctx),
      this.detectRCE(url, body, ctx),
      this.detectLFI(url, body, ctx),
      this.detectSSTI(url, body, ctx),
      this.detectSSRF(url, body, ctx),
      this.detectInfo(body, headers)
    ]);

    const findings = results.filter(r => r && r.vulnerable);
    const analysis = {
      url, findings, riskScore: this.calcRisk(findings),
      confidence: this.calcConfidence(findings),
      timestamp: new Date().toISOString()
    };
    
    this.cache.set(key, analysis);
    return analysis;
  }

  async detectSQLI(url, body, ctx) {
    const p = PATTERNS.sqli;
    const findings = [];
    let db = null, maxC = 0;

    for (const pat of p.errors) {
      if (pat.r.test(body)) {
        const m = body.match(pat.r);
        findings.push({ type: 'SQLi', subtype: 'Error', evidence: m[0], db: pat.db, confidence: pat.c });
        maxC = Math.max(maxC, pat.c);
        db = pat.db;
      }
    }

    if (findings.length && this.opts.verify && ctx.params) {
      const tb = await this.verifyTimeSQLI(url, ctx.params);
      if (tb.vulnerable) {
        findings.push({ type: 'SQLi', subtype: 'Time-based', evidence: `Delay: ${tb.delay}ms`, db, confidence: 95 });
      }
    }

    if (!findings.length) return { vulnerable: false };
    return {
      vulnerable: true, type: 'SQL Injection', severity: p.severity,
      cvssScore: this.calcCVSS(p.cvss), cvssVector: p.cvss,
      findings, confidence: maxC, database: db
    };
  }

  async verifyTimeSQLI(url, params) {
    const param = params[0] || 'id';
    for (const payload of PATTERNS.sqli.timePayloads) {
      try {
        const testUrl = `${url}${url.includes('?') ? '&' : '?'}${param}=${encodeURIComponent(payload)}`;
        const start = Date.now();
        await axios.get(testUrl, { timeout: 15000, validateStatus: () => true, headers: { 'User-Agent': UA }, httpsAgent });
        const elapsed = Date.now() - start;
        
        if (elapsed > 4000) {
          const bStart = Date.now();
          await axios.get(`${url}${url.includes('?') ? '&' : '?'}${param}=1`, { timeout: 10000, validateStatus: () => true, headers: { 'User-Agent': UA }, httpsAgent });
          if (Date.now() - bStart < 2000) return { vulnerable: true, delay: elapsed };
        }
      } catch (e) { continue; }
    }
    return { vulnerable: false };
  }

  async detectXSS(url, body, ctx) {
    const p = PATTERNS.xss;
    const findings = [];

    for (const pat of p.patterns) {
      if (pat.test(body)) {
        const m = body.match(pat);
        findings.push({ type: 'XSS', subtype: 'Reflected', evidence: m[0].substring(0, 100), confidence: 85 });
      }
    }

    if (ctx.params && this.opts.verify) {
      for (const payload of p.payloads) {
        try {
          const param = ctx.params[0] || 'q';
          const testUrl = `${url}${url.includes('?') ? '&' : '?'}${param}=${encodeURIComponent(payload)}`;
          const r = await axios.get(testUrl, { timeout: 10000, validateStatus: () => true, headers: { 'User-Agent': UA }, httpsAgent });
          const rb = typeof r.data === 'string' ? r.data : '';
          if (rb.includes(payload) || rb.includes('alert(1)')) {
            findings.push({ type: 'XSS', subtype: 'Verified', evidence: 'Payload reflected', payload, confidence: 95 });
            break;
          }
        } catch (e) { continue; }
      }
    }

    if (!findings.length) return { vulnerable: false };
    return {
      vulnerable: true, type: 'XSS', severity: p.severity,
      cvssScore: this.calcCVSS(p.cvss), cvssVector: p.cvss,
      findings, confidence: Math.max(...findings.map(f => f.confidence))
    };
  }

  async detectRCE(url, body, ctx) {
    const p = PATTERNS.rce;
    const findings = [];

    for (const ind of p.indicators) {
      if (ind.r.test(body)) {
        const m = body.match(ind.r);
        findings.push({ type: 'RCE', subtype: 'Output', evidence: m[0], cmd: ind.cmd, confidence: ind.c });
      }
    }

    if (!findings.length) return { vulnerable: false };
    return {
      vulnerable: true, type: 'RCE', severity: p.severity,
      cvssScore: this.calcCVSS(p.cvss), cvssVector: p.cvss,
      findings, confidence: Math.max(...findings.map(f => f.confidence))
    };
  }

  async detectLFI(url, body, ctx) {
    const p = PATTERNS.lfi;
    const findings = [];

    for (const ind of p.indicators) {
      if (ind.r.test(body)) {
        const m = body.match(ind.r);
        findings.push({ type: 'LFI', subtype: 'File', evidence: m[0], file: ind.f, confidence: ind.c });
      }
    }

    if (!findings.length) return { vulnerable: false };
    return {
      vulnerable: true, type: 'LFI', severity: p.severity,
      cvssScore: this.calcCVSS(p.cvss), cvssVector: p.cvss,
      findings, confidence: Math.max(...findings.map(f => f.confidence))
    };
  }

  async detectSSTI(url, body, ctx) {
    const p = PATTERNS.ssti;
    const findings = [];

    if (ctx.params && this.opts.verify) {
      for (const eng of p.engines) {
        for (let i = 0; i < eng.p.length; i++) {
          try {
            const param = ctx.params[0] || 'name';
            const testUrl = `${url}${url.includes('?') ? '&' : '?'}${param}=${encodeURIComponent(eng.p[i])}`;
            const r = await axios.get(testUrl, { timeout: 10000, validateStatus: () => true, headers: { 'User-Agent': UA }, httpsAgent });
            const rb = typeof r.data === 'string' ? r.data : '';
            if (rb.includes(eng.e[i]) && !rb.includes(eng.p[i])) {
              findings.push({ type: 'SSTI', subtype: eng.name, evidence: `${eng.p[i]} -> ${eng.e[i]}`, confidence: 95 });
            }
          } catch (e) { continue; }
        }
      }
    }

    if (!findings.length) return { vulnerable: false };
    return {
      vulnerable: true, type: 'SSTI', severity: p.severity,
      cvssScore: this.calcCVSS(p.cvss), cvssVector: p.cvss,
      findings, confidence: Math.max(...findings.map(f => f.confidence))
    };
  }

  async detectSSRF(url, body, ctx) {
    const p = PATTERNS.ssrf;
    const findings = [];

    for (const ind of p.indicators) {
      if (ind.r.test(body)) {
        const m = body.match(ind.r);
        findings.push({ type: 'SSRF', subtype: ind.s, evidence: m[0], confidence: ind.c });
      }
    }

    if (!findings.length) return { vulnerable: false };
    return {
      vulnerable: true, type: 'SSRF', severity: p.severity,
      cvssScore: this.calcCVSS(p.cvss), cvssVector: p.cvss,
      findings, confidence: Math.max(...findings.map(f => f.confidence))
    };
  }

  detectInfo(body, headers) {
    const p = PATTERNS.info;
    const findings = [];

    for (const pat of p.patterns) {
      if (pat.r.test(body)) {
        const m = body.match(pat.r);
        findings.push({ type: 'Info Disclosure', subtype: pat.t, evidence: m[0].substring(0, 100), confidence: pat.c });
      }
    }

    if (!findings.length) return { vulnerable: false };
    return {
      vulnerable: true, type: 'Info Disclosure', severity: p.severity,
      findings, confidence: Math.max(...findings.map(f => f.confidence))
    };
  }

  calcCVSS(vector) {
    // Simplified CVSS calculation
    if (vector.includes('C:H') && vector.includes('I:H') && vector.includes('A:H')) return 9.8;
    if (vector.includes('C:H') || vector.includes('I:H')) return 8.1;
    if (vector.includes('C:L') || vector.includes('I:L')) return 5.4;
    return 3.1;
  }

  calcRisk(findings) {
    if (!findings.length) return 0;
    const scores = findings.map(f => {
      const s = f.cvssScore || 5;
      return f.severity === 'critical' ? s * 1.5 : f.severity === 'high' ? s * 1.2 : s;
    });
    return Math.min(100, Math.round(scores.reduce((a, b) => a + b, 0) / findings.length * 10));
  }

  calcConfidence(findings) {
    if (!findings.length) return 0;
    return Math.round(findings.reduce((a, f) => a + (f.confidence || 80), 0) / findings.length);
  }

  // Context-aware payload generation
  generatePayloads(vulnType, context) {
    const payloads = [];
    const base = PATTERNS[String(vulnType || '').toLowerCase()];
    if (!base) return payloads;

    // Add base payloads
    if (base.payloads) payloads.push(...base.payloads);

    // Context-specific modifications
    if (context.tech) {
      if (context.tech.includes('PHP')) {
        if (vulnType === 'sqli') payloads.push("1' AND SLEEP(5) AND '1'='1", "1' AND pg_sleep(5) AND '1'='1");
        if (vulnType === 'lfi') payloads.push('php://filter/convert.base64-encode/resource=index.php', 'php://input');
      }
      if (context.tech.includes('Java')) {
        if (vulnType === 'sqli') payloads.push("1' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('A',5)--");
      }
    }

    return [...new Set(payloads)];
  }
}

export default AIAnalyzer;
