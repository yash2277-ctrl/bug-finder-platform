// discovery_engine.js — Enhanced Endpoint & Asset Discovery Engine
import axios from 'axios';
import https from 'https';
import { URL } from 'url';
import * as cheerio from 'cheerio';

const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36';
const httpsAgent = new https.Agent({ rejectUnauthorized: false });

// Wordlists for discovery
const SUBDOMAIN_PREFIXES = [
  'www', 'mail', 'ftp', 'smtp', 'pop', 'imap', 'webmail', 'ns1', 'ns2',
  'api', 'dev', 'staging', 'test', 'beta', 'admin', 'portal', 'vpn',
  'remote', 'gateway', 'secure', 'login', 'app', 'blog', 'shop',
  'store', 'cdn', 'static', 'assets', 'media', 'img', 'images',
  'docs', 'help', 'support', 'status', 'monitor', 'dashboard',
  'm', 'mobile', 'auth', 'sso', 'oauth', 'git', 'gitlab', 'jenkins',
  'ci', 'jira', 'confluence', 'wiki', 'intranet', 'internal',
  'db', 'database', 'mysql', 'postgres', 'redis', 'mongo',
  'backup', 'old', 'new', 'v2', 'v3', 'sandbox',
  'demo', 'preview', 'stage', 'uat', 'qa', 'prod',
  'cpanel', 'plesk', 'whm', 'webdisk', 'autodiscover',
  'mx', 'mx1', 'mx2', 'relay', 'email', 'newsletter',
  'cloud', 'aws', 'gcp', 'azure', 's3', 'storage',
  'grafana', 'prometheus', 'kibana', 'elasticsearch',
  'docker', 'kubernetes', 'k8s', 'rancher',
  'swagger', 'api-docs', 'openapi', 'graphql',
  'webhook', 'callback', 'oauth2', 'saml'
];

const DIRECTORY_WORDLIST = [
  'admin', 'administrator', 'login', 'dashboard', 'panel', 'wp-admin',
  'api', 'api/v1', 'api/v2', 'api/docs', 'api/swagger', 'api/health',
  'console', 'portal', 'manage', 'manager', 'system', 'backend',
  'backup', 'backups', 'db', 'database', 'dump', 'export', 'archive',
  'config', 'configuration', 'settings', 'setup', 'install', 'wizard',
  'test', 'testing', 'dev', 'debug', 'staging', 'sandbox',
  'uploads', 'upload', 'files', 'media', 'images', 'static', 'assets',
  'private', 'internal', 'secret', 'hidden', '.hidden', '.git',
  'phpmyadmin', 'pma', 'adminer', 'phpMyAdmin', 'pgadmin',
  'wp-content', 'wp-includes', 'wp-config.php.bak', '.env',
  'cgi-bin', 'bin', 'scripts', 'cgi', 'fcgi',
  'logs', 'log', 'error_log', 'access_log', 'audit',
  'tmp', 'temp', 'cache', '.cache', 'sessions',
  'node_modules', 'vendor', 'packages', 'composer',
  '.svn', '.hg', '.bzr', 'CVS', '.gitignore',
  'server-info', 'server-status', 'status', 'health', 'healthcheck',
  'swagger-ui', 'swagger', 'docs', 'documentation', 'redoc',
  'graphql', 'graphiql', 'playground', 'apollo',
  'sitemap.xml', 'crossdomain.xml', 'security.txt', '.well-known',
  'composer.json', 'package.json', 'Gemfile', 'requirements.txt',
  'Dockerfile', 'docker-compose.yml', '.dockerenv', '.dockerignore',
  'wp-cron.php', 'xmlrpc.php', 'readme.html', 'license.txt',
  'user', 'users', 'account', 'accounts', 'profile', 'register',
  'signup', 'signin', 'signout', 'logout', 'password', 'reset',
  'oauth', 'oauth2', 'authorize', 'token', 'callback',
  'webhook', 'webhooks', 'hook', 'hooks', 'integration',
  'v1', 'v2', 'v3', 'version', 'versions', 'release', 'releases'
];

const API_ENDPOINT_PATTERNS = [
  /["'](\/api\/[a-zA-Z0-9_/-]+)["']/g,
  /["'](\/v\d+\/[a-zA-Z0-9_/-]+)["']/g,
  /fetch\(["']([^"']+)["']/g,
  /axios\.(get|post|put|delete)\(["']([^"']+)["']/g,
  /url:\s*["']([^"']+)["']/g,
  /endpoint:\s*["']([^"']+)["']/g,
  /path:\s*["']([^"']+)["']/g,
  /route:\s*["']([^"']+)["']/g,
  /\/graphql/g,
  /\/query/g,
  /\/mutation/g
];

const SECRET_PATTERNS = [
  { name: 'AWS Access Key', pattern: /AKIA[0-9A-Z]{16}/g },
  { name: 'AWS Secret Key', pattern: /[0-9a-zA-Z\/+]{40}/g },
  { name: 'GitHub Token', pattern: /ghp_[a-zA-Z0-9]{36}/g },
  { name: 'GitHub PAT', pattern: /github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}/g },
  { name: 'OpenAI API Key', pattern: /sk-[a-zA-Z0-9]{48}/g },
  { name: 'Stripe Key', pattern: /sk_live_[0-9a-zA-Z]{24,}/g },
  { name: 'Stripe Publishable', pattern: /pk_live_[0-9a-zA-Z]{24,}/g },
  { name: 'Private Key', pattern: /-----BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----/g },
  { name: 'JWT Token', pattern: /eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*/g },
  { name: 'Slack Token', pattern: /xox[baprs]-[0-9a-zA-Z]{10,48}/g },
  { name: 'Slack Webhook', pattern: /https:\/\/hooks\.slack\.com\/services\/T[a-zA-Z0-9_]{8}\/B[a-zA-Z0-9_]{10}\/[a-zA-Z0-9_]{24}/g },
  { name: 'Google API', pattern: /AIza[0-9A-Za-z_-]{35}/g },
  { name: 'Firebase Key', pattern: /AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}/g },
  { name: 'Heroku Key', pattern: /[hH][eE][rR][oO][kK][uU].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}/g },
  { name: 'Mailgun Key', pattern: /key-[0-9a-zA-Z]{32}/g },
  { name: 'SendGrid Key', pattern: /SG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43}/g },
  { name: 'Twilio Key', pattern: /SK[0-9a-fA-F]{32}/g },
  { name: 'Password', pattern: /password\s*[=:]\s*["'][^"']{8,}["']/gi },
  { name: 'Secret', pattern: /secret\s*[=:]\s*["'][^"']{8,}["']/gi },
  { name: 'API Key', pattern: /api[_-]?key\s*[=:]\s*["'][^"']{8,}["']/gi },
  { name: 'Database URL', pattern: /(postgres|mysql|mongodb|redis):\/\/[^:\s]+:[^@\s]+@[^/\s]+/gi }
];

export class DiscoveryEngine {
  constructor(opts = {}) {
    this.opts = { timeout: 10000, maxDepth: 3, maxPages: 50, ...opts };
    this.visited = new Set();
    this.endpoints = new Set();
    this.assets = new Set();
    this.secrets = [];
    this.forms = [];
    this.params = new Set();
  }

  async discover(baseUrl, options = {}) {
    const url = new URL(baseUrl);
    const domain = url.hostname;
    
    console.log(`[*] Starting discovery for ${domain}`);
    
    const results = {
      domain,
      baseUrl,
      subdomains: [],
      endpoints: [],
      assets: [],
      secrets: [],
      forms: [],
      params: [],
      techStack: [],
      discoveredAt: new Date().toISOString()
    };

    // 1. Subdomain enumeration
    results.subdomains = await this.enumerateSubdomains(domain);
    
    // 2. Deep crawl
    const crawlResults = await this.deepCrawl(baseUrl);
    results.endpoints = [...crawlResults.endpoints];
    results.assets = [...crawlResults.assets];
    results.forms = crawlResults.forms;
    results.params = [...crawlResults.params];
    
    // 3. JavaScript analysis
    const jsResults = await this.analyzeJavaScript(crawlResults.jsFiles);
    results.endpoints.push(...jsResults.endpoints);
    results.secrets.push(...jsResults.secrets);
    
    // 4. Directory brute force
    const dirResults = await this.bruteForceDirectories(baseUrl);
    results.endpoints.push(...dirResults);
    
    // 5. API discovery
    const apiResults = await this.discoverAPIs(baseUrl);
    results.endpoints.push(...apiResults);
    
    // 6. Technology fingerprinting
    results.techStack = await this.fingerprintTech(baseUrl);
    
    // Deduplicate
    results.endpoints = [...new Set(results.endpoints.map(e => JSON.stringify(e)))].map(e => JSON.parse(e));
    results.assets = [...new Set(results.assets)];
    
    return results;
  }

  async enumerateSubdomains(domain) {
    const found = new Set();
    
    // DNS brute force
    const dns = await import('dns/promises');
    
    for (const prefix of SUBDOMAIN_PREFIXES) {
      const subdomain = `${prefix}.${domain}`;
      try {
        await dns.resolve4(subdomain);
        found.add(subdomain);
      } catch (e) {}
    }
    
    // Try certificate transparency (if available)
    try {
      const ctUrl = `https://crt.sh/?q=%.${domain}&output=json`;
      const r = await axios.get(ctUrl, { timeout: 15000, validateStatus: () => true });
      if (r.data && Array.isArray(r.data)) {
        for (const entry of r.data) {
          const names = (entry.name_value || '').split('\n');
          for (const name of names) {
            const clean = String(name || '').trim().toLowerCase();
            if (clean.endsWith(domain) && clean !== domain) {
              found.add(clean.replace(/^\*\./, ''));
            }
          }
        }
      }
    } catch (e) {}
    
    return [...found].map(s => ({ subdomain: s, source: 'enumeration' }));
  }

  async deepCrawl(startUrl, depth = 0) {
    if (depth >= this.opts.maxDepth || this.visited.size >= this.opts.maxPages) {
      return { endpoints: [], assets: [], jsFiles: [], forms: [], params: [] };
    }
    
    if (this.visited.has(startUrl)) {
      return { endpoints: [], assets: [], jsFiles: [], forms: [], params: [] };
    }
    
    this.visited.add(startUrl);
    
    try {
      const r = await axios.get(startUrl, {
        timeout: this.opts.timeout,
        validateStatus: () => true,
        headers: { 'User-Agent': UA },
        httpsAgent
      });
      
      const body = typeof r.data === 'string' ? r.data : '';
      const $ = cheerio.load(body);
      const base = new URL(startUrl);
      
      const results = {
        endpoints: [],
        assets: [],
        jsFiles: [],
        forms: [],
        params: []
      };
      
      // Extract links
      $('a[href]').each((_, el) => {
        const href = $(el).attr('href');
        if (href) {
          try {
            const abs = new URL(href, startUrl).href;
            const absBase = new URL(abs).origin;
            if (absBase === base.origin) {
              results.endpoints.push({ url: abs, method: 'GET', source: 'crawl' });
              if (abs.endsWith('.js')) results.jsFiles.push(abs);
            }
          } catch (e) {}
        }
      });
      
      // Extract forms
      $('form').each((_, el) => {
        const action = $(el).attr('action') || startUrl;
        const method = ($(el).attr('method') || 'GET').toUpperCase();
        const inputs = [];
        
        $(el).find('input, textarea, select').each((_, input) => {
          const name = $(input).attr('name');
          const type = $(input).attr('type') || 'text';
          if (name) inputs.push({ name, type });
        });
        
        results.forms.push({
          action: new URL(action, startUrl).href,
          method,
          inputs,
          source: startUrl
        });
        
        inputs.forEach(i => results.params.push(i.name));
      });
      
      // Extract scripts
      $('script[src]').each((_, el) => {
        const src = $(el).attr('src');
        if (src) {
          try {
            const abs = new URL(src, startUrl).href;
            results.assets.push(abs);
            results.jsFiles.push(abs);
          } catch (e) {}
        }
      });
      
      // Extract stylesheets
      $('link[rel="stylesheet"]').each((_, el) => {
        const href = $(el).attr('href');
        if (href) {
          try {
            results.assets.push(new URL(href, startUrl).href);
          } catch (e) {}
        }
      });
      
      // Extract images
      $('img[src]').each((_, el) => {
        const src = $(el).attr('src');
        if (src) {
          try {
            results.assets.push(new URL(src, startUrl).href);
          } catch (e) {}
        }
      });
      
      // Extract URL parameters from all links
      results.endpoints.forEach(ep => {
        try {
          const u = new URL(ep.url);
          u.searchParams.forEach((_, key) => results.params.push(key));
        } catch (e) {}
      });
      
      // Crawl deeper
      if (depth < this.opts.maxDepth) {
        for (const ep of results.endpoints.slice(0, 10)) {
          const deeper = await this.deepCrawl(ep.url, depth + 1);
          results.endpoints.push(...deeper.endpoints);
          results.assets.push(...deeper.assets);
          results.jsFiles.push(...deeper.jsFiles);
          results.forms.push(...deeper.forms);
          results.params.push(...deeper.params);
        }
      }
      
      return results;
    } catch (e) {
      return { endpoints: [], assets: [], jsFiles: [], forms: [], params: [] };
    }
  }

  async analyzeJavaScript(jsFiles) {
    const results = { endpoints: [], secrets: [] };
    
    for (const jsUrl of jsFiles.slice(0, 20)) {
      try {
        const r = await axios.get(jsUrl, {
          timeout: 10000,
          validateStatus: () => true,
          headers: { 'User-Agent': UA },
          httpsAgent
        });
        
        const body = typeof r.data === 'string' ? r.data : '';
        
        // Extract API endpoints
        for (const pattern of API_ENDPOINT_PATTERNS) {
          const matches = body.matchAll(pattern);
          for (const match of matches) {
            const endpoint = match[1] || match[2];
            if (endpoint && endpoint.startsWith('/')) {
              results.endpoints.push({ url: endpoint, method: 'GET', source: `js:${jsUrl}` });
            }
          }
        }
        
        // Extract secrets
        for (const secret of SECRET_PATTERNS) {
          const matches = body.matchAll(secret.pattern);
          for (const match of matches) {
            results.secrets.push({
              type: secret.name,
              value: match[0].substring(0, 50),
              source: jsUrl,
              confidence: 90
            });
          }
        }
      } catch (e) {}
    }
    
    return results;
  }

  async bruteForceDirectories(baseUrl) {
    const found = [];
    const base = baseUrl.replace(/\/$/, '');
    
    const checks = DIRECTORY_WORDLIST.map(async path => {
      try {
        const url = `${base}/${path}`;
        const r = await axios.get(url, {
          timeout: 5000,
          validateStatus: () => true,
          headers: { 'User-Agent': UA },
          httpsAgent,
          maxRedirects: 0
        });
        
        if (r.status < 400 && r.status !== 0) {
          const body = typeof r.data === 'string' ? r.data : '';
          const size = body.length;
          if (size > 50) {
            found.push({ url, method: 'GET', status: r.status, size, source: 'dirbust' });
          }
        }
      } catch (e) {}
    });
    
    // Run in batches of 10
    for (let i = 0; i < checks.length; i += 10) {
      await Promise.all(checks.slice(i, i + 10));
    }
    
    return found;
  }

  async discoverAPIs(baseUrl) {
    const endpoints = [];
    const apiPaths = ['/api', '/api/v1', '/api/v2', '/graphql', '/swagger.json', '/openapi.json'];
    
    for (const path of apiPaths) {
      try {
        const url = `${baseUrl}${path}`;
        const r = await axios.get(url, {
          timeout: 10000,
          validateStatus: () => true,
          headers: { 'User-Agent': UA, 'Accept': 'application/json' },
          httpsAgent
        });
        
        if (r.status === 200) {
          const body = typeof r.data === 'string' ? r.data : JSON.stringify(r.data);
          
          // Parse OpenAPI/Swagger
          if (body.includes('"paths"') || body.includes('"swagger"') || body.includes('"openapi"')) {
            try {
              const spec = typeof r.data === 'string' ? JSON.parse(r.data) : r.data;
              const paths = spec.paths || {};
              for (const [p, methods] of Object.entries(paths)) {
                for (const method of Object.keys(methods)) {
                  endpoints.push({
                    url: `${baseUrl}${p}`,
                    method: method.toUpperCase(),
                    source: 'openapi',
                    params: Object.keys(methods[method].parameters || {})
                  });
                }
              }
            } catch (e) {}
          }
          
          // GraphQL introspection
          if (path === '/graphql') {
            endpoints.push({ url, method: 'POST', source: 'graphql' });
          }
        }
      } catch (e) {}
    }
    
    return endpoints;
  }

  async fingerprintTech(url) {
    const tech = [];
    
    try {
      const r = await axios.get(url, {
        timeout: 10000,
        validateStatus: () => true,
        headers: { 'User-Agent': UA },
        httpsAgent
      });
      
      const headers = r.headers || {};
      const body = typeof r.data === 'string' ? r.data : '';
      
      // Server header
      if (headers.server) {
        const s = headers.server;
        if (s.includes('nginx')) tech.push({ name: 'nginx', version: s.match(/nginx\/([\d.]+)/)?.[1], category: 'server' });
        if (s.includes('Apache')) tech.push({ name: 'Apache', version: s.match(/Apache\/([\d.]+)/)?.[1], category: 'server' });
        if (s.includes('IIS')) tech.push({ name: 'IIS', category: 'server' });
        if (s.includes('cloudflare')) tech.push({ name: 'Cloudflare', category: 'cdn' });
      }
      
      // X-Powered-By
      if (headers['x-powered-by']) {
        const p = headers['x-powered-by'];
        if (p.includes('PHP')) tech.push({ name: 'PHP', version: p.match(/PHP\/([\d.]+)/)?.[1], category: 'language' });
        if (p.includes('ASP.NET')) tech.push({ name: 'ASP.NET', version: p.match(/ASP\.NET\s+([\d.]+)/)?.[1], category: 'framework' });
      }
      
      // Body analysis
      if (body.includes('wp-content') || body.includes('wp-includes')) {
        tech.push({ name: 'WordPress', category: 'cms' });
      }
      if (body.includes('Drupal.settings')) {
        tech.push({ name: 'Drupal', category: 'cms' });
      }
      if (body.includes('__NEXT_DATA__')) {
        tech.push({ name: 'Next.js', category: 'framework' });
      }
      if (body.includes('react-root') || body.includes('reactroot')) {
        tech.push({ name: 'React', category: 'framework' });
      }
      if (body.includes('vue-app') || body.includes('__vue__')) {
        tech.push({ name: 'Vue.js', category: 'framework' });
      }
      if (body.includes('ng-version') || body.includes('ng-app')) {
        tech.push({ name: 'Angular', category: 'framework' });
      }
      if (body.includes('laravel_session')) {
        tech.push({ name: 'Laravel', category: 'framework' });
      }
      if (body.includes('django') || body.includes('csrfmiddlewaretoken')) {
        tech.push({ name: 'Django', category: 'framework' });
      }
      if (body.includes('express') || body.includes('Express')) {
        tech.push({ name: 'Express', category: 'framework' });
      }
      if (body.includes('swagger-ui') || body.includes('openapi')) {
        tech.push({ name: 'Swagger/OpenAPI', category: 'api' });
      }
      if (body.includes('graphql') || body.includes('__schema')) {
        tech.push({ name: 'GraphQL', category: 'api' });
      }
      
    } catch (e) {}
    
    return tech;
  }
}

export default DiscoveryEngine;
