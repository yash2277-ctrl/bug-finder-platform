// threat_intel.js — Threat Intelligence & CVE Database Engine
import axios from 'axios';
import fs from 'fs/promises';
import path from 'path';
import crypto from 'crypto';

const NVD_API_BASE = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
const EXPLOITDB_API = 'https://www.exploit-db.com/search';
const CACHE_DIR = './cache';
const CACHE_TTL = 24 * 60 * 60 * 1000; // 24 hours

// Technology to CPE mapping for accurate CVE lookup
const CPE_MAPPINGS = {
  'apache': { vendor: 'apache', products: ['http_server', 'tomcat', 'struts', 'log4j'] },
  'nginx': { vendor: 'nginx', products: ['nginx'] },
  'php': { vendor: 'php', products: ['php'] },
  'mysql': { vendor: 'oracle', products: ['mysql'] },
  'postgresql': { vendor: 'postgresql', products: ['postgresql'] },
  'mongodb': { vendor: 'mongodb', products: ['mongodb'] },
  'redis': { vendor: 'redis', products: ['redis'] },
  'wordpress': { vendor: 'wordpress', products: ['wordpress'] },
  'drupal': { vendor: 'drupal', products: ['drupal'] },
  'jenkins': { vendor: 'jenkins', products: ['jenkins'] },
  'gitlab': { vendor: 'gitlab', products: ['gitlab'] },
  'docker': { vendor: 'docker', products: ['docker'] },
  'kubernetes': { vendor: 'kubernetes', products: ['kubernetes'] },
  'node.js': { vendor: 'nodejs', products: ['node.js'] },
  'express': { vendor: 'expressjs', products: ['express'] },
  'react': { vendor: 'facebook', products: ['react'] },
  'angular': { vendor: 'angular', products: ['angular'] },
  'vue': { vendor: 'vuejs', products: ['vue'] },
  'django': { vendor: 'djangoproject', products: ['django'] },
  'flask': { vendor: 'palletsprojects', products: ['flask'] },
  'rails': { vendor: 'rubyonrails', products: ['rails'] },
  'spring': { vendor: 'vmware', products: ['spring_framework'] },
  'laravel': { vendor: 'laravel', products: ['laravel'] },
  'openssl': { vendor: 'openssl', products: ['openssl'] },
  'openssh': { vendor: 'openbsd', products: ['openssh'] },
  'tomcat': { vendor: 'apache', products: ['tomcat'] },
  'iis': { vendor: 'microsoft', products: ['iis'] },
  'sharepoint': { vendor: 'microsoft', products: ['sharepoint'] },
  'exchange': { vendor: 'microsoft', products: ['exchange_server'] },
  'windows': { vendor: 'microsoft', products: ['windows'] },
  'linux': { vendor: 'linux', products: ['linux_kernel'] },
  'ubuntu': { vendor: 'canonical', products: ['ubuntu_linux'] },
  'debian': { vendor: 'debian', products: ['debian_linux'] },
  'centos': { vendor: 'centos', products: ['centos'] },
  'rhel': { vendor: 'redhat', products: ['enterprise_linux'] }
};

// Known vulnerable version ranges
const VULNERABLE_VERSIONS = {
  'log4j': [
    { cve: 'CVE-2021-44228', range: '<2.15.0', severity: 'critical', name: 'Log4Shell' },
    { cve: 'CVE-2021-45046', range: '<2.16.0', severity: 'critical', name: 'Log4Shell 2' },
    { cve: 'CVE-2021-45105', range: '<2.17.0', severity: 'high', name: 'DoS' }
  ],
  'apache': [
    { cve: 'CVE-2021-41773', range: '2.4.49', severity: 'critical', name: 'Path Traversal' },
    { cve: 'CVE-2021-42013', range: '2.4.50', severity: 'critical', name: 'Path Traversal' }
  ],
  'nginx': [
    { cve: 'CVE-2021-23017', range: '0.6.18-1.20.0', severity: 'high', name: 'DNS Resolver' },
    { cve: 'CVE-2022-41741', range: '1.23.0', severity: 'high', name: 'Memory Corruption' }
  ],
  'php': [
    { cve: 'CVE-2019-11043', range: '7.1-7.3', severity: 'critical', name: 'RCE' },
    { cve: 'CVE-2020-7069', range: '7.2-7.4', severity: 'high', name: 'Information Disclosure' }
  ],
  'mysql': [
    { cve: 'CVE-2021-2307', range: '8.0.24', severity: 'high', name: 'Privilege Escalation' }
  ],
  'postgresql': [
    { cve: 'CVE-2021-3393', range: '11-13', severity: 'high', name: 'Information Disclosure' }
  ],
  'redis': [
    { cve: 'CVE-2021-41099', range: '6.2-7.0', severity: 'high', name: 'Integer Overflow' }
  ],
  'wordpress': [
    { cve: 'CVE-2021-29447', range: '<5.7.1', severity: 'high', name: 'XXE' },
    { cve: 'CVE-2022-21661', range: '<5.8.3', severity: 'high', name: 'SQL Injection' }
  ],
  'drupal': [
    { cve: 'CVE-2018-7600', range: '7.57, 8.3.8, 8.4.5, 8.5.0', severity: 'critical', name: 'Drupalgeddon2' },
    { cve: 'CVE-2019-6340', range: '8.5.x, 8.6.x', severity: 'critical', name: 'RCE' }
  ],
  'jenkins': [
    { cve: 'CVE-2024-23897', range: '<2.426.2', severity: 'critical', name: 'Arbitrary File Read' }
  ],
  'openssl': [
    { cve: 'CVE-2021-3449', range: '1.1.1-1.1.1j', severity: 'high', name: 'DoS' },
    { cve: 'CVE-2021-3711', range: '1.1.1-1.1.1k', severity: 'high', name: 'SM2 Decryption' }
  ],
  'openssh': [
    { cve: 'CVE-2021-41617', range: '8.0-8.8', severity: 'high', name: 'Privilege Escalation' }
  ],
  'spring': [
    { cve: 'CVE-2022-22965', range: '5.3.0-5.3.17, 5.2.0-5.2.19', severity: 'critical', name: 'Spring4Shell' },
    { cve: 'CVE-2022-22963', range: '3.1.6, 3.2.2', severity: 'critical', name: 'SpEL RCE' }
  ],
  'struts': [
    { cve: 'CVE-2017-5638', range: '2.3.5-2.3.31, 2.5-2.5.10', severity: 'critical', name: 'Equifax' },
    { cve: 'CVE-2018-11776', range: '2.3-2.3.34, 2.5-2.5.16', severity: 'critical', name: 'RCE' }
  ],
  'tomcat': [
    { cve: 'CVE-2020-1938', range: '9.0.0-9.0.30, 8.5.0-8.5.50, 7.0.0-7.0.99', severity: 'critical', name: 'Ghostcat' }
  ],
  'django': [
    { cve: 'CVE-2022-28346', range: '2.2-4.0.3', severity: 'high', name: 'SQL Injection' },
    { cve: 'CVE-2022-28347', range: '2.2-4.0.3', severity: 'high', name: 'SQL Injection' }
  ],
  'rails': [
    { cve: 'CVE-2022-21831', range: '6.0-7.0', severity: 'critical', name: 'RCE' }
  ],
  'laravel': [
    { cve: 'CVE-2021-43617', range: '8.0-8.73.1', severity: 'high', name: 'SQL Injection' }
  ],
  'node.js': [
    { cve: 'CVE-2021-22940', range: '12.x, 14.x, 16.x', severity: 'high', name: 'Use-after-free' }
  ],
  'express': [
    { cve: 'CVE-2022-24999', range: '<4.17.3', severity: 'high', name: 'qs Prototype Pollution' }
  ]
};

export class ThreatIntelEngine {
  constructor(opts = {}) {
    this.opts = { cacheEnabled: true, cacheTTL: CACHE_TTL, ...opts };
    this.cache = new Map();
    this.ensureCacheDir();
  }

  async ensureCacheDir() {
    try {
      await fs.mkdir(CACHE_DIR, { recursive: true });
    } catch (e) {}
  }

  getCacheKey(key) {
    return crypto.createHash('md5').update(key).digest('hex');
  }

  async getFromCache(key) {
    if (!this.opts.cacheEnabled) return null;
    
    const cacheKey = this.getCacheKey(key);
    const cachePath = path.join(CACHE_DIR, `${cacheKey}.json`);
    
    try {
      const data = await fs.readFile(cachePath, 'utf8');
      const cached = JSON.parse(data);
      
      if (Date.now() - cached.timestamp > this.opts.cacheTTL) {
        await fs.unlink(cachePath);
        return null;
      }
      
      return cached.data;
    } catch (e) {
      return null;
    }
  }

  async saveToCache(key, data) {
    if (!this.opts.cacheEnabled) return;
    
    const cacheKey = this.getCacheKey(key);
    const cachePath = path.join(CACHE_DIR, `${cacheKey}.json`);
    
    try {
      await fs.writeFile(cachePath, JSON.stringify({
        timestamp: Date.now(),
        data
      }));
    } catch (e) {}
  }

  async lookupCVE(keyword, version = null) {
    const cacheKey = `cve:${keyword}:${version || 'latest'}`;
    const cached = await this.getFromCache(cacheKey);
    if (cached) return cached;

    const cves = [];
    
    // 1. Check known vulnerable versions first
    const known = this.checkKnownVulnerabilities(keyword, version);
    if (known.length) cves.push(...known);
    
    // 2. Query NVD API
    try {
      const nvdResults = await this.queryNVD(keyword, version);
      cves.push(...nvdResults);
    } catch (e) {
      console.log(`[ThreatIntel] NVD query failed: ${e.message}`);
    }
    
    // 3. Check ExploitDB
    try {
      const exploitResults = await this.queryExploitDB(keyword);
      for (const cve of cves) {
        const exploit = exploitResults.find(e => cve.cve_id && e.cve && e.cve.includes(cve.cve_id));
        if (exploit) {
          cve.exploitAvailable = true;
          cve.exploitDBId = exploit.id;
        }
      }
    } catch (e) {}
    
    // Deduplicate by CVE ID
    const unique = new Map();
    for (const cve of cves) {
      if (!unique.has(cve.cve_id) || cve.confidence > unique.get(cve.cve_id).confidence) {
        unique.set(cve.cve_id, cve);
      }
    }
    
    const result = [...unique.values()].sort((a, b) => (b.cvssScore || 0) - (a.cvssScore || 0));
    await this.saveToCache(cacheKey, result);
    
    return result;
  }

  checkKnownVulnerabilities(tech, version) {
    const cves = [];
    const techLower = tech.toLowerCase();
    
    for (const [name, vulns] of Object.entries(VULNERABLE_VERSIONS)) {
      if (techLower.includes(name)) {
        for (const vuln of vulns) {
          // Check if version is in range
          if (!version || this.isVersionInRange(version, vuln.range)) {
            cves.push({
              cve_id: vuln.cve,
              severity: vuln.severity,
              cvssScore: vuln.severity === 'critical' ? 9.8 : vuln.severity === 'high' ? 8.1 : 6.5,
              description: `${vuln.name} vulnerability in ${tech} ${version || 'unknown'}`,
              technology: tech,
              version: version,
              vulnerableRange: vuln.range,
              confidence: 95,
              source: 'known_vulnerabilities'
            });
          }
        }
      }
    }
    
    return cves;
  }

  isVersionInRange(version, range) {
    // Simple version range check
    if (range.startsWith('<')) {
      const max = range.substring(1);
      return this.compareVersions(version, max) < 0;
    }
    if (range.includes('-')) {
      const [min, max] = range.split('-');
      return this.compareVersions(version, min) >= 0 && this.compareVersions(version, max) <= 0;
    }
    return version === range;
  }

  compareVersions(v1, v2) {
    const parts1 = v1.split('.').map(Number);
    const parts2 = v2.split('.').map(Number);
    
    for (let i = 0; i < Math.max(parts1.length, parts2.length); i++) {
      const p1 = parts1[i] || 0;
      const p2 = parts2[i] || 0;
      if (p1 < p2) return -1;
      if (p1 > p2) return 1;
    }
    return 0;
  }

  async queryNVD(keyword, version) {
    const cves = [];
    
    try {
      // Build CPE query if possible
      let cpeName = null;
      for (const [tech, mapping] of Object.entries(CPE_MAPPINGS)) {
        if (keyword.toLowerCase().includes(tech)) {
          cpeName = `cpe:2.3:a:${mapping.vendor}:${mapping.products[0]}:${version || '*'}:*:*:*:*:*:*:*`;
          break;
        }
      }
      
      // Query by keyword
      const url = `${NVD_API_BASE}?keywordSearch=${encodeURIComponent(keyword)}&resultsPerPage=20`;
      const r = await axios.get(url, { timeout: 30000 });
      
      if (r.data?.vulnerabilities) {
        for (const v of r.data.vulnerabilities) {
          const cve = v.cve;
          const desc = cve.descriptions?.find(d => d.lang === 'en')?.value || '';
          const metrics = cve.metrics?.cvssMetricV31?.[0]?.cvssData || cve.metrics?.cvssMetricV30?.[0]?.cvssData;
          const score = metrics?.baseScore || 0;
          const severity = score >= 9 ? 'critical' : score >= 7 ? 'high' : score >= 4 ? 'medium' : 'low';
          
          cves.push({
            cve_id: cve.id,
            severity,
            cvssScore: score,
            cvssVector: metrics?.vectorString || '',
            description: desc.substring(0, 500),
            published: cve.published,
            modified: cve.lastModified,
            references: cve.references?.map(r => r.url) || [],
            technology: keyword,
            version: version,
            confidence: 90,
            source: 'nvd'
          });
        }
      }
    } catch (e) {
      throw new Error(`NVD API error: ${e.message}`);
    }
    
    return cves;
  }

  async queryExploitDB(keyword) {
    // This would require scraping or API access
    // For now, return empty array
    return [];
  }

  async getEPSS(cveId) {
    // EPSS (Exploit Prediction Scoring System)
    // Returns probability of exploitation in the wild
    try {
      const url = `https://api.first.org/data/v1/epss?cve=${cveId}`;
      const r = await axios.get(url, { timeout: 10000 });
      
      if (r.data?.data?.[0]) {
        return {
          cve: cveId,
          epssScore: parseFloat(r.data.data[0].epss),
          percentile: parseFloat(r.data.data[0].percentile),
          date: r.data.data[0].date
        };
      }
    } catch (e) {}
    
    return null;
  }

  async enrichWithThreatIntel(cves) {
    const enriched = [];
    
    for (const cve of cves) {
      const enrichedCve = { ...cve };
      
      // Get EPSS score
      const epss = await this.getEPSS(cve.cve_id);
      if (epss) {
        enrichedCve.epssScore = epss.epssScore;
        enrichedCve.epssPercentile = epss.percentile;
      }
      
      // Check for known exploits
      enrichedCve.exploitAvailable = await this.checkExploitAvailable(cve.cve_id);
      
      // Calculate risk score
      enrichedCve.riskScore = this.calculateRiskScore(enrichedCve);
      
      enriched.push(enrichedCve);
    }
    
    return enriched;
  }

  async checkExploitAvailable(cveId) {
    // Check various exploit databases
    const checks = [
      this.checkExploitDB(cveId),
      this.checkGitHubExploits(cveId),
      this.checkMetasploit(cveId)
    ];
    
    const results = await Promise.allSettled(checks);
    return results.some(r => r.status === 'fulfilled' && r.value);
  }

  async checkExploitDB(cveId) {
    try {
      const url = `https://www.exploit-db.com/search?cve=${cveId.replace('CVE-', '')}`;
      const r = await axios.get(url, { timeout: 10000, validateStatus: () => true });
      return r.status === 200 && r.data.includes('EDB-ID');
    } catch (e) {
      return false;
    }
  }

  async checkGitHubExploits(cveId) {
    try {
      const url = `https://api.github.com/search/repositories?q=${cveId}+exploit`;
      const r = await axios.get(url, { timeout: 10000, validateStatus: () => true });
      return r.status === 200 && r.data?.total_count > 0;
    } catch (e) {
      return false;
    }
  }

  async checkMetasploit(cveId) {
    try {
      const url = `https://www.rapid7.com/db/?q=${cveId}`;
      const r = await axios.get(url, { timeout: 10000, validateStatus: () => true });
      return r.status === 200 && r.data.includes('metasploit');
    } catch (e) {
      return false;
    }
  }

  calculateRiskScore(cve) {
    let score = cve.cvssScore || 5;
    
    // Increase score if exploit available
    if (cve.exploitAvailable) score += 1;
    
    // Increase score based on EPSS
    if (cve.epssScore > 0.5) score += 1;
    
    // Decrease score if old and no exploits
    const age = (Date.now() - new Date(cve.published || Date.now())) / (365 * 24 * 60 * 60 * 1000);
    if (age > 5 && !cve.exploitAvailable) score -= 1;
    
    return Math.min(10, Math.max(0, score));
  }

  async getRemediationAdvice(cve) {
    const advice = {
      immediate: [],
      shortTerm: [],
      longTerm: []
    };
    
    // Parse CVSS vector for attack vectors
    if (cve.cvssVector) {
      if (cve.cvssVector.includes('AV:N')) {
        advice.immediate.push('Block external access to vulnerable component');
      }
      if (cve.cvssVector.includes('AC:L')) {
        advice.immediate.push('Attack is easy to execute - prioritize patching');
      }
    }
    
    // Technology-specific advice
    const tech = cve.technology?.toLowerCase() || '';
    
    if (tech.includes('apache') || tech.includes('nginx')) {
      advice.shortTerm.push('Update web server to latest stable version');
      advice.shortTerm.push('Review and update server configuration');
    }
    
    if (tech.includes('php') || tech.includes('node') || tech.includes('python')) {
      advice.shortTerm.push('Update runtime to patched version');
      advice.shortTerm.push('Review application dependencies');
    }
    
    if (tech.includes('mysql') || tech.includes('postgres') || tech.includes('mongo')) {
      advice.shortTerm.push('Apply database security patches');
      advice.shortTerm.push('Review database access controls');
    }
    
    if (tech.includes('wordpress') || tech.includes('drupal') || tech.includes('joomla')) {
      advice.shortTerm.push('Update CMS core to latest version');
      advice.shortTerm.push('Update all plugins and themes');
    }
    
    advice.longTerm.push('Implement vulnerability management program');
    advice.longTerm.push('Set up automated security scanning');
    advice.longTerm.push('Establish patch management procedures');
    
    return advice;
  }
}

export default ThreatIntelEngine;
