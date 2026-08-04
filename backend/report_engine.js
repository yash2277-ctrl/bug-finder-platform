// report_engine.js — Intelligent Reporting & Remediation Engine
import fs from 'fs/promises';
import path from 'path';

// OWASP Top 10 2021 mapping
const OWASP_TOP10 = {
  'A01:2021': { name: 'Broken Access Control', cwe: [22, 23, 35, 59, 200, 201, 219, 264, 275, 276, 284, 285, 352, 359, 639, 651, 668, 706, 862, 863, 913, 922, 1275] },
  'A02:2021': { name: 'Cryptographic Failures', cwe: [261, 296, 310, 311, 312, 313, 314, 315, 316, 319, 321, 322, 323, 324, 325, 326, 327, 328, 329, 330, 331, 335, 336, 337, 338, 340, 347, 523, 720, 757, 759, 760, 780, 818, 916] },
  'A03:2021': { name: 'Injection', cwe: [20, 74, 75, 77, 78, 79, 80, 83, 87, 88, 89, 90, 91, 93, 94, 95, 96, 97, 98, 99, 113, 116, 117, 138, 184, 470, 471, 564, 610, 643, 644, 652, 917] },
  'A04:2021': { name: 'Insecure Design', cwe: [73, 183, 209, 213, 235, 256, 257, 266, 269, 280, 311, 312, 313, 316, 419, 430, 434, 444, 451, 489, 502, 522, 525, 539, 579, 598, 602, 607, 620, 641, 642, 647, 650, 668, 693, 776, 782, 807, 840, 841, 927, 1021, 1173, 1175, 1188] },
  'A05:2021': { name: 'Security Misconfiguration', cwe: [2, 11, 13, 15, 16, 52, 209, 215, 548, 611, 614, 756, 776] },
  'A06:2021': { name: 'Vulnerable and Outdated Components', cwe: [937, 1035, 1104] },
  'A07:2021': { name: 'Identification and Authentication Failures', cwe: [255, 259, 287, 288, 290, 294, 295, 297, 300, 302, 304, 306, 307, 346, 384, 521, 613, 620, 640, 798, 940, 1216] },
  'A08:2021': { name: 'Software and Data Integrity Failures', cwe: [345, 353, 426, 494, 502, 565, 784, 829, 830, 915] },
  'A09:2021': { name: 'Security Logging and Monitoring Failures', cwe: [117, 223, 532, 778, 1173, 1174, 1175, 1176, 1177, 1178, 1179, 1180, 1181, 1182, 1183, 1184, 1185, 1186, 1187, 1188, 1189, 1190, 1191, 1192, 1193, 1194, 1195] },
  'A10:2021': { name: 'Server-Side Request Forgery (SSRF)', cwe: [918] }
};

// CWE to vulnerability type mapping
const CWE_MAPPING = {
  89: { type: 'SQL Injection', owasp: 'A03:2021' },
  79: { type: 'XSS', owasp: 'A03:2021' },
  94: { type: 'Code Injection', owasp: 'A03:2021' },
  78: { type: 'OS Command Injection', owasp: 'A03:2021' },
  22: { type: 'Path Traversal', owasp: 'A01:2021' },
  918: { type: 'SSRF', owasp: 'A10:2021' },
  352: { type: 'CSRF', owasp: 'A01:2021' },
  287: { type: 'Authentication Bypass', owasp: 'A07:2021' },
  311: { type: 'Missing Encryption', owasp: 'A02:2021' },
  798: { type: 'Hardcoded Credentials', owasp: 'A07:2021' },
  200: { type: 'Information Disclosure', owasp: 'A01:2021' },
  502: { type: 'Deserialization', owasp: 'A08:2021' },
  918: { type: 'SSRF', owasp: 'A10:2021' },
  601: { type: 'Open Redirect', owasp: 'A01:2021' },
  942: { type: 'CORS Misconfiguration', owasp: 'A05:2021' }
};

// Risk matrix
const RISK_MATRIX = {
  critical: { min: 9.0, color: '#dc2626', label: 'Critical', action: 'Immediate' },
  high: { min: 7.0, color: '#ea580c', label: 'High', action: 'Within 7 days' },
  medium: { min: 4.0, color: '#ca8a04', label: 'Medium', action: 'Within 30 days' },
  low: { min: 0.1, color: '#16a34a', label: 'Low', action: 'Within 90 days' },
  info: { min: 0, color: '#6b7280', label: 'Info', action: 'Best practice' }
};

export class ReportEngine {
  constructor(opts = {}) {
    this.opts = { templateDir: './templates', outputDir: './reports', ...opts };
  }

  async generateReport(scanData, options = {}) {
    const report = {
      metadata: this.generateMetadata(scanData),
      executive: this.generateExecutiveSummary(scanData),
      findings: this.categorizeFindings(scanData.findings || []),
      technical: this.generateTechnicalDetails(scanData),
      remediation: this.generateRemediationPlan(scanData),
      compliance: this.mapCompliance(scanData.findings || []),
      statistics: this.calculateStatistics(scanData),
      timeline: scanData.timeline || [],
      raw: options.includeRaw ? scanData : undefined
    };

    return report;
  }

  generateMetadata(scanData) {
    return {
      title: `Security Assessment Report - ${scanData.target}`,
      generatedAt: new Date().toISOString(),
      scanId: scanData.scanId,
      target: scanData.target,
      scanDuration: scanData.duration,
      scannerVersion: '2.0.0',
      reportVersion: '1.0.0',
      classification: 'Confidential'
    };
  }

  generateExecutiveSummary(scanData) {
    const findings = scanData.findings || [];
    const critical = findings.filter(f => f.severity === 'critical').length;
    const high = findings.filter(f => f.severity === 'high').length;
    const medium = findings.filter(f => f.severity === 'medium').length;
    const low = findings.filter(f => f.severity === 'low').length;
    
    const totalRisk = this.calculateTotalRisk(findings);
    const riskRating = this.getRiskRating(totalRisk);
    
    return {
      overview: `This security assessment identified ${findings.length} vulnerabilities across ${scanData.target}.`,
      riskRating: riskRating.label,
      riskScore: totalRisk,
      riskColor: riskRating.color,
      keyFindings: [
        critical > 0 ? `${critical} critical vulnerabilities requiring immediate attention` : null,
        high > 0 ? `${high} high severity vulnerabilities` : null,
        medium > 0 ? `${medium} medium severity vulnerabilities` : null,
        findings.some(f => f.exploitAvailable) ? 'Exploits are publicly available for some vulnerabilities' : null,
        findings.some(f => f.cwe === 89) ? 'SQL Injection vulnerabilities present - immediate patching required' : null,
        findings.some(f => f.cwe === 78) ? 'Remote Code Execution possible - critical risk' : null
      ].filter(Boolean),
      recommendations: this.generateTopRecommendations(findings),
      metrics: { critical, high, medium, low, total: findings.length }
    };
  }

  categorizeFindings(findings) {
    const categories = {
      critical: [],
      high: [],
      medium: [],
      low: [],
      info: []
    };

    for (const finding of findings) {
      const enriched = this.enrichFinding(finding);
      const sev = enriched.severity || 'medium';
      categories[sev].push(enriched);
    }

    // Sort by CVSS score within each category
    for (const cat of Object.keys(categories)) {
      categories[cat].sort((a, b) => (b.cvssScore || 0) - (a.cvssScore || 0));
    }

    return categories;
  }

  enrichFinding(finding) {
    const enriched = { ...finding };
    
    // Map to OWASP Top 10
    if (finding.cwe && CWE_MAPPING[finding.cwe]) {
      enriched.owaspCategory = CWE_MAPPING[finding.cwe].owasp;
      enriched.owaspName = OWASP_TOP10[CWE_MAPPING[finding.cwe].owasp]?.name;
    }
    
    // Add risk matrix info
    const riskInfo = RISK_MATRIX[finding.severity] || RISK_MATRIX.medium;
    enriched.riskColor = riskInfo.color;
    enriched.timeToFix = riskInfo.action;
    
    // Calculate business impact
    enriched.businessImpact = this.calculateBusinessImpact(finding);
    
    // Add remediation complexity
    enriched.remediationComplexity = this.assessRemediationComplexity(finding);
    
    return enriched;
  }

  calculateBusinessImpact(finding) {
    const factors = [];
    let score = 5; // Base score
    
    if (finding.severity === 'critical') score += 3;
    if (finding.severity === 'high') score += 2;
    if (finding.exploitAvailable) { score += 2; factors.push('Public exploit available'); }
    if (finding.cwe === 89 || finding.cwe === 78) { score += 2; factors.push('Data breach possible'); }
    if (finding.cwe === 200) { score += 1; factors.push('Information disclosure'); }
    if (finding.cvssVector?.includes('AV:N')) { score += 1; factors.push('Internet accessible'); }
    
    const impact = score >= 9 ? 'Severe' : score >= 7 ? 'High' : score >= 5 ? 'Medium' : 'Low';
    
    return { score: Math.min(10, score), rating: impact, factors };
  }

  assessRemediationComplexity(finding) {
    const type = String(finding.type || '').toLowerCase();
    
    if (type.includes('header') || type.includes('config')) {
      return { level: 'Simple', effort: '1-2 hours', skills: 'System Administrator' };
    }
    if (type.includes('sql') || type.includes('xss') || type.includes('injection')) {
      return { level: 'Complex', effort: '1-3 days', skills: 'Developer + Security Engineer' };
    }
    if (type.includes('cve') || type.includes('version')) {
      return { level: 'Moderate', effort: '4-8 hours', skills: 'System Administrator' };
    }
    if (type.includes('rce') || type.includes('deserialization')) {
      return { level: 'Complex', effort: '3-7 days', skills: 'Senior Developer + Security Architect' };
    }
    
    return { level: 'Moderate', effort: '1-2 days', skills: 'Developer' };
  }

  generateTechnicalDetails(scanData) {
    const findings = scanData.findings || [];
    
    return {
      attackSurface: this.analyzeAttackSurface(scanData),
      vulnerabilityDetails: findings.map(f => ({
        id: f.id,
        title: f.title || f.type,
        severity: f.severity,
        cvssScore: f.cvssScore,
        cvssVector: f.cvssVector,
        description: f.description,
        evidence: f.evidence,
        affectedUrls: f.affectedUrls || [f.url],
        parameters: f.parameters,
        request: f.request,
        response: f.response?.substring(0, 2000),
        impact: f.impact,
        remediation: f.remediation,
        references: f.references,
        cwe: f.cwe,
        cve: f.cve_id,
        owasp: f.owaspCategory
      })),
      exploitability: this.assessExploitability(findings),
      attackChains: this.identifyAttackChains(findings)
    };
  }

  analyzeAttackSurface(scanData) {
    return {
      totalEndpoints: scanData.endpoints?.length || 0,
      totalParameters: scanData.parameters?.length || 0,
      technologies: scanData.techStack || [],
      exposedServices: scanData.ports?.filter(p => p.state === 'open').map(p => p.service) || [],
      authentication: this.assessAuthentication(scanData),
      inputVectors: this.identifyInputVectors(scanData)
    };
  }

  assessAuthentication(scanData) {
    const findings = scanData.findings || [];
    const authIssues = findings.filter(f => 
      f.cwe === 287 || f.cwe === 798 || String(f.type || '').toLowerCase().includes('auth')
    );
    
    return {
      hasAuthentication: !authIssues.some(f => f.type?.includes('Missing')),
      weaknesses: authIssues.map(f => f.type),
      recommendations: authIssues.length > 0 ? ['Implement multi-factor authentication', 'Review session management'] : []
    };
  }

  identifyInputVectors(scanData) {
    const vectors = [];
    const params = scanData.parameters || [];
    
    if (params.length > 0) vectors.push({ type: 'URL Parameters', count: params.length, risk: 'High' });
    if (scanData.forms?.length > 0) vectors.push({ type: 'Form Inputs', count: scanData.forms.length, risk: 'High' });
    if (scanData.headers?.length > 0) vectors.push({ type: 'HTTP Headers', count: scanData.headers.length, risk: 'Medium' });
    if (scanData.cookies?.length > 0) vectors.push({ type: 'Cookies', count: scanData.cookies.length, risk: 'Medium' });
    
    return vectors;
  }

  assessExploitability(findings) {
    let score = 0;
    const factors = [];
    
    const criticalExploits = findings.filter(f => f.severity === 'critical' && f.exploitAvailable);
    if (criticalExploits.length > 0) {
      score += 5;
      factors.push(`${criticalExploits.length} critical vulnerabilities with public exploits`);
    }
    
    const networkExploits = findings.filter(f => f.cvssVector?.includes('AV:N'));
    if (networkExploits.length > 0) {
      score += 3;
      factors.push('Vulnerabilities accessible from network');
    }
    
    const lowComplexity = findings.filter(f => f.cvssVector?.includes('AC:L'));
    if (lowComplexity.length > 0) {
      score += 2;
      factors.push('Low complexity attacks possible');
    }
    
    return {
      score: Math.min(10, score),
      rating: score >= 8 ? 'Critical' : score >= 6 ? 'High' : score >= 4 ? 'Medium' : 'Low',
      factors,
      timeToCompromise: score >= 8 ? 'Hours' : score >= 6 ? 'Days' : score >= 4 ? 'Weeks' : 'Months'
    };
  }

  identifyAttackChains(findings) {
    const chains = [];
    
    // Chain 1: Information Disclosure -> Authentication Bypass -> Data Access
    const infoDisclosure = findings.find(f => f.cwe === 200);
    const authBypass = findings.find(f => f.cwe === 287);
    const sqli = findings.find(f => f.cwe === 89);
    
    if (infoDisclosure && authBypass) {
      chains.push({
        name: 'Privilege Escalation Chain',
        steps: [
          'Gather system information from disclosure',
          'Bypass authentication using exposed credentials',
          'Access sensitive data or admin functions'
        ],
        risk: 'Critical',
        findings: [infoDisclosure.id, authBypass.id]
      });
    }
    
    // Chain 2: XSS -> Session Hijack -> Account Takeover
    const xss = findings.find(f => f.cwe === 79);
    const sessionIssues = findings.find(f => f.type?.includes('Session'));
    
    if (xss && sessionIssues) {
      chains.push({
        name: 'Account Takeover Chain',
        steps: [
          'Inject malicious JavaScript via XSS',
          'Steal session token from victim',
          'Impersonate user and perform actions'
        ],
        risk: 'High',
        findings: [xss.id, sessionIssues.id]
      });
    }
    
    // Chain 3: SQL Injection -> Data Exfiltration -> Ransom
    if (sqli) {
      chains.push({
        name: 'Data Breach Chain',
        steps: [
          'Extract database schema via SQLi',
          'Dump sensitive customer data',
          'Potential ransomware or data sale'
        ],
        risk: 'Critical',
        findings: [sqli.id]
      });
    }
    
    return chains;
  }

  generateRemediationPlan(scanData) {
    const findings = scanData.findings || [];
    
    // Group by remediation type
    const byType = {};
    for (const f of findings) {
      const type = f.remediationType || f.type || 'General';
      if (!byType[type]) byType[type] = [];
      byType[type].push(f);
    }
    
    // Prioritize
    const prioritized = Object.entries(byType)
      .sort((a, b) => this.getPriorityScore(b[1]) - this.getPriorityScore(a[1]));
    
    return {
      immediate: this.generateActionItems(findings.filter(f => f.severity === 'critical'), 'immediate'),
      shortTerm: this.generateActionItems(findings.filter(f => f.severity === 'high'), 'short-term'),
      longTerm: this.generateActionItems(findings.filter(f => ['medium', 'low'].includes(f.severity)), 'long-term'),
      byCategory: prioritized.map(([type, items]) => ({
        category: type,
        count: items.length,
        maxSeverity: items.reduce((m, f) => this.severityRank(f.severity) > m ? this.severityRank(f.severity) : m, 0),
        actions: this.getRemediationSteps(type, items)
      })),
      estimatedEffort: this.estimateEffort(findings)
    };
  }

  getPriorityScore(findings) {
    return findings.reduce((sum, f) => sum + (f.cvssScore || 5) * (f.exploitAvailable ? 2 : 1), 0);
  }

  severityRank(sev) {
    const ranks = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
    return ranks[sev] || 0;
  }

  generateActionItems(findings, timeframe) {
    return findings.map(f => ({
      id: f.id,
      title: f.title || f.type,
      severity: f.severity,
      action: f.remediation || 'Review and patch',
      owner: this.getOwner(f),
      dueDate: this.calculateDueDate(timeframe),
      verification: f.verificationSteps || 'Re-scan to confirm fix'
    }));
  }

  getOwner(finding) {
    const type = String(finding.type || '').toLowerCase();
    if (type.includes('header') || type.includes('config') || type.includes('ssl')) return 'Infrastructure Team';
    if (type.includes('cve') || type.includes('version')) return 'System Administrators';
    if (type.includes('sql') || type.includes('xss') || type.includes('injection')) return 'Development Team';
    return 'Security Team';
  }

  calculateDueDate(timeframe) {
    const now = new Date();
    if (timeframe === 'immediate') return new Date(now.setDate(now.getDate() + 1)).toISOString();
    if (timeframe === 'short-term') return new Date(now.setDate(now.getDate() + 7)).toISOString();
    return new Date(now.setDate(now.getDate() + 30)).toISOString();
  }

  getRemediationSteps(type, findings) {
    const steps = {
      'SQL Injection': [
        'Use parameterized queries/prepared statements',
        'Implement input validation and sanitization',
        'Apply principle of least privilege to database accounts',
        'Enable SQL injection detection in WAF'
      ],
      'XSS': [
        'Implement Content Security Policy (CSP)',
        'Encode all output based on context',
        'Use modern framework auto-escaping features',
        'Validate and sanitize all user input'
      ],
      'RCE': [
        'Disable dangerous functions (eval, system, exec)',
        'Implement strict input validation',
        'Use allowlist approach for command execution',
        'Apply sandboxing/containerization'
      ],
      'LFI/Path Traversal': [
        'Validate and canonicalize file paths',
        'Use allowlist for accessible files',
        'Disable directory traversal in web server config',
        'Implement chroot jail'
      ],
      'SSRF': [
        'Validate and sanitize URLs',
        'Implement URL allowlist',
        'Disable unnecessary URL schemas',
        'Use network segmentation'
      ],
      'Information Disclosure': [
        'Remove debug information from production',
        'Implement custom error pages',
        'Review logging configuration',
        'Apply security headers'
      ],
      'Missing Headers': [
        'Add HSTS header for HTTPS sites',
        'Implement Content-Security-Policy',
        'Add X-Frame-Options header',
        'Configure X-Content-Type-Options'
      ],
      'CVE': [
        'Update to latest patched version',
        'Apply vendor security patches',
        'Implement virtual patching via WAF',
        'Consider temporary workarounds'
      ]
    };
    
    return steps[type] || ['Review security documentation', 'Apply security patches', 'Implement security controls'];
  }

  estimateEffort(findings) {
    const hours = findings.reduce((sum, f) => {
      const complexity = this.assessRemediationComplexity(f);
      const hours = complexity.effort.includes('hour') ? 
        parseInt(complexity.effort) : 
        parseInt(complexity.effort) * 8;
      return sum + (isNaN(hours) ? 8 : hours);
    }, 0);
    
    return {
      totalHours: hours,
      totalDays: Math.ceil(hours / 8),
      developers: Math.ceil(findings.filter(f => f.type?.includes('injection') || f.type?.includes('XSS')).length / 5),
      administrators: Math.ceil(findings.filter(f => f.type?.includes('header') || f.type?.includes('CVE')).length / 10)
    };
  }

  mapCompliance(findings) {
    const mappings = {
      'PCI-DSS': this.mapPCI(findings),
      'OWASP-Top10': this.mapOWASP(findings),
      'NIST-800-53': this.mapNIST(findings),
      'ISO-27001': this.mapISO(findings),
      'GDPR': this.mapGDPR(findings),
      'HIPAA': this.mapHIPAA(findings)
    };
    
    return mappings;
  }

  mapPCI(findings) {
    const relevant = findings.filter(f => 
      f.cwe === 89 || f.cwe === 79 || f.cwe === 200 || f.cwe === 311 || f.cwe === 798
    );
    
    return {
      applicable: relevant.length > 0,
      requirements: [
        { id: '6.5.1', name: 'Injection Flaws', findings: relevant.filter(f => f.cwe === 89).map(f => f.id) },
        { id: '6.5.7', name: 'Cross-Site Scripting', findings: relevant.filter(f => f.cwe === 79).map(f => f.id) },
        { id: '6.5.10', name: 'Broken Authentication', findings: relevant.filter(f => f.cwe === 287).map(f => f.id) },
        { id: '2.3', name: 'Encrypt Transmission', findings: relevant.filter(f => f.cwe === 311).map(f => f.id) },
        { id: '8.2.1', name: 'Strong Cryptography', findings: relevant.filter(f => f.cwe === 798).map(f => f.id) }
      ],
      complianceScore: Math.max(0, 100 - (relevant.length * 10))
    };
  }

  mapOWASP(findings) {
    const categories = {};
    
    for (const f of findings) {
      if (f.owaspCategory) {
        if (!categories[f.owaspCategory]) categories[f.owaspCategory] = [];
        categories[f.owaspCategory].push(f.id);
      }
    }
    
    return {
      categories: Object.entries(categories).map(([code, ids]) => ({
        code,
        name: OWASP_TOP10[code]?.name,
        count: ids.length,
        findings: ids
      })),
      topRisks: Object.entries(categories)
        .sort((a, b) => b[1].length - a[1].length)
        .slice(0, 3)
        .map(([code]) => ({ code, name: OWASP_TOP10[code]?.name }))
    };
  }

  mapNIST(findings) {
    return {
      controls: [
        { id: 'SI-10', name: 'Information Input Validation', findings: findings.filter(f => f.cwe === 89 || f.cwe === 79).map(f => f.id) },
        { id: 'SC-13', name: 'Cryptographic Protection', findings: findings.filter(f => f.cwe === 311).map(f => f.id) },
        { id: 'IA-5', name: 'Authenticator Management', findings: findings.filter(f => f.cwe === 798).map(f => f.id) }
      ]
    };
  }

  mapISO(findings) {
    return {
      controls: [
        { id: 'A.14.2.2', name: 'System Change Control', findings: findings.filter(f => f.type?.includes('CVE')).map(f => f.id) },
        { id: 'A.12.3.1', name: 'Information Backup', findings: findings.filter(f => f.cwe === 200).map(f => f.id) },
        { id: 'A.9.4.3', name: 'Password Management', findings: findings.filter(f => f.cwe === 798).map(f => f.id) }
      ]
    };
  }

  mapGDPR(findings) {
    const relevant = findings.filter(f => 
      f.cwe === 200 || f.cwe === 311 || f.cwe === 798 || f.type?.includes('SQL')
    );
    
    return {
      applicable: relevant.length > 0,
      articles: [
        { id: '32', name: 'Security of Processing', findings: relevant.map(f => f.id) },
        { id: '33', name: 'Breach Notification', findings: relevant.filter(f => f.cwe === 200).map(f => f.id) }
      ],
      riskLevel: relevant.some(f => f.severity === 'critical') ? 'High' : 'Medium'
    };
  }

  mapHIPAA(findings) {
    return {
      safeguards: [
        { id: '164.312(a)(1)', name: 'Access Control', findings: findings.filter(f => f.cwe === 287).map(f => f.id) },
        { id: '164.312(a)(2)(iv)', name: 'Encryption', findings: findings.filter(f => f.cwe === 311).map(f => f.id) },
        { id: '164.312(b)', name: 'Audit Controls', findings: findings.filter(f => f.cwe === 200).map(f => f.id) }
      ]
    };
  }

  calculateStatistics(scanData) {
    const findings = scanData.findings || [];
    
    return {
      total: findings.length,
      bySeverity: {
        critical: findings.filter(f => f.severity === 'critical').length,
        high: findings.filter(f => f.severity === 'high').length,
        medium: findings.filter(f => f.severity === 'medium').length,
        low: findings.filter(f => f.severity === 'low').length,
        info: findings.filter(f => f.severity === 'info').length
      },
      byType: this.groupBy(findings, 'type'),
      byTechnology: this.groupBy(findings, 'technology'),
      exploitable: findings.filter(f => f.exploitAvailable).length,
      withRemediation: findings.filter(f => f.remediation).length,
      averageCvss: findings.reduce((sum, f) => sum + (f.cvssScore || 0), 0) / (findings.length || 1),
      trend: scanData.previousScan ? this.calculateTrend(findings, scanData.previousScan) : null
    };
  }

  groupBy(array, key) {
    const groups = {};
    for (const item of array) {
      const val = item[key] || 'Unknown';
      groups[val] = (groups[val] || 0) + 1;
    }
    return groups;
  }

  calculateTrend(current, previous) {
    return {
      newFindings: current.length - previous.length,
      resolved: previous.filter(p => !current.find(c => c.id === p.id)).length,
      trend: current.length > previous.length ? 'Worsening' : current.length < previous.length ? 'Improving' : 'Stable'
    };
  }

  calculateTotalRisk(findings) {
    if (!findings.length) return 0;
    const weights = { critical: 10, high: 7, medium: 4, low: 1, info: 0 };
    const total = findings.reduce((sum, f) => sum + (weights[f.severity] || 0), 0);
    return Math.min(100, total * 2);
  }

  getRiskRating(score) {
    if (score >= 80) return RISK_MATRIX.critical;
    if (score >= 60) return RISK_MATRIX.high;
    if (score >= 40) return RISK_MATRIX.medium;
    if (score >= 20) return RISK_MATRIX.low;
    return RISK_MATRIX.info;
  }

  generateTopRecommendations(findings) {
    const recs = [];
    
    if (findings.some(f => f.cwe === 89)) {
      recs.push('Immediately review and fix all SQL injection vulnerabilities');
    }
    if (findings.some(f => f.cwe === 78)) {
      recs.push('Disable dangerous functions and implement input validation');
    }
    if (findings.some(f => f.cwe === 79)) {
      recs.push('Implement Content Security Policy and output encoding');
    }
    if (findings.some(f => f.cwe === 200)) {
      recs.push('Remove debug information and implement proper error handling');
    }
    if (findings.some(f => f.cwe === 311)) {
      recs.push('Enable TLS 1.2+ and implement HSTS');
    }
    if (findings.some(f => f.exploitAvailable)) {
      recs.push('Prioritize patching vulnerabilities with public exploits');
    }
    
    return recs;
  }

  async exportToPDF(report, filename) {
    // This would use a PDF library like puppeteer or pdfkit
    // For now, return a placeholder
    return { format: 'PDF', filename, pages: Math.ceil(JSON.stringify(report).length / 3000) };
  }

  async exportToHTML(report, filename) {
    const html = this.generateHTML(report);
    await fs.writeFile(filename, html);
    return { format: 'HTML', filename, size: html.length };
  }

  generateHTML(report) {
    // Simple HTML generation
    return `<!DOCTYPE html>
<html>
<head>
  <title>${report.metadata.title}</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 40px; }
    .critical { color: #dc2626; }
    .high { color: #ea580c; }
    .medium { color: #ca8a04; }
    .low { color: #16a34a; }
    table { border-collapse: collapse; width: 100%; }
    th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
    th { background-color: #f2f2f2; }
  </style>
</head>
<body>
  <h1>${report.metadata.title}</h1>
  <p>Generated: ${report.metadata.generatedAt}</p>
  <p>Target: ${report.metadata.target}</p>
  
  <h2>Executive Summary</h2>
  <p>Risk Rating: <span class="${String(report.executive.riskRating || 'low').toLowerCase()}">${report.executive.riskRating}</span></p>
  <p>Risk Score: ${report.executive.riskScore}/100</p>
  
  <h2>Findings Summary</h2>
  <table>
    <tr><th>Severity</th><th>Count</th></tr>
    <tr class="critical"><td>Critical</td><td>${report.statistics.bySeverity.critical}</td></tr>
    <tr class="high"><td>High</td><td>${report.statistics.bySeverity.high}</td></tr>
    <tr class="medium"><td>Medium</td><td>${report.statistics.bySeverity.medium}</td></tr>
    <tr class="low"><td>Low</td><td>${report.statistics.bySeverity.low}</td></tr>
  </table>
</body>
</html>`;
  }
}

export default ReportEngine;
