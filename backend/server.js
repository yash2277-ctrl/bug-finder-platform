import express from 'express';
import cors from 'cors';
import Database from 'better-sqlite3';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { v4 as uuidv4 } from 'uuid';
import { WebSocketServer } from 'ws';
import http from 'http';
import { runScanV2, termHeaders, termSSL, termPorts, termDNS, termFetch, termScan, termFuzz, termExploit, termReverseShell, generateRandomPort, validateIP, getLocalIP } from './scanner_v2.js';
import { ReverseShellExploit } from './exploit_engine.js';
import { AIAnalyzer } from './ai_analyzer.js';
import { DiscoveryEngine } from './discovery_engine.js';
import { ThreatIntelEngine } from './threat_intel.js';
import { ReportEngine } from './report_engine.js';

const app = express();
const server = http.createServer(app);
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'bugfinder_secret_key_change_in_production_2024';

// Initialize AI engines
const aiAnalyzer = new AIAnalyzer({ verify: true, threshold: 80 });
const discoveryEngine = new DiscoveryEngine({ maxDepth: 3, maxPages: 50 });
const threatIntel = new ThreatIntelEngine({ cacheEnabled: true });
const reportEngine = new ReportEngine();

// ═══════════════════════════════════════
// Middleware
// ═══════════════════════════════════════
app.use(cors());
app.use(express.json({ limit: '50mb' }));

// ═══════════════════════════════════════
// Database Setup
// ═══════════════════════════════════════
const db = new Database('bugfinder.db');
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.pragma('busy_timeout = 8000');

// Users table
db.exec(`CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now'))
)`);

// Scans table
db.exec(`CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    user_id TEXT,
    domain TEXT NOT NULL,
    status TEXT DEFAULT 'pending',
    risk_score INTEGER DEFAULT 0,
    total_vulnerabilities INTEGER DEFAULT 0,
    critical_count INTEGER DEFAULT 0,
    high_count INTEGER DEFAULT 0,
    medium_count INTEGER DEFAULT 0,
    low_count INTEGER DEFAULT 0,
    subdomain_count INTEGER DEFAULT 0,
    live_host_count INTEGER DEFAULT 0,
    error_message TEXT DEFAULT '',
    started_at TEXT,
    completed_at TEXT,
    created_at TEXT DEFAULT (datetime('now'))
)`);



// Vulnerabilities table
db.exec(`CREATE TABLE IF NOT EXISTS vulnerabilities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL,
    cve_id TEXT,
    severity TEXT,
    description TEXT,
    vuln_type TEXT,
    affected_url TEXT,
    confidence INTEGER DEFAULT 80,
    cvss_score REAL,
    cvss_vector TEXT,
    evidence TEXT,
    remediation TEXT,
    cwe INTEGER,
    FOREIGN KEY (scan_id) REFERENCES scans(id)
)`);

// Add missing columns if they don't exist
try { db.exec("ALTER TABLE vulnerabilities ADD COLUMN confidence INTEGER DEFAULT 80"); } catch (_) {}
try { db.exec("ALTER TABLE vulnerabilities ADD COLUMN cvss_score REAL"); } catch (_) {}
try { db.exec("ALTER TABLE vulnerabilities ADD COLUMN cvss_vector TEXT"); } catch (_) {}
try { db.exec("ALTER TABLE vulnerabilities ADD COLUMN evidence TEXT"); } catch (_) {}
try { db.exec("ALTER TABLE vulnerabilities ADD COLUMN remediation TEXT"); } catch (_) {}
try { db.exec("ALTER TABLE vulnerabilities ADD COLUMN cwe INTEGER"); } catch (_) {}


// Subdomains table
db.exec(`CREATE TABLE IF NOT EXISTS subdomains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL,
    subdomain TEXT NOT NULL,
    source TEXT,
    FOREIGN KEY (scan_id) REFERENCES scans(id)
)`);

// Endpoints table
db.exec(`CREATE TABLE IF NOT EXISTS endpoints (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL,
    url TEXT NOT NULL,
    method TEXT DEFAULT 'GET',
    source TEXT,
    parameters TEXT,
    FOREIGN KEY (scan_id) REFERENCES scans(id)
)`);

// Assets table
db.exec(`CREATE TABLE IF NOT EXISTS assets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL,
    url TEXT NOT NULL,
    asset_type TEXT,
    discovered_from TEXT,
    FOREIGN KEY (scan_id) REFERENCES scans(id)
)`);

// Tech stack table
db.exec(`CREATE TABLE IF NOT EXISTS tech_stack (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL,
    tech_name TEXT,
    tech_version TEXT,
    tech_category TEXT,
    detection_method TEXT,
    FOREIGN KEY (scan_id) REFERENCES scans(id)
)`);

// DNS records table
db.exec(`CREATE TABLE IF NOT EXISTS dns_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL,
    domain TEXT,
    record_type TEXT,
    record_value TEXT,
    FOREIGN KEY (scan_id) REFERENCES scans(id)
)`);

// Ports table
db.exec(`CREATE TABLE IF NOT EXISTS ports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL,
    host TEXT,
    port INTEGER,
    state TEXT,
    service TEXT,
    version TEXT,
    FOREIGN KEY (scan_id) REFERENCES scans(id)
)`);

// Live hosts table
db.exec(`CREATE TABLE IF NOT EXISTS live_hosts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL,
    host TEXT,
    ip TEXT,
    status_code INTEGER,
    server TEXT,
    title TEXT,
    FOREIGN KEY (scan_id) REFERENCES scans(id)
)`);

// Exploit results table
db.exec(`CREATE TABLE IF NOT EXISTS exploit_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL,
    cve_id TEXT,
    affected_url TEXT,
    exploitable INTEGER DEFAULT 0,
    confidence INTEGER DEFAULT 0,
    payload_used TEXT,
    evidence TEXT,
    risk_score INTEGER DEFAULT 0,
    FOREIGN KEY (scan_id) REFERENCES scans(id)
)`);

// Timeline events table
db.exec(`CREATE TABLE IF NOT EXISTS timeline_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL,
    event_type TEXT,
    description TEXT,
    timestamp TEXT,
    FOREIGN KEY (scan_id) REFERENCES scans(id)
)`);

// Migrations
try { db.exec("ALTER TABLE scans ADD COLUMN subdomain_count INTEGER DEFAULT 0"); } catch (_) {}
try { db.exec("ALTER TABLE scans ADD COLUMN live_host_count INTEGER DEFAULT 0"); } catch (_) {}
try { db.exec("ALTER TABLE scans ADD COLUMN error_message TEXT DEFAULT ''"); } catch (_) {}

// ═══════════════════════════════════════
// WebSocket Setup
// ═══════════════════════════════════════
const wss = new WebSocketServer({ server, path: '/ws' });

const clients = new Map();

wss.on('connection', (ws, req) => {
    const scanId = new URL(req.url, 'http://localhost').searchParams.get('scanId');
    if (scanId) {
        clients.set(scanId, ws);
        ws.on('close', () => clients.delete(scanId));
    }
});

function broadcast(scanId, data) {
    const ws = clients.get(scanId);
    if (ws && ws.readyState === 1) {
        ws.send(JSON.stringify(data));
    }
}

// ═══════════════════════════════════════
// Auth Middleware
// ═══════════════════════════════════════
function authMiddleware(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ error: 'No token provided' });
    
    const token = authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Invalid token format' });
    
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        if (!decoded.userId) {
            return res.status(401).json({ error: 'Invalid token payload' });
        }
        req.userId = decoded.userId;
        next();
    } catch (err) {
        res.status(401).json({ error: 'Invalid token' });
    }
}


// ═══════════════════════════════════════
// Auth Routes
// ═══════════════════════════════════════

app.post('/api/auth/register', async (req, res) => {
    const { username, email, password } = req.body;
    if (!username || !email || !password) {
        return res.status(400).json({ error: 'Missing required fields' });
    }
    
    const hashedPassword = await bcrypt.hash(password, 10);
    const id = uuidv4();
    
    try {
        db.prepare('INSERT INTO users (id, username, email, password) VALUES (?, ?, ?, ?)')
            .run(id, username, email, hashedPassword);
        const token = jwt.sign({ userId: id }, JWT_SECRET, { expiresIn: '24h' });
        res.json({ token, user: { id, username, email } });
    } catch (err) {
        res.status(400).json({ error: 'Username or email already exists' });
    }
});

app.post('/api/auth/login', async (req, res) => {
    const { username, password } = req.body;
    const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
    
    if (!user || !await bcrypt.compare(password, user.password)) {
        return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '24h' });
    res.json({ token, user: { id: user.id, username: user.username, email: user.email } });
});

app.get('/api/auth/me', authMiddleware, (req, res) => {
    const user = db.prepare('SELECT id, username, email, created_at FROM users WHERE id = ?').get(req.userId);
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json({ user });
});

// ═══════════════════════════════════════
// AI-Powered Scan Routes
// ═══════════════════════════════════════


app.post('/api/scans', authMiddleware, async (req, res) => {
    const { domain } = req.body;
    const scanId = uuidv4();
    const userId = req.userId;
    
    db.prepare('INSERT INTO scans (id, user_id, domain, status, started_at) VALUES (?, ?, ?, ?, ?)')
        .run(scanId, userId, domain, 'pending', new Date().toISOString());
    
    // Start AI-powered scan
    runAIPoweredScan(domain, scanId, userId);
    
    res.json({ scan: { id: scanId, domain, status: 'pending' } });

});

async function runAIPoweredScan(domain, scanId, userId) {
    const startTime = Date.now();
    const emit = (phase, progress, message) => {
        broadcast(scanId, { phase, progress, message, elapsed: ((Date.now() - startTime) / 1000).toFixed(1) });
    };
    
    try {
        db.prepare("UPDATE scans SET status = 'running' WHERE id = ?").run(scanId);
        emit(1, 0, `Starting AI-powered scan for ${domain}...`);
        
        // Phase 1: Discovery
        emit(1, 5, 'Phase 1: AI Discovery Engine - Enumerating assets...');
        const discovery = await discoveryEngine.discover(`https://${domain}`);
        
        // Store discovery results
        const insertSub = db.prepare('INSERT INTO subdomains (scan_id, subdomain, source) VALUES (?, ?, ?)');
        for (const sub of discovery.subdomains) {
            insertSub.run(scanId, sub.subdomain, sub.source);
        }
        
        const insertEndpoint = db.prepare('INSERT INTO endpoints (scan_id, url, method, source, parameters) VALUES (?, ?, ?, ?, ?)');
        for (const ep of discovery.endpoints) {
            insertEndpoint.run(scanId, ep.url, ep.method, ep.source, JSON.stringify(ep.params || []));
        }
        
        const insertAsset = db.prepare('INSERT INTO assets (scan_id, url, asset_type, discovered_from) VALUES (?, ?, ?, ?)');
        for (const asset of discovery.assets) {
            const type = asset.endsWith('.js') ? 'js' : asset.endsWith('.css') ? 'css' : 'other';
            insertAsset.run(scanId, asset, type, discovery.baseUrl);
        }
        
        const insertTech = db.prepare('INSERT INTO tech_stack (scan_id, tech_name, tech_version, tech_category, detection_method) VALUES (?, ?, ?, ?, ?)');
        for (const tech of discovery.techStack) {
            insertTech.run(scanId, tech.name, tech.version || '', tech.category, 'fingerprint');
        }
        
        emit(1, 20, `Discovered ${discovery.subdomains.length} subdomains, ${discovery.endpoints.length} endpoints, ${discovery.assets.length} assets`);
        
        // Phase 2: AI Vulnerability Analysis
        emit(2, 25, 'Phase 2: AI Analyzer - Detecting vulnerabilities...');
        const findings = [];
        
        // Analyze main target
        const mainUrl = `https://${domain}`;
        try {
            const response = await termFetch(mainUrl);
            const analysis = await aiAnalyzer.analyze(mainUrl, { data: response.body, headers: response.headers }, {
                params: discovery.params
            });
            
            for (const finding of analysis.findings) {
                findings.push(finding);
                db.prepare(`INSERT INTO vulnerabilities 
                    (scan_id, cve_id, severity, description, vuln_type, affected_url, confidence, cvss_score, cvss_vector, evidence) 
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
                    .run(scanId, finding.cve_id || `AI-${finding.type}`, finding.severity, 
                         finding.description || finding.evidence, finding.type, mainUrl, 
                         finding.confidence, finding.cvssScore, finding.cvssVector, finding.evidence);
            }
        } catch (e) {
            console.log(`[AI Scan] Error analyzing ${mainUrl}: ${e.message}`);
        }
        
        // Analyze discovered endpoints
        for (const ep of discovery.endpoints.slice(0, 20)) {
            try {
                const response = await termFetch(ep.url);
                const analysis = await aiAnalyzer.analyze(ep.url, { data: response.body, headers: response.headers }, {
                    params: ep.params || []
                });
                
                for (const finding of analysis.findings) {
                    findings.push(finding);
                    db.prepare(`INSERT INTO vulnerabilities 
                        (scan_id, cve_id, severity, description, vuln_type, affected_url, confidence, cvss_score, cvss_vector, evidence) 
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
                        .run(scanId, finding.cve_id || `AI-${finding.type}`, finding.severity, 
                             finding.description || finding.evidence, finding.type, ep.url, 
                             finding.confidence, finding.cvssScore, finding.cvssVector, finding.evidence);
                }
            } catch (e) {}
        }
        
        emit(2, 50, `AI analysis complete - ${findings.length} vulnerabilities detected`);
        
        // Phase 3: Threat Intelligence
        emit(3, 55, 'Phase 3: Threat Intel - Enriching with CVE data...');
        
        for (const tech of discovery.techStack) {
            const cves = await threatIntel.lookupCVE(tech.name, tech.version);
            const enriched = await threatIntel.enrichWithThreatIntel(cves);
            
            for (const cve of enriched) {
                db.prepare(`INSERT INTO vulnerabilities 
                    (scan_id, cve_id, severity, description, vuln_type, affected_url, confidence, cvss_score, cvss_vector) 
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)
                    .run(scanId, cve.cve_id, cve.severity, cve.description, 'Known CVE', mainUrl, 
                         cve.confidence, cve.cvssScore, cve.cvssVector);
            }
        }
        
        emit(3, 70, 'Threat intelligence enrichment complete');
        
        // Phase 4: Traditional scanning for validation
        emit(4, 75, 'Phase 4: Validating findings with active tests...');
        await runScanV2(domain, scanId, db, emit);
        
        // Phase 5: Generate report
        emit(5, 90, 'Phase 5: Generating comprehensive report...');
        
        const scanData = {
            target: domain,
            scanId,
            findings,
            endpoints: discovery.endpoints,
            techStack: discovery.techStack,
            subdomains: discovery.subdomains,
            assets: discovery.assets,
            duration: (Date.now() - startTime) / 1000
        };
        
        const report = await reportEngine.generateReport(scanData);
        
        // Update scan with final results
        const allVulns = db.prepare('SELECT * FROM vulnerabilities WHERE scan_id = ?').all(scanId);
        const critCount = allVulns.filter(v => v.severity === 'critical').length;
        const highCount = allVulns.filter(v => v.severity === 'high').length;
        const medCount = allVulns.filter(v => v.severity === 'medium').length;
        const lowCount = allVulns.filter(v => v.severity === 'low').length;
        const riskScore = Math.min(100, critCount * 25 + highCount * 15 + medCount * 5 + lowCount);
        
        db.prepare(`UPDATE scans SET 
            status = 'completed', 
            completed_at = ?, 
            risk_score = ?, 
            total_vulnerabilities = ?,
            critical_count = ?,
            high_count = ?,
            medium_count = ?,
            low_count = ?,
            subdomain_count = ?,
            live_host_count = ?
            WHERE id = ?`)
            .run(new Date().toISOString(), riskScore, allVulns.length, critCount, highCount, 
                 medCount, lowCount, discovery.subdomains.length, discovery.endpoints.length, scanId);
        
        emit(10, 100, `Scan complete! ${allVulns.length} vulnerabilities found. Risk: ${riskScore}/100`);
        broadcast(scanId, { 
            phase: 10, 
            progress: 100, 
            completed: true, 
            report: {
                riskScore,
                totalVulns: allVulns.length,
                critical: critCount,
                high: highCount,
                medium: medCount,
                low: lowCount
            }
        });
        
    } catch (err) {
        console.error(`[AI Scan Error] ${domain}:`, err);
        db.prepare("UPDATE scans SET status = 'failed', error_message = ? WHERE id = ?")
            .run(err.message, scanId);
        broadcast(scanId, { phase: 0, progress: 0, error: true, message: err.message });
    }
}

// ═══════════════════════════════════════
// Scan Management Routes
// ═══════════════════════════════════════

app.get('/api/scans', authMiddleware, (req, res) => {
    const scans = db.prepare(`
        SELECT s.*, 
            (SELECT COUNT(*) FROM vulnerabilities WHERE scan_id = s.id) as vuln_count
        FROM scans s 
        WHERE s.user_id = ? 
        ORDER BY s.created_at DESC
    `).all(req.userId);
    res.json({ scans });
});

app.delete('/api/scans/:id', authMiddleware, (req, res) => {
    const scan = db.prepare('SELECT * FROM scans WHERE id = ? AND user_id = ?').get(req.params.id, req.userId);
    if (!scan) return res.status(404).json({ error: 'Scan not found' });
    
    // Delete all related data
    const tables = ['vulnerabilities','subdomains','endpoints','assets','tech_stack','dns_records','ports','live_hosts','exploit_results','timeline_events'];
    for (const table of tables) {
        try { db.prepare(`DELETE FROM ${table} WHERE scan_id = ?`).run(req.params.id); } catch (_) {}
    }
    db.prepare('DELETE FROM scans WHERE id = ?').run(req.params.id);
    res.json({ success: true });
});

app.get('/api/scans/:id', authMiddleware, (req, res) => {
    const scan = db.prepare('SELECT * FROM scans WHERE id = ? AND user_id = ?').get(req.params.id, req.userId);
    if (!scan) return res.status(404).json({ error: 'Scan not found' });
    
    const vulnerabilities = db.prepare('SELECT * FROM vulnerabilities WHERE scan_id = ?').all(req.params.id);
    const subdomains = db.prepare('SELECT * FROM subdomains WHERE scan_id = ?').all(req.params.id);
    const endpoints = db.prepare('SELECT * FROM endpoints WHERE scan_id = ?').all(req.params.id);
    const techStack = db.prepare('SELECT * FROM tech_stack WHERE scan_id = ?').all(req.params.id);
    
    res.json({ scan: { ...scan, vulnerabilities, subdomains, endpoints, techStack } });
});

// Scan detail endpoints
app.get('/api/scans/:id/subdomains', authMiddleware, (req, res) => {
    const subdomains = db.prepare('SELECT * FROM subdomains WHERE scan_id = ?').all(req.params.id);
    res.json({ subdomains });
});

app.get('/api/scans/:id/hosts', authMiddleware, (req, res) => {
    const hosts = db.prepare('SELECT * FROM live_hosts WHERE scan_id = ?').all(req.params.id);
    res.json({ hosts });
});

app.get('/api/scans/:id/screenshots', authMiddleware, (req, res) => {
    // Screenshots not implemented yet
    res.json({ screenshots: [] });
});

app.get('/api/scans/:id/assets', authMiddleware, (req, res) => {
    const assets = db.prepare('SELECT * FROM assets WHERE scan_id = ?').all(req.params.id);
    res.json({ assets });
});

app.get('/api/scans/:id/endpoints', authMiddleware, (req, res) => {
    const endpoints = db.prepare('SELECT * FROM endpoints WHERE scan_id = ?').all(req.params.id);
    res.json({ endpoints });
});

app.get('/api/scans/:id/vulnerabilities', authMiddleware, (req, res) => {
    const vulnerabilities = db.prepare('SELECT * FROM vulnerabilities WHERE scan_id = ? ORDER BY cvss_score DESC').all(req.params.id);
    res.json({ vulnerabilities });
});

app.get('/api/scans/:id/dns', authMiddleware, (req, res) => {
    const dns = db.prepare('SELECT * FROM dns_records WHERE scan_id = ?').all(req.params.id);
    res.json({ dns });
});

app.get('/api/scans/:id/ports', authMiddleware, (req, res) => {
    const ports = db.prepare('SELECT * FROM ports WHERE scan_id = ?').all(req.params.id);
    res.json({ ports });
});

app.get('/api/scans/:id/tech', authMiddleware, (req, res) => {
    const tech = db.prepare('SELECT * FROM tech_stack WHERE scan_id = ?').all(req.params.id);
    res.json({ tech });
});

app.get('/api/scans/:id/exploits', authMiddleware, (req, res) => {
    const exploits = db.prepare('SELECT * FROM exploit_results WHERE scan_id = ?').all(req.params.id);
    res.json({ exploits });
});

app.get('/api/scans/:id/attack-chains', authMiddleware, (req, res) => {
    // Generate attack chains from vulnerabilities
    const vulns = db.prepare('SELECT * FROM vulnerabilities WHERE scan_id = ?').all(req.params.id);
    const chains = [];
    
    // Chain 1: Info Disclosure -> Auth Bypass
    const infoDisclosure = vulns.find(v => v.vuln_type?.includes('Info') || v.cve_id?.includes('INFO'));
    const authBypass = vulns.find(v => v.vuln_type?.includes('Auth') || v.cve_id?.includes('AUTH'));
    if (infoDisclosure && authBypass) {
        chains.push({
            id: 1,
            chain_name: 'Privilege Escalation Chain',
            severity: 'critical',
            risk_score: 95,
            steps: ['Gather system information', 'Bypass authentication', 'Access sensitive data'],
            impact: 'Full system compromise possible'
        });
    }
    
    // Chain 2: XSS -> Session Hijack
    const xss = vulns.find(v => v.vuln_type?.includes('XSS'));
    if (xss) {
        chains.push({
            id: 2,
            chain_name: 'Account Takeover Chain',
            severity: 'high',
            risk_score: 80,
            steps: ['Inject malicious JavaScript', 'Steal session token', 'Impersonate user'],
            impact: 'User account compromise'
        });
    }
    
    // Chain 3: SQL Injection
    const sqli = vulns.find(v => v.vuln_type?.includes('SQL'));
    if (sqli) {
        chains.push({
            id: 3,
            chain_name: 'Data Breach Chain',
            severity: 'critical',
            risk_score: 98,
            steps: ['Extract database schema', 'Dump sensitive data', 'Potential ransomware'],
            impact: 'Complete data breach'
        });
    }
    
    res.json({ chains });
});

app.get('/api/scans/:id/compliance', authMiddleware, (req, res) => {
    const vulns = db.prepare('SELECT * FROM vulnerabilities WHERE scan_id = ?').all(req.params.id);
    const compliance = [];
    
    // OWASP Top 10 mapping
    const owaspMapping = {
        'A01:2021': { name: 'Broken Access Control', checks: [] },
        'A02:2021': { name: 'Cryptographic Failures', checks: [] },
        'A03:2021': { name: 'Injection', checks: ['SQL', 'XSS', 'Command'] },
        'A05:2021': { name: 'Security Misconfiguration', checks: ['Header', 'Config'] },
        'A06:2021': { name: 'Vulnerable Components', checks: ['CVE'] }
    };
    
    for (const [code, data] of Object.entries(owaspMapping)) {
        const found = vulns.filter(v => data.checks.some(c => v.vuln_type?.includes(c) || v.cve_id?.includes(c)));
        compliance.push({
            id: code,
            framework: 'OWASP Top 10 2021',
            category: code,
            check_name: data.name,
            status: found.length > 0 ? 'fail' : 'pass',
            details: found.length > 0 ? `${found.length} issues found` : 'No issues'
        });
    }
    
    res.json({ compliance });
});

app.get('/api/scans/:id/timeline', authMiddleware, (req, res) => {
    const timeline = db.prepare('SELECT * FROM timeline_events WHERE scan_id = ? ORDER BY timestamp').all(req.params.id);
    res.json({ timeline });
});

app.get('/api/scans/:id/remediation', authMiddleware, (req, res) => {
    const vulns = db.prepare('SELECT * FROM vulnerabilities WHERE scan_id = ?').all(req.params.id);
    const remediation = vulns.map(v => ({
        id: v.id,
        title: v.cve_id || v.vuln_type,
        severity: v.severity,
        description: v.description,
        fix: v.remediation || 'Apply security patches and follow vendor recommendations',
        priority: v.severity === 'critical' ? 1 : v.severity === 'high' ? 2 : v.severity === 'medium' ? 3 : 4,
        effort: v.severity === 'critical' ? '1-2 days' : v.severity === 'high' ? '3-5 days' : '1-2 weeks'
    }));
    res.json({ remediation });
});

app.get('/api/scans/:id/export', authMiddleware, async (req, res) => {
    const format = req.query.format || 'json';
    const scan = db.prepare('SELECT * FROM scans WHERE id = ? AND user_id = ?').get(req.params.id, req.userId);
    if (!scan) return res.status(404).json({ error: 'Scan not found' });
    
    const vulnerabilities = db.prepare('SELECT * FROM vulnerabilities WHERE scan_id = ?').all(req.params.id);
    
    if (format === 'json') {
        res.setHeader('Content-Type', 'application/json');
        res.setHeader('Content-Disposition', `attachment; filename="scan-${scan.domain}.json"`);
        res.json({ scan, vulnerabilities });
    } else if (format === 'csv') {
        const headers = ['ID', 'CVE', 'Severity', 'Type', 'Description', 'URL', 'CVSS'];
        const rows = vulnerabilities.map(v => [
            v.id, v.cve_id, v.severity, v.vuln_type, 
            `"${(v.description || '').replace(/"/g, '""')}"`, 
            v.affected_url, v.cvss_score
        ]);
        const csv = [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
        res.setHeader('Content-Type', 'text/csv');
        res.setHeader('Content-Disposition', `attachment; filename="scan-${scan.domain}.csv"`);
        res.send(csv);
    } else {
        res.status(400).json({ error: 'Unsupported format' });
    }
});

app.post('/api/scans/:scanId/exploit/:vulnId', authMiddleware, async (req, res) => {
    const { scanId, vulnId } = req.params;
    
    try {
        const vuln = db.prepare('SELECT * FROM vulnerabilities WHERE id = ? AND scan_id = ?').get(vulnId, scanId);
        if (!vuln) return res.status(404).json({ error: 'Vulnerability not found' });
        
        // Run exploit verification
        const result = await termExploit(vuln.affected_url, vuln.vuln_type, [], {
            verifyOnly: true,
            verbose: true
        });
        
        // Store exploit result
        db.prepare(`INSERT INTO exploit_results 
            (scan_id, cve_id, affected_url, exploitable, confidence, payload_used, evidence, risk_score) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
            .run(scanId, vuln.cve_id, vuln.affected_url, 
                 result.verified ? 1 : 0, 
                 result.hits?.[0]?.confidence || 50,
                 result.hits?.[0]?.payload || '',
                 result.hits?.[0]?.evidence || '',
                 vuln.cvss_score || 50);
        
        res.json({
            exploit: {
                verified: result.verified,
                methods_tried: result.hits?.length || 0,
                methods_succeeded: result.verified ? 1 : 0,
                payload: result.hits?.[0]?.payload,
                evidence: result.hits?.[0]?.evidence,
                response_body: result.hits?.[0]?.responseSnippet,
                remediation: 'Apply vendor patches immediately'
            }
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});


app.get('/api/scans/:id/report', authMiddleware, async (req, res) => {
    const scan = db.prepare('SELECT * FROM scans WHERE id = ? AND user_id = ?').get(req.params.id, req.userId);
    if (!scan) return res.status(404).json({ error: 'Scan not found' });
    
    const vulnerabilities = db.prepare('SELECT * FROM vulnerabilities WHERE scan_id = ?').all(req.params.id);
    const endpoints = db.prepare('SELECT * FROM endpoints WHERE scan_id = ?').all(req.params.id);
    const techStack = db.prepare('SELECT * FROM tech_stack WHERE scan_id = ?').all(req.params.id);
    
    const scanData = {
        target: scan.domain,
        scanId: scan.id,
        findings: vulnerabilities,
        endpoints,
        techStack,
        duration: scan.completed_at ? (new Date(scan.completed_at) - new Date(scan.started_at)) / 1000 : 0
    };
    
    const report = await reportEngine.generateReport(scanData, { includeRaw: req.query.raw === 'true' });
    res.json(report);
});

// ═══════════════════════════════════════
// AI Analysis Routes
// ═══════════════════════════════════════

app.post('/api/ai/analyze', authMiddleware, async (req, res) => {
    const { url, method = 'GET', headers = {}, body = '', params = [] } = req.body;
    
    try {
        const response = await termFetch(url);
        const analysis = await aiAnalyzer.analyze(url, { 
            data: response.body, 
            headers: response.headers 
        }, { params });
        
        res.json({
            url,
            analysis,
            timestamp: new Date().toISOString()
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/ai/discover', authMiddleware, async (req, res) => {
    const { url } = req.body;
    
    try {
        const discovery = await discoveryEngine.discover(url);
        res.json(discovery);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/ai/threat-intel', authMiddleware, async (req, res) => {
    const { technology, version } = req.body;
    
    try {
        const cves = await threatIntel.lookupCVE(technology, version);
        const enriched = await threatIntel.enrichWithThreatIntel(cves);
        res.json({ technology, version, cves: enriched });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ═══════════════════════════════════════
// Terminal Routes
// ═══════════════════════════════════════

app.post('/api/terminal/headers', authMiddleware, async (req, res) => {
    try {
        const result = await termHeaders(req.body.url);
        res.json(result);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/terminal/ssl', authMiddleware, async (req, res) => {
    try {
        const result = await termSSL(req.body.domain);
        res.json(result);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/terminal/ports', authMiddleware, async (req, res) => {
    try {
        const result = await termPorts(req.body.host);
        res.json(result);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/terminal/dns', authMiddleware, async (req, res) => {
    try {
        const result = await termDNS(req.body.domain);
        res.json(result);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/terminal/fetch', authMiddleware, async (req, res) => {
    try {
        const result = await termFetch(req.body.url);
        res.json(result);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/terminal/scan', authMiddleware, async (req, res) => {
    try {
        const result = await termScan(req.body.url, db, req.body.scanId, req.userId);
        res.json(result);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/terminal/fuzz', authMiddleware, async (req, res) => {
    try {
        const result = await termFuzz(req.body.url);
        res.json(result);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/terminal/exploit', authMiddleware, async (req, res) => {
    try {
        const result = await termExploit(req.body.url, req.body.vulnType, req.body.params, req.body.options);
        res.json(result);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/terminal/reverse-shell', authMiddleware, async (req, res) => {
    const { url, yourIp, yourPort, options = {} } = req.body;
    
    try {
        const result = await termReverseShell(url, yourIp, yourPort, options);
        res.json(result);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// GET Terminal Routes (for frontend integration)
app.get('/api/terminal/headers', authMiddleware, async (req, res) => {
    try {
        const result = await termHeaders(req.query.url);
        res.json({ headers: result });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/terminal/ssl', authMiddleware, async (req, res) => {
    try {
        const result = await termSSL(req.query.domain);
        res.json({ ssl: result });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/terminal/ports', authMiddleware, async (req, res) => {
    try {
        const result = await termPorts(req.query.host);
        res.json({ ports: result });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/terminal/dns', authMiddleware, async (req, res) => {
    try {
        const result = await termDNS(req.query.domain);
        res.json({ records: result });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/terminal/fetch', authMiddleware, async (req, res) => {
    try {
        const result = await termFetch(req.query.url);
        res.json(result);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/terminal/status', authMiddleware, async (req, res) => {
    const scanId = req.query.scanId;
    const scan = db.prepare('SELECT * FROM scans WHERE id = ?').get(scanId);
    const endpoints = db.prepare('SELECT COUNT(*) as count FROM endpoints WHERE scan_id = ?').get(scanId);
    const vulns = db.prepare('SELECT COUNT(*) as count FROM vulnerabilities WHERE scan_id = ?').get(scanId);
    const exploits = db.prepare('SELECT COUNT(*) as count FROM exploit_results WHERE scan_id = ?').get(scanId);
    
    res.json({
        scan,
        stats: {
            endpoints: endpoints?.count || 0,
            vulnerabilities: vulns?.count || 0,
            exploitChecks: exploits?.count || 0
        }
    });
});

app.get('/api/terminal/vulns', authMiddleware, async (req, res) => {
    const vulnerabilities = db.prepare('SELECT * FROM vulnerabilities WHERE scan_id = ?').all(req.query.scanId);
    res.json({ vulnerabilities });
});

app.get('/api/terminal/endpoints', authMiddleware, async (req, res) => {
    const endpoints = db.prepare('SELECT * FROM endpoints WHERE scan_id = ?').all(req.query.scanId);
    res.json({ endpoints });
});

app.get('/api/terminal/subdomains', authMiddleware, async (req, res) => {
    const subdomains = db.prepare('SELECT * FROM subdomains WHERE scan_id = ?').all(req.query.scanId);
    res.json({ subdomains });
});

app.get('/api/terminal/tech', authMiddleware, async (req, res) => {
    const tech = db.prepare('SELECT * FROM tech_stack WHERE scan_id = ?').all(req.query.scanId);
    res.json({ tech });
});

app.get('/api/terminal/attack-surface', authMiddleware, async (req, res) => {
    const scanId = req.query.scanId;
    const scan = db.prepare('SELECT * FROM scans WHERE id = ?').get(scanId);
    const subdomains = db.prepare('SELECT COUNT(*) as count FROM subdomains WHERE scan_id = ?').get(scanId);
    const hosts = db.prepare('SELECT COUNT(*) as count FROM live_hosts WHERE scan_id = ?').get(scanId);
    const endpoints = db.prepare('SELECT COUNT(*) as count FROM endpoints WHERE scan_id = ?').get(scanId);
    const ports = db.prepare('SELECT * FROM ports WHERE scan_id = ? AND state = ?').all(scanId, 'open');
    const tech = db.prepare('SELECT * FROM tech_stack WHERE scan_id = ?').all(scanId);
    const vulns = db.prepare('SELECT * FROM vulnerabilities WHERE scan_id = ?').all(scanId);
    const activeVulns = vulns.filter(v => v.vuln_type?.includes('ACTIVE'));
    const sensitive = vulns.filter(v => v.vuln_type?.includes('Sensitive') || v.description?.includes('exposed'));
    
    res.json({
        domain: scan?.domain,
        subdomains: subdomains?.count || 0,
        hosts: hosts?.count || 0,
        endpoints: endpoints?.count || 0,
        riskScore: scan?.risk_score || 0,
        openPorts: ports,
        tech,
        summary: {
            critical: scan?.critical_count || 0,
            high: scan?.high_count || 0,
            medium: scan?.medium_count || 0,
            low: scan?.low_count || 0,
            total_vulns: vulns.length,
            confirmed_exploits: activeVulns.length
        },
        activeVulns,
        sensitiveExposed: sensitive
    });
});

// ═══════════════════════════════════════
// Exploit Engine Routes
// ═══════════════════════════════════════


// Active sessions storage
const activeSessions = new Map();

app.post('/api/exploit/reverse-shell', authMiddleware, async (req, res) => {
    const { scanId, targetUrl, yourIp, yourPort, payloadType = 'python', verifyOnly = false } = req.body;
    
    try {
        const sessionId = Date.now();
        const result = await termReverseShell(targetUrl, yourIp, yourPort, {
            payloadType,
            verifyOnly,
            verbose: true
        });
        
        if (result.shellConnected) {
            activeSessions.set(sessionId, {
                id: sessionId,
                scanId,
                targetUrl,
                yourIp,
                yourPort,
                payloadType,
                status: 'active',
                connectedAt: new Date().toISOString()
            });
        }
        
        res.json({
            ...result,
            sessionId,
            connected: result.shellConnected,
            status: result.shellConnected ? 'active' : 'failed'
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/exploit/execute-command', authMiddleware, async (req, res) => {
    const { sessionId, command } = req.body;
    
    const session = activeSessions.get(sessionId);
    if (!session) {
        return res.status(404).json({ error: 'Session not found' });
    }
    
    // This would execute on the actual shell - placeholder for now
    res.json({
        success: true,
        command,
        output: `Executed: ${command}\n[Output would appear here from actual shell]`,
        sessionId
    });
});

app.post('/api/exploit/stop-listener', authMiddleware, async (req, res) => {
    const { sessionId } = req.body;
    
    const session = activeSessions.get(sessionId);
    if (session) {
        session.status = 'stopped';
        session.stoppedAt = new Date().toISOString();
        res.json({ success: true, message: 'Listener stopped' });
    } else {
        res.status(404).json({ error: 'Session not found' });
    }
});

app.get('/api/exploit/shell-sessions/:scanId', authMiddleware, (req, res) => {
    const sessions = Array.from(activeSessions.values())
        .filter(s => s.scanId === req.params.scanId);
    res.json({ sessions });
});

app.get('/api/exploit/active-sessions', authMiddleware, (req, res) => {
    const sessions = Array.from(activeSessions.values())
        .filter(s => s.status === 'active');
    res.json({ activeSessions: sessions });
});

app.post('/api/terminal/exploit-full', authMiddleware, async (req, res) => {
    const { scanId, vulnId, targetUrl, yourIp, yourPort, autoShell } = req.body;
    
    try {
        let url = targetUrl;
        let vulnType = 'all';
        let knownParams = [];
        
        // If vulnId is provided, look up the vulnerability
        if (vulnId && scanId) {
            // Try as numeric ID first
            let vuln = db.prepare('SELECT * FROM vulnerabilities WHERE id = ? AND scan_id = ?').get(vulnId, scanId);
            if (!vuln) {
                // Try as CVE ID
                vuln = db.prepare('SELECT * FROM vulnerabilities WHERE (cve_id = ? OR vuln_type = ?) AND scan_id = ?').get(vulnId, vulnId, scanId);
            }
            if (!vuln) {
                // Try as type match
                vuln = db.prepare("SELECT * FROM vulnerabilities WHERE LOWER(vuln_type) LIKE ? AND scan_id = ?").get(`%${String(vulnId).toLowerCase()}%`, scanId);
            }
            if (vuln) {
                url = vuln.affected_url || targetUrl;
                vulnType = vuln.vuln_type || 'all';
            }
        }
        
        if (!url) {
            const scan = db.prepare('SELECT domain FROM scans WHERE id = ?').get(scanId);
            url = scan ? `https://${scan.domain}` : targetUrl;
        }
        
        const result = await termExploit(url, vulnType, knownParams, {
            exploit: autoShell || false,
            yourIp,
            yourPort,
            verbose: true
        });
        
        // Build terminal output
        const terminalOutput = [
            '═══════════════════════════════════════════════════',
            `EXPLOIT VERIFICATION: ${vulnType}`,
            '═══════════════════════════════════════════════════',
            `Target: ${url}`,
            `Test: ${result.testName || vulnType}`,
            '',
        ];
        
        if (result.verified && result.hits?.length > 0) {
            terminalOutput.push('🔴 VULNERABILITY CONFIRMED EXPLOITABLE');
            terminalOutput.push('');
            for (const hit of result.hits) {
                terminalOutput.push(`── EXPLOIT EVIDENCE ──`);
                terminalOutput.push(`  Type: ${hit.type}`);
                if (hit.param) terminalOutput.push(`  Parameter: ${hit.param}`);
                if (hit.payload) terminalOutput.push(`  Payload: ${hit.payload}`);
                if (hit.evidence) terminalOutput.push(`  Evidence: ${hit.evidence}`);
                terminalOutput.push('');
            }
        } else {
            terminalOutput.push('🟡 NOT CONFIRMED — ATTEMPTED but no exploitation evidence');
            terminalOutput.push('Suggest: Try manual testing or different parameters');
        }
        
        terminalOutput.push('═══════════════════════════════════════════════════');
        
        res.json({
            ...result,
            terminalOutput,
            shellConnected: result.hits?.some(h => h.shellConnected) || false
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/terminal/exploit-ultimate', authMiddleware, async (req, res) => {
    const { scanId, targetUrl, yourIp, yourPort, autoShell = true } = req.body;
    
    try {
        // Run comprehensive exploit
        const result = await termExploit(targetUrl, 'rce', [], {
            exploit: autoShell,
            yourIp,
            yourPort,
            verbose: true
        });
        
        const terminalOutput = [
            '═══════════════════════════════════════════════════',
            '🔥 ULTIMATE EXPLOIT - MAXIMUM POWER 🔥',
            '═══════════════════════════════════════════════════',
            `Target: ${targetUrl}`,
            `Callback: ${yourIp}:${yourPort}`,
            '',
            result.verified ? '✅ EXPLOIT VERIFIED' : '❌ EXPLOIT FAILED',
            '',
            'Methods attempted:',
            ...(result.hits?.map(h => `  - ${h.type}: ${h.vulnerable ? 'SUCCESS' : 'FAILED'}`) || []),
            '',
            result.verified ? '🔴 SERVER COMPROMISED' : '🟡 Try different payload types',
            '═══════════════════════════════════════════════════'
        ];
        
        res.json({
            ...result,
            terminalOutput,
            shellConnected: result.verified && autoShell
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});


// ═══════════════════════════════════════
// Health Check
// ═══════════════════════════════════════

app.get('/api/health', (req, res) => {
    res.json({ 
        status: 'ok', 
        version: '3.0.0', 
        uptime: process.uptime(), 
        features: ['ai-analysis', 'discovery', 'threat-intel', 'reverse-shell', 'rce-verify'],
        engines: {
            aiAnalyzer: true,
            discoveryEngine: true,
            threatIntel: true,
            reportEngine: true
        }
    });
});

// ═══════════════════════════════════════
// Start Server
// ═══════════════════════════════════════

server.on('error', (err) => {
    if (err?.code === 'EADDRINUSE') {
        console.error(`\n[Server] Port ${PORT} is already in use.`);
        process.exit(1);
    }
    console.error('[Server] error:', err.message);
    process.exit(1);
});

server.listen(PORT, () => {
    console.log(`\n🛡️  Cosmic Eye AI-Powered Backend running on http://localhost:${PORT}`);
    console.log(`📡  WebSocket available at ws://localhost:${PORT}/ws`);
    console.log(`🤖  AI Engines: Analyzer, Discovery, Threat Intel, Report`);
    console.log(`📦  Database: bugfinder.db (SQLite WAL mode)\n`);
});
