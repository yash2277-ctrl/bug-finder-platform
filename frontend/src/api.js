// API client for Cosmic Eye AI-Powered Pentesting
const API_BASE = '/api';


function getHeaders() {
    const token = localStorage.getItem('bf_token');
    return {
        'Content-Type': 'application/json',
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
    };
}

async function request(path, options = {}) {
    const res = await fetch(`${API_BASE}${path}`, {
        ...options,
        headers: { ...getHeaders(), ...options.headers },
    });
    if (res.status === 401) {
        localStorage.removeItem('bf_token');
        localStorage.removeItem('bf_user');
        window.location.href = '/auth';
        throw new Error('Unauthorized');
    }
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Request failed');
    return data;
}

export const api = {
    // Auth
    register: (body) => request('/auth/register', { method: 'POST', body: JSON.stringify(body) }),
    login: (body) => request('/auth/login', { method: 'POST', body: JSON.stringify(body) }),
    me: () => request('/auth/me'),

    // Scans
    createScan: (domain) => request('/scans', { method: 'POST', body: JSON.stringify({ domain }) }),
    getScans: () => request('/scans'),
    getScan: (id) => request(`/scans/${id}`),
    deleteScan: (id) => request(`/scans/${id}`, { method: 'DELETE' }),
    getScanReport: (id, includeRaw = false) => request(`/scans/${id}/report${includeRaw ? '?raw=true' : ''}`),

    // AI-Powered Analysis
    aiAnalyze: (body) => request('/ai/analyze', { method: 'POST', body: JSON.stringify(body) }),
    aiDiscover: (body) => request('/ai/discover', { method: 'POST', body: JSON.stringify(body) }),
    aiThreatIntel: (body) => request('/ai/threat-intel', { method: 'POST', body: JSON.stringify(body) }),

    // Original Results
    getSubdomains: (id) => request(`/scans/${id}/subdomains`),
    getHosts: (id) => request(`/scans/${id}/hosts`),
    getScreenshots: (id) => request(`/scans/${id}/screenshots`),
    getAssets: (id) => request(`/scans/${id}/assets`),
    getEndpoints: (id) => request(`/scans/${id}/endpoints`),
    getVulnerabilities: (id) => request(`/scans/${id}/vulnerabilities`),

    // NEW: AI-Powered endpoints
    getDNS: (id) => request(`/scans/${id}/dns`),
    getPorts: (id) => request(`/scans/${id}/ports`),
    getTechStack: (id) => request(`/scans/${id}/tech`),
    getExploits: (id) => request(`/scans/${id}/exploits`),
    getAttackChains: (id) => request(`/scans/${id}/attack-chains`),
    getCompliance: (id) => request(`/scans/${id}/compliance`),
    getTimeline: (id) => request(`/scans/${id}/timeline`),
    getRemediation: (id) => request(`/scans/${id}/remediation`),

    // One-Tap Exploit
    exploitVuln: (scanId, vulnId) => request(`/scans/${scanId}/exploit/${vulnId}`, { method: 'POST' }),

    // ULTIMATE EXPLOIT - Maximum Power
    ultimateExploit: (body) => request('/terminal/exploit-ultimate', { method: 'POST', body: JSON.stringify(body) }),
    
    // Reverse Shell
    reverseShell: (body) => request('/exploit/reverse-shell', { method: 'POST', body: JSON.stringify(body) }),
    
    // Execute Command on Active Shell
    executeShellCommand: (body) => request('/exploit/execute-command', { method: 'POST', body: JSON.stringify(body) }),
    
    // Stop Shell Listener
    stopListener: (body) => request('/exploit/stop-listener', { method: 'POST', body: JSON.stringify(body) }),
    
    // Get Shell Sessions
    getShellSessions: (scanId) => request(`/exploit/shell-sessions/${scanId}`),
    
    // Get Active Sessions
    getActiveSessions: () => request('/exploit/active-sessions'),

    // Terminal Commands
    terminalScan: (body) => request('/terminal/scan', { method: 'POST', body: JSON.stringify(body) }),
    terminalFuzz: (body) => request('/terminal/fuzz', { method: 'POST', body: JSON.stringify(body) }),
    terminalHeaders: (url) => request(`/terminal/headers?url=${encodeURIComponent(url)}`),
    terminalSSL: (domain) => request(`/terminal/ssl?domain=${encodeURIComponent(domain)}`),
    terminalPorts: (host) => request(`/terminal/ports?host=${encodeURIComponent(host)}`),
    terminalDNS: (domain) => request(`/terminal/dns?domain=${encodeURIComponent(domain)}`),
    terminalFetch: (url) => request(`/terminal/fetch?url=${encodeURIComponent(url)}`),
    terminalStatus: (scanId) => request(`/terminal/status?scanId=${encodeURIComponent(scanId)}`),
    terminalVulns: (scanId) => request(`/terminal/vulns?scanId=${encodeURIComponent(scanId)}`),
    terminalEndpoints: (scanId) => request(`/terminal/endpoints?scanId=${encodeURIComponent(scanId)}`),
    terminalSubdomains: (scanId) => request(`/terminal/subdomains?scanId=${encodeURIComponent(scanId)}`),
    terminalTech: (scanId) => request(`/terminal/tech?scanId=${encodeURIComponent(scanId)}`),
    terminalAttackSurface: (scanId) => request(`/terminal/attack-surface?scanId=${encodeURIComponent(scanId)}`),

    // Export
    exportScan: (id, format) => {
        const token = localStorage.getItem('bf_token');
        return fetch(`${API_BASE}/scans/${id}/export?format=${format}`, {
            headers: { Authorization: `Bearer ${token}` },
        });
    },
};

export function connectWebSocket(scanId, onMessage) {
    const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsBase = import.meta.env.VITE_WS_BASE
        ? String(import.meta.env.VITE_WS_BASE).replace(/\/$/, '')
        : `${proto}//${window.location.host}`;
    const ws = new WebSocket(`${wsBase}/ws?scanId=${scanId}`);
    ws.onopen = () => {
        console.log('[WebSocket] Connected for scan:', scanId);
    };
    ws.onmessage = (event) => {
        try {
            const data = JSON.parse(event.data);
            onMessage(data);
        } catch (e) { 
            console.error('[WebSocket] Parse error:', e);
        }
    };
    ws.onerror = (err) => { 
        console.error('[WebSocket] Error:', err);
    };
    ws.onclose = () => {
        console.log('[WebSocket] Disconnected');
    };
    return ws;
}

export default api;
