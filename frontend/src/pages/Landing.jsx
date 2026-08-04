import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../api';
import { useToast } from '../App';

export default function Landing() {
    const [domain, setDomain] = useState('');
    const [loading, setLoading] = useState(false);
    const [scans, setScans] = useState([]);
    const [scansLoading, setScansLoading] = useState(true);
    const navigate = useNavigate();
    const showToast = useToast();

    useEffect(() => {
        loadScans();
    }, []);

    async function loadScans() {
        try {
            const data = await api.getScans();
            setScans(data.scans || []);
        } catch (e) {
            console.error(e);
        } finally {
            setScansLoading(false);
        }
    }

    async function handleScan(e) {
        e.preventDefault();
        if (!domain.trim()) return;
        setLoading(true);
        try {
            const res = await api.createScan(domain.trim());
            showToast(`Scan started for ${res.scan.domain}`, 'success');
            navigate(`/scan/${res.scan.id}`);
        } catch (err) {
            showToast(err.message, 'error');
        } finally {
            setLoading(false);
        }
    }

    async function handleDelete(id) {
        try {
            await api.deleteScan(id);
            setScans(scans.filter(s => s.id !== id));
            showToast('Scan deleted', 'success');
        } catch {
            showToast('Failed to delete', 'error');
        }
    }

    const statusColor = (s) => {
        if (s === 'completed') return 'var(--success)';
        if (s === 'running') return 'var(--accent-cyan)';
        if (s === 'failed') return 'var(--danger)';
        return 'var(--text-muted)';
    };

    return (
        <div>
            {/* Hero */}
            <section className="hero">
                <h1 className="animate-in">🛰️ Cosmic Eye</h1>
                <p className="animate-in" style={{ animationDelay: '0.1s' }}>
                    AI-Powered Penetration Testing Platform. Discover all endpoints, find real vulnerabilities with exploit verification, establish reverse shells, and map attack chains — with intelligent accuracy and zero false positives.
                </p>

                <form className="domain-input-group animate-in" style={{ animationDelay: '0.2s' }} onSubmit={handleScan}>
                    <input
                        className="input input-lg"
                        type="text"
                        placeholder="Enter target domain (e.g. example.com)"
                        value={domain}
                        onChange={(e) => setDomain(e.target.value)}
                        disabled={loading}
                        autoFocus
                    />
                    <button className="btn btn-primary" type="submit" disabled={loading || !domain.trim()} style={{ padding: '16px 28px', fontSize: '1rem' }}>
                        {loading ? <span className="spinner"></span> : '🚀'} Start Scan
                    </button>
                </form>
            </section>

            {/* Features */}
            <div className="features-grid">
                {[
                    { icon: '🌐', title: 'AI Endpoint Discovery', desc: 'Intelligent crawling with JavaScript analysis to find hidden APIs, GraphQL endpoints, and WebSocket interfaces.' },
                    { icon: '📡', title: 'Real Vulnerability Detection', desc: 'ML-powered detection with out-of-band verification. No fake data — every vulnerability is real and exploitable.' },
                    { icon: '💥', title: 'Auto-Exploitation', desc: 'One-tap exploit verification with reverse shell capabilities. Confirm vulnerabilities actually work.' },
                    { icon: '⛓️', title: 'Attack Chain Mapping', desc: 'Graph-based attack path discovery showing how vulnerabilities chain together for maximum impact.' },
                    { icon: '🛡️', title: 'Intelligent CVE Correlation', desc: 'Real-time exploitDB and CISA KEV integration with actual exploit code availability.' },
                    { icon: '⚔️', title: 'Full Pentest Arsenal', desc: 'XSS, SQLi, RCE, SSTI, LFI, SSRF, CORS, Open Redirect — all with differential analysis for accuracy.' },
                ].map((f, i) => (

                    <div className="feature-card animate-in" key={i} style={{ animationDelay: `${0.1 * i}s` }}>
                        <div className="feature-icon">{f.icon}</div>
                        <h3>{f.title}</h3>
                        <p>{f.desc}</p>
                    </div>
                ))}
            </div>

            {/* Scan History */}
            <div className="scan-history">
                <h2 className="section-title">Recent Scans</h2>
                {scansLoading ? (
                    <div className="loading-overlay"><div className="spinner"></div> Loading scans...</div>
                ) : scans.length === 0 ? (
                    <div className="empty-state">
                        <div className="empty-icon">🔍</div>
                        <h3>No scans yet</h3>
                        <p>Enter a domain above to start your first scan</p>
                    </div>
                ) : (
                    <div className="table-container">
                        <table className="data-table">
                            <thead>
                                <tr>
                                    <th>Domain</th>
                                    <th>Status</th>
                                    <th>Subdomains</th>
                                    <th>Live Hosts</th>
                                    <th>Vulnerabilities</th>
                                    <th>Critical</th>
                                    <th>Started</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                {scans.map(scan => (
                                    <tr key={scan.id}>
                                        <td>
                                            <span className="mono" style={{ cursor: 'pointer' }} onClick={() => navigate(`/scan/${scan.id}`)}>
                                                {scan.domain}
                                            </span>
                                        </td>
                                        <td>
                                            <span className="badge"
                                                title={scan.status === 'failed' && scan.error_message ? scan.error_message : ''}
                                                style={{
                                                background: `${statusColor(scan.status)}18`,
                                                color: statusColor(scan.status),
                                                border: `1px solid ${statusColor(scan.status)}40`
                                            }}>
                                                {scan.status === 'running' && <span className="status-dot running"></span>}
                                                {scan.status}
                                            </span>
                                        </td>
                                        <td>{scan.subdomain_count || 0}</td>
                                        <td>{scan.live_host_count || 0}</td>
                                        <td>{scan.total_vulnerabilities || 0}</td>
                                        <td>
                                            {(scan.critical_count || 0) > 0 ? (
                                                <span className="badge badge-danger">{scan.critical_count}</span>
                                            ) : (
                                                <span style={{ color: 'var(--text-muted)' }}>0</span>
                                            )}
                                        </td>
                                        <td style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                                            {new Date(scan.created_at).toLocaleString()}
                                        </td>
                                        <td>
                                            <div style={{ display: 'flex', gap: 6 }}>
                                                <button className="btn btn-sm btn-secondary" onClick={() => navigate(`/scan/${scan.id}`)}>
                                                    View
                                                </button>
                                                <button className="btn btn-sm btn-danger" onClick={() => handleDelete(scan.id)}>
                                                    ✕
                                                </button>
                                            </div>
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                )}
            </div>

            {/* Footer */}
            <footer style={{ textAlign: 'center', padding: '40px 20px', color: 'var(--text-muted)', fontSize: '0.8rem', borderTop: '1px solid var(--border-primary)', marginTop: 40 }}>
                <p>⚠️ Only scan domains you own or have explicit authorization to test.</p>
                <p style={{ marginTop: 4 }}>🛰️ Cosmic Eye — AI-Powered Penetration Testing Platform</p>
            </footer>

        </div>
    );
}
