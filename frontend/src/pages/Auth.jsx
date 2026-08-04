import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../App';
import { api } from '../api';

export default function AuthPage() {
    const [isLogin, setIsLogin] = useState(true);
    const [form, setForm] = useState({ username: '', email: '', password: '' });
    const [error, setError] = useState('');
    const [loading, setLoading] = useState(false);
    const { login, user } = useAuth();
    const navigate = useNavigate();

    if (user) {
        navigate('/', { replace: true });
        return null;
    }

    const handleSubmit = async (e) => {
        e.preventDefault();
        setError('');
        setLoading(true);
        try {
            let res;
            if (isLogin) {
                res = await api.login({ username: form.username, password: form.password });
            } else {
                if (!form.email) { setError('Email is required'); setLoading(false); return; }
                res = await api.register(form);
            }
            login(res.token, res.user);
            navigate('/');
        } catch (err) {
            setError(err.message);
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="auth-page">
            <div className="auth-card animate-in">
                <div style={{ textAlign: 'center', fontSize: '2.5rem', marginBottom: 8 }}>🛰️</div>
                <h1 className="auth-title">{isLogin ? 'Welcome Back' : 'Create Account'}</h1>
                <p className="auth-subtitle">
                    {isLogin ? 'Sign in to your Cosmic Eye account' : 'Start discovering vulnerabilities today'}
                </p>


                <form className="auth-form" onSubmit={handleSubmit}>
                    <div className="input-group">
                        <label>Username</label>
                        <input
                            className="input"
                            type="text"
                            placeholder="Enter username"
                            value={form.username}
                            onChange={(e) => setForm({ ...form, username: e.target.value })}
                            required
                            autoFocus
                        />
                    </div>

                    {!isLogin && (
                        <div className="input-group">
                            <label>Email</label>
                            <input
                                className="input"
                                type="email"
                                placeholder="Enter email address"
                                value={form.email}
                                onChange={(e) => setForm({ ...form, email: e.target.value })}
                                required
                            />
                        </div>
                    )}

                    <div className="input-group">
                        <label>Password</label>
                        <input
                            className="input"
                            type="password"
                            placeholder="Enter password"
                            value={form.password}
                            onChange={(e) => setForm({ ...form, password: e.target.value })}
                            required
                            minLength={6}
                        />
                    </div>

                    {error && <p className="error-text" style={{ textAlign: 'center' }}>⚠ {error}</p>}

                    <button className="btn btn-primary" type="submit" disabled={loading} style={{ width: '100%', marginTop: 8 }}>
                        {loading ? <span className="spinner" style={{ width: 16, height: 16 }}></span> : null}
                        {isLogin ? 'Sign In' : 'Create Account'}
                    </button>
                </form>

                <div className="auth-toggle">
                    {isLogin ? "Don't have an account? " : 'Already have an account? '}
                    <button onClick={() => { setIsLogin(!isLogin); setError(''); }}>
                        {isLogin ? 'Sign Up' : 'Sign In'}
                    </button>
                </div>

                <div style={{ marginTop: 24, padding: '12px 16px', background: 'rgba(0,245,212,0.05)', border: '1px solid rgba(0,245,212,0.15)', borderRadius: 8, fontSize: '0.75rem', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
                    ⚠️ <strong>Disclaimer:</strong> Only scan domains you own or have explicit authorization to test. Unauthorized scanning is illegal.
                </div>
            </div>
        </div>
    );
}
