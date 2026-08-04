import { useState, useEffect, createContext, useContext } from 'react';
import { BrowserRouter, Routes, Route, Navigate, useNavigate, Link } from 'react-router-dom';
import AuthPage from './pages/Auth';
import Landing from './pages/Landing';
import ScanDashboard from './pages/ScanDashboard';

// eslint-disable-next-line react-refresh/only-export-components
// ─── Auth Context ───
const AuthContext = createContext(null);

export function useAuth() {
  return useContext(AuthContext);
}

function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const token = localStorage.getItem('bf_token');
    const saved = localStorage.getItem('bf_user');
    if (token && saved) {
      try { 
        setUser(JSON.parse(saved)); 
      } catch { 
        // ignore JSON parse error
      }
    }
    setLoading(false);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const login = (token, userData) => {
    localStorage.setItem('bf_token', token);
    localStorage.setItem('bf_user', JSON.stringify(userData));
    setUser(userData);
  };

  const logout = () => {
    localStorage.removeItem('bf_token');
    localStorage.removeItem('bf_user');
    setUser(null);
  };

  if (loading) return null;

  return (
    <AuthContext.Provider value={{ user, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

function ProtectedRoute({ children }) {
  const { user } = useAuth();
  if (!user) return <Navigate to="/auth" replace />;
  return children;
}

// ─── Header ───
function Header() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();

  return (
    <header className="app-header">
      <div className="app-logo" onClick={() => navigate('/')}>
        <div className="logo-icon">🛰️</div>
        <span>Cosmic Eye</span>
      </div>
      <div className="header-nav">
        {user ? (
          <>
            <div className="header-user">
              <span>👤</span>
              <span>{user.username}</span>
            </div>
            <button className="btn btn-sm btn-secondary" onClick={() => { logout(); navigate('/auth'); }}>
              Logout
            </button>
          </>
        ) : (
          <button className="btn btn-sm btn-primary" onClick={() => navigate('/auth')}>
            Sign In
          </button>
        )}
      </div>
    </header>
  );
}

// ─── Toast ───
export const ToastContext = createContext(null);

// eslint-disable-next-line react-refresh/only-export-components
export function useToast() {
  return useContext(ToastContext);
}

function ToastProvider({ children }) {
  const [toast, setToast] = useState(null);

  const showToast = (message, type = 'info') => {
    setToast({ message, type });
    setTimeout(() => setToast(null), 4000);
  };

  return (
    <ToastContext.Provider value={showToast}>
      {children}
      {toast && (
        <div className={`toast toast-${toast.type}`}>
          {toast.type === 'success' ? '✓' : toast.type === 'error' ? '✕' : 'ℹ'} {toast.message}
        </div>
      )}
    </ToastContext.Provider>
  );
}

// ─── App ───
export default function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <ToastProvider>
          <div className="app-layout">
            <Header />
            <Routes>
              <Route path="/auth" element={<AuthPage />} />
              <Route path="/" element={
                <ProtectedRoute><Landing /></ProtectedRoute>
              } />
              <Route path="/scan/:scanId" element={
                <ProtectedRoute><ScanDashboard /></ProtectedRoute>
              } />
              <Route path="*" element={<Navigate to="/" replace />} />
            </Routes>
          </div>
        </ToastProvider>
      </AuthProvider>
    </BrowserRouter>
  );
}
