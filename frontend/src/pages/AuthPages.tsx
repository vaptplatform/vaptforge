import React, { useState, useEffect } from 'react';
import { useNavigate, useSearchParams, Link } from 'react-router-dom';
import {
  Shield, Eye, EyeOff, Loader2, ArrowLeft,
  Mail, CheckCircle, KeyRound, AlertTriangle,
} from 'lucide-react';
import axios from 'axios';
import { authAPI } from '../services/api';
import { useAuthStore, useToastStore } from '../store';

const api = axios.create({ baseURL: '/api/v1' });

/* ── Shared card wrapper ─────────────────────────────────────── */
function AuthCard({ children }: { children: React.ReactNode }) {
  return (
    <div style={{
      minHeight: '100vh',
      background: 'linear-gradient(135deg,#080C14 0%,#0F172A 50%,#080C14 100%)',
      display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 20,
    }}>
      <div style={{ width: '100%', maxWidth: 440 }}>
        <div style={{ textAlign: 'center', marginBottom: 32 }}>
          <div style={{ display: 'inline-flex', alignItems: 'center', gap: 10, marginBottom: 10 }}>
            <div style={{
              width: 44, height: 44,
              background: 'linear-gradient(135deg,#1E40AF,#0EA5E9)',
              borderRadius: 12, display: 'flex', alignItems: 'center',
              justifyContent: 'center', boxShadow: '0 0 20px rgba(59,130,246,0.4)',
            }}>
              <Shield size={22} color="white" />
            </div>
            <span style={{ fontSize: 24, fontWeight: 800, color: '#E2E8F0', letterSpacing: '-0.5px' }}>
              VAPT<span style={{ color: '#60A5FA' }}>Forge</span>
            </span>
          </div>
          <p style={{ fontSize: 12, color: '#475569', letterSpacing: '0.5px' }}>
            ENTERPRISE SECURITY PLATFORM
          </p>
        </div>
        {children}
      </div>
    </div>
  );
}

function Field({ label, type, value, onChange, placeholder, right, error }: {
  label: string; type: string; value: string;
  onChange: (v: string) => void; placeholder?: string;
  right?: React.ReactNode; error?: string;
}) {
  return (
    <div>
      <label style={{ fontSize: 11, color: '#64748B', display: 'block', marginBottom: 6,
        fontWeight: 600, letterSpacing: '0.5px' }}>{label}</label>
      <div style={{ position: 'relative' }}>
        <input className="input" type={type} placeholder={placeholder} value={value}
          onChange={e => onChange(e.target.value)}
          style={{ paddingRight: right ? 40 : undefined,
            borderColor: error ? '#EF4444' : undefined }} />
        {right && (
          <span style={{ position: 'absolute', right: 12, top: '50%',
            transform: 'translateY(-50%)', color: '#64748B', cursor: 'pointer' }}>
            {right}
          </span>
        )}
      </div>
      {error && <p style={{ fontSize: 11, color: '#EF4444', marginTop: 4 }}>{error}</p>}
    </div>
  );
}

/* ── Login Page ─────────────────────────────────────────────── */
export function LoginPage() {
  const navigate = useNavigate();
  const setAuth  = useAuthStore(s => s.setAuth);
  const addToast = useToastStore(s => s.add);
  const [form, setForm]     = useState({ email: '', password: '' });
  const [showPw, setShowPw] = useState(false);
  const [loading, setLoad]  = useState(false);
  const set = (k: string) => (v: string) => setForm(f => ({ ...f, [k]: v }));

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoad(true);
    try {
      const { data } = await authAPI.login(form.email, form.password);
      setAuth(data.user, data.access_token);
      navigate('/dashboard');
    } catch (err: any) {
      addToast('error', err.response?.data?.detail ?? 'Invalid email or password');
    } finally { setLoad(false); }
  };

  return (
    <AuthCard>
      <form onSubmit={submit} className="card"
        style={{ display: 'flex', flexDirection: 'column', gap: 18,
          background: 'rgba(13,18,32,0.9)', border: '1px solid rgba(99,179,237,0.15)' }}>
        <div>
          <h1 style={{ fontSize: 20, fontWeight: 700, color: '#E2E8F0', marginBottom: 4 }}>Sign in</h1>
          <p style={{ fontSize: 12, color: '#475569' }}>
            Default: <code style={{ fontFamily: 'monospace', color: '#60A5FA',
              background: 'rgba(59,130,246,0.1)', padding: '1px 6px', borderRadius: 4 }}>
              admin@vapt.local</code>{' / '}
            <code style={{ fontFamily: 'monospace', color: '#60A5FA',
              background: 'rgba(59,130,246,0.1)', padding: '1px 6px', borderRadius: 4 }}>
              ChangeMe!2024</code>
          </p>
        </div>
        <Field label="EMAIL ADDRESS" type="email" value={form.email}
          onChange={set('email')} placeholder="admin@company.com" />
        <Field label="PASSWORD" type={showPw ? 'text' : 'password'} value={form.password}
          onChange={set('password')} placeholder="••••••••"
          right={<span onClick={() => setShowPw(!showPw)}>
            {showPw ? <EyeOff size={14}/> : <Eye size={14}/>}
          </span>} />
        <button className="btn btn-primary" type="submit" disabled={loading}
          style={{ width: '100%', justifyContent: 'center', padding: '11px' }}>
          {loading
            ? <><Loader2 size={14} className="animate-spin"/> Signing in…</>
            : 'Sign In →'}
        </button>
        <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12, color: '#475569' }}>
          <Link to="/forgot-password" style={{ color: '#60A5FA', textDecoration: 'none' }}>
            Forgot password?
          </Link>
          <Link to="/register" style={{ color: '#60A5FA', textDecoration: 'none' }}>
            Create organization →
          </Link>
        </div>
      </form>
    </AuthCard>
  );
}

/* ── Register Page ──────────────────────────────────────────── */
export function RegisterPage() {
  const navigate = useNavigate();
  const setAuth  = useAuthStore(s => s.setAuth);
  const addToast = useToastStore(s => s.add);
  const [form, setForm]  = useState({ email: '', password: '', full_name: '', org_name: '' });
  const [loading, setLoad] = useState(false);
  const set = (k: string) => (v: string) => setForm(f => ({ ...f, [k]: v }));

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (form.password.length < 8) {
      addToast('error', 'Password must be at least 8 characters'); return;
    }
    setLoad(true);
    try {
      const { data } = await authAPI.register(form.email, form.password, form.full_name, form.org_name);
      setAuth(data.user, data.access_token);
      addToast('success', 'Organization created! Welcome to VAPTForge.');
      navigate('/dashboard');
    } catch (err: any) {
      addToast('error', err.response?.data?.detail ?? 'Registration failed');
    } finally { setLoad(false); }
  };

  return (
    <AuthCard>
      <form onSubmit={submit} className="card"
        style={{ display: 'flex', flexDirection: 'column', gap: 16,
          background: 'rgba(13,18,32,0.9)', border: '1px solid rgba(99,179,237,0.15)' }}>
        <div>
          <h1 style={{ fontSize: 20, fontWeight: 700, color: '#E2E8F0', marginBottom: 4 }}>Create Organization</h1>
          <p style={{ fontSize: 12, color: '#475569' }}>Start your free enterprise security assessment</p>
        </div>
        <Field label="ORGANIZATION NAME" type="text" value={form.org_name}
          onChange={set('org_name')} placeholder="Acme Security Team" />
        <Field label="YOUR FULL NAME" type="text" value={form.full_name}
          onChange={set('full_name')} placeholder="Jane Smith" />
        <Field label="EMAIL ADDRESS" type="email" value={form.email}
          onChange={set('email')} placeholder="admin@company.com" />
        <Field label="PASSWORD (min 8 chars)" type="password" value={form.password}
          onChange={set('password')} placeholder="••••••••" />
        <button className="btn btn-primary" type="submit" disabled={loading}
          style={{ width: '100%', justifyContent: 'center', padding: '11px' }}>
          {loading ? <><Loader2 size={14}/> Creating…</> : 'Create Account →'}
        </button>
        <p style={{ textAlign: 'center', fontSize: 12, color: '#475569' }}>
          Already have an account?{' '}
          <Link to="/login" style={{ color: '#60A5FA', textDecoration: 'none' }}>Sign in</Link>
        </p>
      </form>
    </AuthCard>
  );
}

/* ── Forgot Password Page ───────────────────────────────────── */
export function ForgotPasswordPage() {
  const navigate = useNavigate();
  const [email, setEmail]     = useState('');
  const [loading, setLoad]    = useState(false);
  const [sent, setSent]       = useState(false);
  const [error, setError]     = useState('');

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    const trimmed = email.trim().toLowerCase();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(trimmed)) {
      setError('Enter a valid email address'); return;
    }
    setError('');
    setLoad(true);
    try {
      await api.post('/auth/forgot-password', { email: trimmed });
      setSent(true);
    } catch (err: any) {
      if (err.response?.status === 429) {
        setError('Too many requests. Please wait 1 hour before trying again.');
      } else {
        // Still show sent UI to prevent email enumeration
        setSent(true);
      }
    } finally { setLoad(false); }
  };

  return (
    <AuthCard>
      <div className="card"
        style={{ display: 'flex', flexDirection: 'column', gap: 20,
          background: 'rgba(13,18,32,0.9)', border: '1px solid rgba(99,179,237,0.15)' }}>

        <button onClick={() => navigate('/login')}
          style={{ display: 'flex', alignItems: 'center', gap: 6, background: 'none',
            border: 'none', color: '#64748B', cursor: 'pointer', fontSize: 12, padding: 0, width: 'fit-content' }}>
          <ArrowLeft size={13}/> Back to login
        </button>

        {!sent ? (
          <form onSubmit={submit} style={{ display: 'flex', flexDirection: 'column', gap: 18 }}>
            <div>
              <h1 style={{ fontSize: 20, fontWeight: 700, color: '#E2E8F0', marginBottom: 6 }}>
                Reset Password
              </h1>
              <p style={{ fontSize: 13, color: '#64748B', lineHeight: 1.6 }}>
                Enter your account email. If it exists, we'll send a secure reset link valid for 30 minutes.
              </p>
            </div>

            <div style={{ display: 'flex', gap: 10, alignItems: 'center',
              background: 'rgba(59,130,246,0.06)', border: '1px solid rgba(59,130,246,0.2)',
              borderRadius: 8, padding: '10px 14px' }}>
              <Mail size={15} style={{ color: '#60A5FA', flexShrink: 0 }}/>
              <input className="input" type="email" placeholder="your@email.com"
                value={email} onChange={e => setEmail(e.target.value)}
                style={{ background: 'transparent', border: 'none', padding: 0, flex: 1 }}
                required />
            </div>
            {error && (
              <div style={{ display: 'flex', gap: 8, alignItems: 'center', background: 'rgba(239,68,68,0.08)',
                border: '1px solid rgba(239,68,68,0.25)', borderRadius: 8, padding: '10px 14px' }}>
                <AlertTriangle size={13} style={{ color: '#FCA5A5', flexShrink: 0 }}/>
                <p style={{ fontSize: 12, color: '#FCA5A5' }}>{error}</p>
              </div>
            )}

            <button className="btn btn-primary" type="submit" disabled={loading}
              style={{ width: '100%', justifyContent: 'center', padding: '11px' }}>
              {loading
                ? <><Loader2 size={14} className="animate-spin"/> Sending…</>
                : 'Send Reset Link'}
            </button>

            <div style={{ background: 'rgba(234,179,8,0.06)', border: '1px solid rgba(234,179,8,0.2)',
              borderRadius: 8, padding: '12px 14px', fontSize: 12, color: '#92400E' }}>
              <strong style={{ color: '#D97706' }}>Admin note:</strong>{' '}
              Configure <code style={{ fontFamily: 'monospace', color: '#60A5FA' }}>SMTP_HOST</code>,{' '}
              <code style={{ fontFamily: 'monospace', color: '#60A5FA' }}>SMTP_USER</code>,{' '}
              <code style={{ fontFamily: 'monospace', color: '#60A5FA' }}>SMTP_PASS</code>{' '}
              in <code style={{ fontFamily: 'monospace', color: '#60A5FA' }}>backend/.env</code>{' '}
              for real email delivery.
            </div>
          </form>
        ) : (
          <div style={{ textAlign: 'center', padding: '20px 0',
            display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 16 }}>
            <div style={{ width: 56, height: 56,
              background: 'rgba(34,197,94,0.1)', border: '1px solid rgba(34,197,94,0.3)',
              borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              <CheckCircle size={28} style={{ color: '#22C55E' }}/>
            </div>
            <div>
              <p style={{ fontSize: 16, fontWeight: 700, color: '#E2E8F0', marginBottom: 6 }}>
                Check your email
              </p>
              <p style={{ fontSize: 13, color: '#64748B', lineHeight: 1.6 }}>
                If <strong style={{ color: '#60A5FA' }}>{email}</strong> is registered,<br/>
                a password reset link (valid 30 min) has been sent.
              </p>
            </div>
            <button onClick={() => navigate('/login')} className="btn btn-outline" style={{ marginTop: 8 }}>
              Back to Login
            </button>
          </div>
        )}
      </div>
    </AuthCard>
  );
}

/* ── Reset Password Page ─────────────────────────────────────── */
export function ResetPasswordPage() {
  const navigate      = useNavigate();
  const [params]      = useSearchParams();
  const token         = params.get('token') ?? '';

  const [pw, setPw]         = useState('');
  const [pw2, setPw2]       = useState('');
  const [showPw, setShowPw] = useState(false);
  const [loading, setLoad]  = useState(false);
  const [done, setDone]     = useState(false);
  const [error, setError]   = useState('');

  useEffect(() => {
    if (!token) setError('Invalid or missing reset token. Request a new link.');
  }, [token]);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (pw.length < 8) { setError('Password must be at least 8 characters'); return; }
    if (pw !== pw2)    { setError('Passwords do not match'); return; }
    setError('');
    setLoad(true);
    try {
      await api.post('/auth/reset-password', { token, new_password: pw });
      setDone(true);
    } catch (err: any) {
      setError(err.response?.data?.detail ?? 'Reset failed. The link may have expired.');
    } finally { setLoad(false); }
  };

  return (
    <AuthCard>
      <div className="card"
        style={{ display: 'flex', flexDirection: 'column', gap: 20,
          background: 'rgba(13,18,32,0.9)', border: '1px solid rgba(99,179,237,0.15)' }}>

        {done ? (
          <div style={{ textAlign: 'center', padding: '20px 0',
            display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 16 }}>
            <div style={{ width: 56, height: 56,
              background: 'rgba(34,197,94,0.1)', border: '1px solid rgba(34,197,94,0.3)',
              borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              <CheckCircle size={28} style={{ color: '#22C55E' }}/>
            </div>
            <div>
              <p style={{ fontSize: 16, fontWeight: 700, color: '#E2E8F0', marginBottom: 6 }}>
                Password Reset!
              </p>
              <p style={{ fontSize: 13, color: '#64748B', lineHeight: 1.6 }}>
                Your password has been updated successfully.<br/>
                You can now sign in with your new password.
              </p>
            </div>
            <button onClick={() => navigate('/login')} className="btn btn-primary">
              Go to Login →
            </button>
          </div>
        ) : (
          <form onSubmit={submit} style={{ display: 'flex', flexDirection: 'column', gap: 18 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <KeyRound size={20} style={{ color: '#60A5FA' }}/>
              <div>
                <h1 style={{ fontSize: 20, fontWeight: 700, color: '#E2E8F0' }}>Set New Password</h1>
                <p style={{ fontSize: 12, color: '#64748B' }}>Enter and confirm your new password</p>
              </div>
            </div>

            {!token && (
              <div style={{ background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.25)',
                borderRadius: 8, padding: '12px 14px', display: 'flex', gap: 8, alignItems: 'center' }}>
                <AlertTriangle size={14} style={{ color: '#FCA5A5' }}/>
                <p style={{ fontSize: 12, color: '#FCA5A5' }}>
                  No reset token found. Please use the link from your email.
                </p>
              </div>
            )}

            <Field label="NEW PASSWORD (min 8 chars)"
              type={showPw ? 'text' : 'password'}
              value={pw} onChange={setPw} placeholder="••••••••"
              right={<span onClick={() => setShowPw(!showPw)}>
                {showPw ? <EyeOff size={14}/> : <Eye size={14}/>}
              </span>} />

            <Field label="CONFIRM NEW PASSWORD"
              type={showPw ? 'text' : 'password'}
              value={pw2} onChange={setPw2} placeholder="••••••••"
              error={pw2 && pw !== pw2 ? 'Passwords do not match' : undefined} />

            {/* Password strength indicator */}
            {pw.length > 0 && (
              <div>
                <div style={{ display: 'flex', gap: 4 }}>
                  {[1,2,3,4].map(i => (
                    <div key={i} style={{ flex: 1, height: 3, borderRadius: 2,
                      background: pw.length >= i * 3
                        ? i <= 1 ? '#EF4444' : i === 2 ? '#F97316' : i === 3 ? '#EAB308' : '#22C55E'
                        : 'var(--surface3)' }} />
                  ))}
                </div>
                <p style={{ fontSize: 10, color: 'var(--text3)', marginTop: 3 }}>
                  {pw.length < 8 ? 'Too short' : pw.length < 12 ? 'Moderate' : 'Strong'}
                </p>
              </div>
            )}

            {error && (
              <div style={{ background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.25)',
                borderRadius: 8, padding: '10px 14px', display: 'flex', gap: 8, alignItems: 'center' }}>
                <AlertTriangle size={13} style={{ color: '#FCA5A5', flexShrink: 0 }}/>
                <p style={{ fontSize: 12, color: '#FCA5A5' }}>{error}</p>
              </div>
            )}

            <button className="btn btn-primary" type="submit"
              disabled={loading || !token}
              style={{ width: '100%', justifyContent: 'center', padding: '11px' }}>
              {loading
                ? <><Loader2 size={14} className="animate-spin"/> Updating…</>
                : 'Set New Password'}
            </button>

            <p style={{ textAlign: 'center', fontSize: 12, color: '#475569' }}>
              Remember your password?{' '}
              <Link to="/login" style={{ color: '#60A5FA', textDecoration: 'none' }}>Sign in</Link>
            </p>
          </form>
        )}
      </div>
    </AuthCard>
  );
}
