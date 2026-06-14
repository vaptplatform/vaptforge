import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Play, ShieldCheck, AlertTriangle, CheckCircle2,
  Lock, Globe, Cpu, Settings2, ChevronRight, Loader2
} from 'lucide-react';
import { scansAPI, domainsAPI } from '../services/api';
import { useToastStore, useUIStore } from '../store';
import type { Domain, ScanProfile } from '../types';

const PROFILES: { value: ScanProfile; label: string; desc: string; icon: string }[] = [
  { value: 'full_owasp',   label: 'Full OWASP Top 10', desc: 'All 10 modules — recommended for govt assessment', icon: '🛡️' },
  { value: 'quick',        label: 'Quick Scan',         desc: 'Headers + common issues (~5 min)',                icon: '⚡' },
  { value: 'api_security', label: 'API Security',       desc: 'REST/GraphQL endpoints',                         icon: '🔌' },
  { value: 'auth_deep',    label: 'Auth Deep Dive',     desc: 'JWT, session, auth failures',                    icon: '🔐' },
  { value: 'passive_only', label: 'Passive Only',       desc: 'Headers and static analysis only',               icon: '👁️' },
];

const MODULES = [
  { id: 'a01_broken_access_control', label: 'A01 – Broken Access Control',          default: true },
  { id: 'a02_crypto_failures',        label: 'A02 – Cryptographic Failures',         default: true },
  { id: 'a03_injection',              label: 'A03 – Injection (SQLi / XSS / SSTI)', default: true },
  { id: 'a04_insecure_design',        label: 'A04 – Insecure Design',               default: true },
  { id: 'a05_security_misconfig',     label: 'A05 – Security Misconfiguration',      default: true },
  { id: 'a06_vulnerable_components',  label: 'A06 – Vulnerable Components',          default: true },
  { id: 'a07_auth_failures',          label: 'A07 – Authentication Failures',        default: true },
  { id: 'a08_integrity_failures',     label: 'A08 – Integrity Failures (SRI)',       default: true },
  { id: 'a09_logging_failures',       label: 'A09 – Logging & Monitoring Failures',  default: true },
  { id: 'a10_ssrf',                   label: 'A10 – SSRF',                          default: true },
];

const OPTIONS = [
  { key: 'subdomain_discovery', label: 'Subdomain Discovery',       default: true  },
  { key: 'api_scan',            label: 'API Endpoint Scanner',      default: true  },
  { key: 'jwt_analysis',        label: 'JWT Security Analysis',     default: true  },
  { key: 'waf_detection',       label: 'WAF Detection',             default: false },
  { key: 'dom_scan',            label: 'DOM / Headless Browser Scan', default: true },
  { key: 'oob_detection',       label: 'Out-of-Band Blind Detection', default: true },
  { key: 'cve_mapping',         label: 'CVE Mapping',               default: true  },
];

function StepIndicator({ step, current }: { step: number; current: number }) {
  const done   = current > step;
  const active = current === step;
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
      <div style={{
        width: 28, height: 28, borderRadius: '50%', display: 'flex',
        alignItems: 'center', justifyContent: 'center', fontSize: 12, fontWeight: 700,
        background: done ? '#22C55E' : active ? 'var(--accent)' : 'var(--surface2)',
        color: done || active ? 'white' : 'var(--text3)',
        border: `2px solid ${done ? '#22C55E' : active ? 'var(--accent)' : 'var(--border)'}`,
        transition: 'all 0.3s',
        flexShrink: 0,
      }}>
        {done ? <CheckCircle2 size={14} /> : step}
      </div>
    </div>
  );
}

export default function NewScanPage() {
  const navigate  = useNavigate();
  const addToast  = useToastStore(s => s.add);
  const setActive = useUIStore(s => s.setActiveScan);

  const [domains,       setDomains]       = useState<Domain[]>([]);
  const [url,           setUrl]           = useState('https://');
  const [profile,       setProfile]       = useState<ScanProfile>('full_owasp');
  const [modules,       setModules]       = useState<Record<string, boolean>>(
    Object.fromEntries(MODULES.map(m => [m.id, m.default]))
  );
  const [options,       setOptions]       = useState<Record<string, boolean>>(
    Object.fromEntries(OPTIONS.map(o => [o.key, o.default]))
  );
  const [loading,       setLoading]       = useState(false);
  const [authConfirmed, setAuthConfirmed] = useState(false);

  // ── Authenticated scanning state (declared ONCE) ───────────────────────────
  const [authType,     setAuthType]     = useState<string>('none');
  const [authUsername, setAuthUsername] = useState('');
  const [authPassword, setAuthPassword] = useState('');
  const [authToken,    setAuthToken]    = useState('');
  const [authLoginUrl, setAuthLoginUrl] = useState('');
  const [showAuthPass, setShowAuthPass] = useState(false);

  useEffect(() => {
    domainsAPI.list().then(r =>
      setDomains(r.data.domains.filter((d: Domain) => d.status === 'verified'))
    ).catch(() => {});
  }, []);

  const parsedDomain = (() => { try { return new URL(url).hostname; } catch { return ''; } })();
  const isValidUrl   = url.startsWith('http://') || url.startsWith('https://');
  const isVerified   = domains.some(d =>
    d.domain === parsedDomain || parsedDomain.endsWith('.' + d.domain)
  );
  const isHttp = url.startsWith('http://');

  const currentStep = !isValidUrl || !parsedDomain ? 1
    : !isVerified ? 1
    : !authConfirmed ? 2
    : 3;

  const canLaunch = isVerified && authConfirmed && isValidUrl && !loading;

  const toggleModule = (id: string)  => setModules(prev => ({ ...prev, [id]: !prev[id] }));
  const toggleOption = (key: string) => setOptions(prev => ({ ...prev, [key]: !prev[key] }));
  const selectAll    = () => setModules(Object.fromEntries(MODULES.map(m => [m.id, true])));
  const selectNone   = () => setModules(Object.fromEntries(MODULES.map(m => [m.id, false])));

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!canLaunch) return;
    setLoading(true);
    try {
      const { data } = await scansAPI.create({
        target_url: url, profile,
        enabled_modules: modules,
        scan_options: {
          ...options,
          auth: authType !== 'none' ? {
            auth_type: authType,
            username:  authUsername,
            password:  authPassword,
            token:     authToken,
            login_url: authLoginUrl,
          } : { auth_type: 'none' },
        },
      });
      setActive(data.id);
      addToast('success', `Scan launched for ${parsedDomain}`);
      navigate(`/scans/${data.id}`);
    } catch (err: any) {
      addToast('error', err.response?.data?.detail ?? 'Failed to start scan');
    } finally {
      setLoading(false);
    }
  };

  return (
    <form onSubmit={submit} className="fade-up"
      style={{ display: 'flex', flexDirection: 'column', gap: 20, maxWidth: 960 }}>

      {/* ── Header ──────────────────────────────────────────────────────────── */}
      <div>
        <h1 style={{ fontSize: 20, fontWeight: 800, color: 'var(--text)' }}>New Vulnerability Scan</h1>
        <p style={{ fontSize: 12, color: 'var(--text3)', marginTop: 2 }}>
          Government-grade VAPT assessment — OWASP Top 10 with CVSS v3 scoring and raw HTTP evidence
        </p>
      </div>

      {/* ── Step progress ────────────────────────────────────────────────────── */}
      <div style={{
        background: 'var(--surface)', border: '1px solid var(--border)',
        borderRadius: 12, padding: '16px 20px',
        display: 'flex', alignItems: 'center', gap: 12,
      }}>
        <StepIndicator step={1} current={currentStep} />
        <div style={{ flex: 1, height: 2, background: currentStep > 1 ? '#22C55E' : 'var(--border)', borderRadius: 2, transition: 'background 0.3s' }} />
        <StepIndicator step={2} current={currentStep} />
        <div style={{ flex: 1, height: 2, background: currentStep > 2 ? '#22C55E' : 'var(--border)', borderRadius: 2, transition: 'background 0.3s' }} />
        <StepIndicator step={3} current={currentStep} />
        <div style={{ marginLeft: 12, fontSize: 12, color: 'var(--text3)' }}>
          {currentStep === 1 && <span>Enter a verified target URL to continue</span>}
          {currentStep === 2 && <span style={{ color: '#22C55E' }}>✓ Domain verified — confirm authorization</span>}
          {currentStep === 3 && <span style={{ color: 'var(--accent)' }}>Ready to launch scan</span>}
        </div>
      </div>

      {/* ── Target Configuration ─────────────────────────────────────────────── */}
      <div className="card" style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <Globe size={16} color="var(--accent)" />
          <p className="card-title" style={{ marginBottom: 0 }}>Target Configuration</p>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: 12 }}>
          <div>
            <label style={{ fontSize: 11, color: 'var(--text3)', display: 'block', marginBottom: 5, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.5px' }}>
              Target URL
            </label>
            <div style={{ position: 'relative' }}>
              <input
                className="input"
                value={url}
                onChange={e => { setUrl(e.target.value); setAuthConfirmed(false); }}
                placeholder="https://app.example.com"
                required
                style={{ paddingRight: isVerified ? 36 : 12 }}
              />
              {isVerified && (
                <ShieldCheck size={16} color="#22C55E"
                  style={{ position: 'absolute', right: 10, top: '50%', transform: 'translateY(-50%)' }} />
              )}
            </div>
            {isHttp && (
              <div style={{
                display: 'flex', alignItems: 'flex-start', gap: 8, marginTop: 8,
                background: 'rgba(245,158,11,0.08)', border: '1px solid rgba(245,158,11,0.3)',
                borderRadius: 8, padding: '9px 12px',
              }}>
                <AlertTriangle size={13} style={{ color: '#F59E0B', marginTop: 1, flexShrink: 0 }} />
                <p style={{ fontSize: 12, color: '#FCD34D', lineHeight: 1.6 }}>
                  <strong>Plain HTTP detected.</strong> All data transmitted in cleartext.
                  This will be flagged as a HIGH severity OWASP A02 finding.
                </p>
              </div>
            )}
          </div>

          <div>
            <label style={{ fontSize: 11, color: 'var(--text3)', display: 'block', marginBottom: 5, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.5px' }}>
              Scan Profile
            </label>
            <select className="input" value={profile} onChange={e => setProfile(e.target.value as ScanProfile)}>
              {PROFILES.map(p => (
                <option key={p.value} value={p.value}>{p.icon} {p.label}</option>
              ))}
            </select>
            <p style={{ fontSize: 11, color: 'var(--text3)', marginTop: 6 }}>
              {PROFILES.find(p => p.value === profile)?.desc}
            </p>
          </div>
        </div>

        {/* Domain verification status */}
        <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
          <span style={{
            display: 'inline-flex', alignItems: 'center', gap: 6,
            padding: '5px 14px', borderRadius: 20, fontSize: 12, fontFamily: 'monospace',
            background: isVerified ? 'rgba(34,197,94,0.12)' : parsedDomain ? 'rgba(239,68,68,0.08)' : 'var(--surface2)',
            color:      isVerified ? '#86EFAC'              : parsedDomain ? '#FCA5A5'               : 'var(--text3)',
            border:     `1px solid ${isVerified ? 'rgba(34,197,94,0.3)' : parsedDomain ? 'rgba(239,68,68,0.25)' : 'var(--border)'}`,
            fontWeight: 600,
          }}>
            {isVerified
              ? <><ShieldCheck size={13} /> {parsedDomain} — Verified & Authorized ✓</>
              : parsedDomain
                ? <><AlertTriangle size={13} /> {parsedDomain} — Not in whitelist</>
                : <><Globe size={13} /> Enter a URL above</>
            }
          </span>
          {!isVerified && parsedDomain && (
            <button type="button" onClick={() => navigate('/settings')}
              style={{
                display: 'inline-flex', alignItems: 'center', gap: 5,
                fontSize: 11, color: 'var(--accent)', background: 'rgba(59,130,246,0.08)',
                border: '1px solid rgba(59,130,246,0.25)', borderRadius: 6,
                padding: '4px 10px', cursor: 'pointer',
              }}>
              Add to whitelist <ChevronRight size={11} />
            </button>
          )}
        </div>

        {/* Verified domains quick list */}
        {domains.length > 0 && (
          <div style={{ background: 'var(--surface2)', borderRadius: 8, padding: '10px 14px' }}>
            <p style={{ fontSize: 10, color: 'var(--text3)', fontWeight: 600, marginBottom: 8, textTransform: 'uppercase', letterSpacing: '0.5px' }}>
              Your Verified Domains
            </p>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
              {domains.map(d => (
                <button key={d.id} type="button"
                  onClick={() => { setUrl(`https://${d.domain}`); setAuthConfirmed(false); }}
                  style={{
                    display: 'inline-flex', alignItems: 'center', gap: 5,
                    fontFamily: 'monospace', fontSize: 11,
                    color: parsedDomain === d.domain ? 'white' : '#86EFAC',
                    background: parsedDomain === d.domain ? '#22C55E' : 'rgba(34,197,94,0.08)',
                    border: `1px solid ${parsedDomain === d.domain ? '#22C55E' : 'rgba(34,197,94,0.25)'}`,
                    borderRadius: 6, padding: '3px 10px', cursor: 'pointer',
                  }}>
                  <span style={{ width: 5, height: 5, borderRadius: '50%', background: parsedDomain === d.domain ? 'white' : '#22C55E', display: 'inline-block' }} />
                  {d.domain}
                </button>
              ))}
            </div>
          </div>
        )}

        {domains.length === 0 && (
          <div style={{ background: 'rgba(239,68,68,0.06)', border: '1px solid rgba(239,68,68,0.2)', borderRadius: 8, padding: '12px 14px' }}>
            <p style={{ fontSize: 12, color: '#FCA5A5' }}>
              No verified domains yet.{' '}
              <span style={{ color: 'var(--accent)', cursor: 'pointer', textDecoration: 'underline' }}
                onClick={() => navigate('/settings')}>
                Go to Settings → Domains
              </span>{' '}
              to add and verify a domain before scanning.
            </p>
          </div>
        )}
      </div>

      {/* ── Authorization confirmation ────────────────────────────────────────── */}
      {isVerified && (
        <div style={{
          background: authConfirmed ? 'rgba(34,197,94,0.06)' : 'rgba(239,68,68,0.06)',
          border: `1px solid ${authConfirmed ? 'rgba(34,197,94,0.25)' : 'rgba(239,68,68,0.25)'}`,
          borderRadius: 12, padding: '16px 20px', transition: 'all 0.3s',
        }}>
          <label style={{ display: 'flex', alignItems: 'flex-start', gap: 14, cursor: 'pointer' }}>
            <input
              type="checkbox"
              checked={authConfirmed}
              onChange={e => setAuthConfirmed(e.target.checked)}
              style={{ width: 18, height: 18, accentColor: '#22C55E', cursor: 'pointer', marginTop: 2, flexShrink: 0 }}
            />
            <div>
              <p style={{ fontSize: 13, fontWeight: 700, color: authConfirmed ? '#86EFAC' : '#FCA5A5', marginBottom: 4 }}>
                {authConfirmed
                  ? '✓ Authorization Confirmed — Ready to Launch'
                  : '⚠ Authorization Confirmation Required'}
              </p>
              <p style={{ fontSize: 12, color: 'var(--text2)', lineHeight: 1.7 }}>
                I confirm that I have <strong>explicit written authorization</strong> to conduct
                vulnerability assessment on <strong style={{ fontFamily: 'monospace', color: '#86EFAC' }}>{parsedDomain}</strong>.
                I understand that unauthorized scanning is illegal under the Computer Fraud and Abuse Act
                and equivalent legislation. All activity is logged, timestamped, and audited.
                This assessment is conducted for legitimate security testing purposes only.
              </p>
            </div>
          </label>
        </div>
      )}

      {/* ── Modules + Options ────────────────────────────────────────────────── */}
      {isVerified && (
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
          {/* OWASP Modules */}
          <div className="card">
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 12 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <Cpu size={15} color="var(--accent)" />
                <p className="card-title" style={{ marginBottom: 0 }}>OWASP Detection Modules</p>
              </div>
              <div style={{ display: 'flex', gap: 6 }}>
                <button type="button" className="btn btn-ghost btn-sm" onClick={selectAll}
                  style={{ fontSize: 10, padding: '2px 8px' }}>All</button>
                <button type="button" className="btn btn-ghost btn-sm" onClick={selectNone}
                  style={{ fontSize: 10, padding: '2px 8px' }}>None</button>
              </div>
            </div>
            {MODULES.map(m => (
              <label key={m.id} style={{
                display: 'flex', alignItems: 'center', gap: 10, cursor: 'pointer',
                padding: '6px 0', borderBottom: '1px solid var(--border)',
              }}>
                <input type="checkbox" checked={modules[m.id]} onChange={() => toggleModule(m.id)}
                  style={{ accentColor: 'var(--accent)', width: 14, height: 14 }} />
                <span style={{ fontSize: 12, color: modules[m.id] ? 'var(--text)' : 'var(--text3)', fontFamily: 'monospace', transition: 'color 0.2s' }}>
                  {m.label}
                </span>
                {modules[m.id] && <span style={{ marginLeft: 'auto', width: 6, height: 6, borderRadius: '50%', background: '#22C55E', flexShrink: 0 }} />}
              </label>
            ))}
            <p style={{ fontSize: 10, color: 'var(--text3)', marginTop: 10 }}>
              {Object.values(modules).filter(Boolean).length}/{MODULES.length} modules active
            </p>
          </div>

          {/* Advanced Options */}
          <div className="card">
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12 }}>
              <Settings2 size={15} color="var(--accent)" />
              <p className="card-title" style={{ marginBottom: 0 }}>Advanced Options</p>
            </div>
            {OPTIONS.map(o => (
              <label key={o.key} style={{
                display: 'flex', alignItems: 'center', gap: 10,
                cursor: 'pointer', padding: '8px 0', borderBottom: '1px solid var(--border)',
              }}>
                <input type="checkbox" checked={options[o.key]} onChange={() => toggleOption(o.key)}
                  style={{ accentColor: 'var(--accent)', width: 14, height: 14 }} />
                <span style={{ fontSize: 13, color: options[o.key] ? 'var(--text)' : 'var(--text3)', transition: 'color 0.2s' }}>
                  {o.label}
                </span>
              </label>
            ))}
            <div style={{
              marginTop: 14, background: 'rgba(59,130,246,0.06)',
              border: '1px solid rgba(59,130,246,0.2)', borderRadius: 8, padding: '10px 12px',
            }}>
              <p style={{ fontSize: 10, color: 'var(--accent)', fontWeight: 700, marginBottom: 6, textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                Govt-Grade Report Includes
              </p>
              {[
                'CVSS v3.1 score per finding',
                'Raw HTTP request + response evidence',
                'Remediation priority matrix',
                'OWASP Top 10 coverage table',
                'Executive summary + risk rating',
              ].map(item => (
                <div key={item} style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 3 }}>
                  <span style={{ color: '#22C55E', fontSize: 10 }}>✓</span>
                  <span style={{ fontSize: 11, color: 'var(--text2)' }}>{item}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* ── Authenticated Scanning ───────────────────────────────────────────── */}
      {isVerified && (
        <div className="card">
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 14 }}>
            <Lock size={15} color="var(--accent)" />
            <p className="card-title" style={{ marginBottom: 0 }}>
              Authenticated Scanning
              <span style={{ fontSize: 10, color: '#22C55E', fontWeight: 700, marginLeft: 8 }}>+20% Detection</span>
              <span style={{ fontSize: 11, color: 'var(--text3)', fontWeight: 400, marginLeft: 6 }}>(Optional — scans behind login)</span>
            </p>
          </div>
          <p style={{ fontSize: 12, color: 'var(--text2)', marginBottom: 12, lineHeight: 1.7 }}>
            Optionally provide login credentials to scan behind authentication.
            Detects IDOR, privilege escalation, and post-login vulnerabilities invisible to anonymous scans.
          </p>

          {/* Auth type pill selector */}
          <div style={{ display: 'flex', gap: 8, marginBottom: 14, flexWrap: 'wrap' }}>
            {[
              { val: 'none',    label: 'Anonymous (default)' },
              { val: 'form',    label: 'Form Login'          },
              { val: 'bearer',  label: 'Bearer Token'        },
              { val: 'basic',   label: 'Basic Auth'          },
              { val: 'apikey',  label: 'API Key'             },
            ].map(({ val, label }) => (
              <button key={val} type="button" onClick={() => setAuthType(val)}
                style={{
                  padding: '5px 14px', borderRadius: 20, fontSize: 12, fontWeight: 600,
                  cursor: 'pointer', transition: 'all 0.2s',
                  background: authType === val ? 'var(--accent)' : 'var(--surface2)',
                  color:      authType === val ? 'white'         : 'var(--text2)',
                  border: `1px solid ${authType === val ? 'var(--accent)' : 'var(--border)'}`,
                }}>
                {label}
              </button>
            ))}
          </div>

          {/* Form login fields */}
          {authType === 'form' && (
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
              <div>
                <label style={{ fontSize: 11, color: 'var(--text3)', display: 'block', marginBottom: 4, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                  Login URL (optional — auto-detected)
                </label>
                <input className="input" placeholder="https://app.example.com/login"
                  value={authLoginUrl} onChange={e => setAuthLoginUrl(e.target.value)} />
              </div>
              <div />
              <div>
                <label style={{ fontSize: 11, color: 'var(--text3)', display: 'block', marginBottom: 4, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                  Username / Email
                </label>
                <input className="input" placeholder="user@example.com"
                  value={authUsername} onChange={e => setAuthUsername(e.target.value)} autoComplete="off" />
              </div>
              <div>
                <label style={{ fontSize: 11, color: 'var(--text3)', display: 'block', marginBottom: 4, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                  Password
                </label>
                <div style={{ position: 'relative' }}>
                  <input className="input" type={showAuthPass ? 'text' : 'password'}
                    placeholder="••••••••" value={authPassword}
                    onChange={e => setAuthPassword(e.target.value)}
                    autoComplete="new-password"
                    style={{ paddingRight: 52 }} />
                  <button type="button" onClick={() => setShowAuthPass(p => !p)}
                    style={{ position: 'absolute', right: 10, top: '50%', transform: 'translateY(-50%)',
                             background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text3)', fontSize: 11 }}>
                    {showAuthPass ? 'HIDE' : 'SHOW'}
                  </button>
                </div>
              </div>
            </div>
          )}

          {/* Basic auth fields */}
          {authType === 'basic' && (
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
              <div>
                <label style={{ fontSize: 11, color: 'var(--text3)', display: 'block', marginBottom: 4, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.5px' }}>Username</label>
                <input className="input" placeholder="admin"
                  value={authUsername} onChange={e => setAuthUsername(e.target.value)} />
              </div>
              <div>
                <label style={{ fontSize: 11, color: 'var(--text3)', display: 'block', marginBottom: 4, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.5px' }}>Password</label>
                <div style={{ position: 'relative' }}>
                  <input className="input" type={showAuthPass ? 'text' : 'password'}
                    placeholder="••••••••" value={authPassword}
                    onChange={e => setAuthPassword(e.target.value)}
                    style={{ paddingRight: 52 }} />
                  <button type="button" onClick={() => setShowAuthPass(p => !p)}
                    style={{ position: 'absolute', right: 10, top: '50%', transform: 'translateY(-50%)',
                             background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text3)', fontSize: 11 }}>
                    {showAuthPass ? 'HIDE' : 'SHOW'}
                  </button>
                </div>
              </div>
            </div>
          )}

          {/* Bearer / API key fields */}
          {(authType === 'bearer' || authType === 'apikey') && (
            <div>
              <label style={{ fontSize: 11, color: 'var(--text3)', display: 'block', marginBottom: 4, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                {authType === 'bearer' ? 'Bearer Token / JWT' : 'API Key'}
              </label>
              <input className="input" type={showAuthPass ? 'text' : 'password'}
                placeholder={authType === 'bearer' ? 'eyJhbGciOi...' : 'sk-...'}
                value={authToken} onChange={e => setAuthToken(e.target.value)}
                style={{ fontFamily: 'monospace' }} />
              <button type="button" onClick={() => setShowAuthPass(p => !p)}
                style={{ fontSize: 11, color: 'var(--accent)', background: 'none', border: 'none',
                         cursor: 'pointer', marginTop: 6, padding: 0 }}>
                {showAuthPass ? 'Hide token' : 'Show token'}
              </button>
            </div>
          )}

          {authType !== 'none' && (
            <div style={{ marginTop: 12, padding: '8px 12px', background: 'rgba(34,197,94,0.06)',
                          border: '1px solid rgba(34,197,94,0.2)', borderRadius: 8 }}>
              <p style={{ fontSize: 11, color: '#86EFAC' }}>
                ✓ Authenticated scanning enables: IDOR detection, privilege escalation testing,
                post-login parameter injection, session management checks.
                Credentials are used only for this scan and never stored permanently.
              </p>
            </div>
          )}
        </div>
      )}

      {/* ── Launch button ────────────────────────────────────────────────────── */}
      <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
        <button
          className="btn btn-primary"
          type="submit"
          disabled={!canLaunch}
          style={{
            padding: '12px 32px', fontSize: 14, fontWeight: 700,
            display: 'flex', alignItems: 'center', gap: 8,
            opacity: canLaunch ? 1 : 0.5,
            cursor: canLaunch ? 'pointer' : 'not-allowed',
            transition: 'all 0.2s',
            ...(canLaunch ? {
              background: 'linear-gradient(135deg, #1E40AF, #2563EB)',
              boxShadow: '0 4px 14px rgba(37,99,235,0.4)',
            } : {}),
          }}>
          {loading
            ? <><Loader2 size={16} className="animate-spin" /> Launching Scan…</>
            : canLaunch
              ? <><Play size={16} /> Launch VAPT Scan</>
              : <><Lock size={16} /> {!isVerified ? 'Domain Not Verified' : !authConfirmed ? 'Confirm Authorization' : 'Not Ready'}</>
          }
        </button>

        {isVerified && (
          <button type="button" className="btn btn-outline" onClick={() => navigate('/settings')}>
            Manage Whitelist
          </button>
        )}
        {!isVerified && parsedDomain && (
          <button type="button" className="btn btn-outline" onClick={() => navigate('/settings')}>
            Verify {parsedDomain} First →
          </button>
        )}
      </div>

      {/* ── Status hint ──────────────────────────────────────────────────────── */}
      {!canLaunch && (
        <p style={{ fontSize: 12, color: 'var(--text3)' }}>
          {!parsedDomain && '① Enter a target URL above'}
          {parsedDomain && !isVerified && `① Add "${parsedDomain}" to your whitelist in Settings and verify it`}
          {parsedDomain && isVerified && !authConfirmed && '② Check the authorization confirmation checkbox above'}
        </p>
      )}
    </form>
  );
}