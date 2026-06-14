import React, { useState, useRef, useEffect } from 'react';
import {
  Globe, ShieldCheck, AlertTriangle, CheckCircle,
  Loader2, ChevronDown, ChevronRight, Link, FileCode,
  Terminal, Clock, Activity, Zap, FileJson, FileText, Download, Mail,
} from 'lucide-react';
import api from '../services/api';
import { useToastStore } from '../store';

type ScannerMode = 'sast' | 'dast' | 'combined';
type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

const SEV_COLOR: Record<Severity, string> = {
  critical: '#DC2626', high: '#EA580C', medium: '#D97706',
  low: '#2563EB', info: '#6B7280',
};
const SEV_BG: Record<Severity, string> = {
  critical: 'rgba(220,38,38,0.10)', high: 'rgba(234,88,12,0.10)',
  medium: 'rgba(217,119,6,0.10)', low: 'rgba(37,99,235,0.10)',
  info: 'rgba(107,114,128,0.08)',
};

function SevBadge({ sev }: { sev: string }) {
  const s = (sev?.toLowerCase() || 'info') as Severity;
  return (
    <span style={{
      background: SEV_BG[s] || SEV_BG.info,
      color: SEV_COLOR[s] || SEV_COLOR.info,
      border: `1px solid ${(SEV_COLOR[s] || SEV_COLOR.info)}50`,
      padding: '2px 8px', borderRadius: 5,
      fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.5px',
    }}>{sev}</span>
  );
}

function CountCard({ label, count, sev }: { label: string; count: number; sev: Severity }) {
  return (
    <div style={{
      background: SEV_BG[sev], border: `1px solid ${SEV_COLOR[sev]}30`,
      borderRadius: 8, padding: '10px 14px', textAlign: 'center', minWidth: 64,
    }}>
      <div style={{ fontSize: 22, fontWeight: 800, color: SEV_COLOR[sev], lineHeight: 1 }}>{count}</div>
      <div style={{ fontSize: 10, color: SEV_COLOR[sev], textTransform: 'uppercase', fontWeight: 600, marginTop: 3 }}>{label}</div>
    </div>
  );
}

function FindingCard({ f, index, type }: { f: any; index: number; type: 'sast' | 'dast' }) {
  const [open, setOpen] = useState(false);
  return (
    <div style={{
      background: 'var(--surface)', border: '1px solid var(--border)',
      borderLeft: `3px solid ${SEV_COLOR[(f.severity?.toLowerCase() || 'info') as Severity]}`,
      borderRadius: 10, overflow: 'hidden', marginBottom: 6,
    }}>
      <button onClick={() => setOpen(o => !o)} style={{
        width: '100%', display: 'flex', alignItems: 'center', gap: 10,
        padding: '11px 14px', background: 'none', border: 'none',
        cursor: 'pointer', textAlign: 'left',
      }}>
        <span style={{ fontSize: 11, color: 'var(--text3)', fontFamily: 'monospace', minWidth: 28 }}>#{index + 1}</span>
        <span style={{ flex: 1, fontSize: 13, fontWeight: 600, color: 'var(--text)' }}>{f.title}</span>
        <SevBadge sev={f.severity} />
        {f.category && (
          <span style={{
            fontSize: 10, color: 'var(--accent)', fontFamily: 'monospace',
            background: 'rgba(59,130,246,0.08)', border: '1px solid rgba(59,130,246,0.2)',
            padding: '1px 6px', borderRadius: 4,
          }}>{f.category}</span>
        )}
        {open ? <ChevronDown size={13} color="var(--text3)" /> : <ChevronRight size={13} color="var(--text3)" />}
      </button>

      {open && (
        <div style={{ padding: '0 14px 14px', display: 'flex', flexDirection: 'column', gap: 10 }}>
          {type === 'sast' && f.file && (
            <div style={{ fontSize: 11, color: 'var(--text3)', fontFamily: 'monospace', background: 'var(--surface2)', padding: '4px 8px', borderRadius: 5 }}>
              📄 {f.file}{f.line ? `:${f.line}` : ''}
            </div>
          )}
          {type === 'dast' && f.url && (
            <div style={{ fontSize: 11, color: 'var(--text3)', fontFamily: 'monospace', background: 'var(--surface2)', padding: '4px 8px', borderRadius: 5 }}>
              🔗 {f.url}{f.parameter ? ` · param: ${f.parameter}` : ''}{f.method ? ` [${f.method}]` : ''}
            </div>
          )}

          <p style={{ fontSize: 13, color: 'var(--text2)', lineHeight: 1.65 }}>{f.description}</p>

          {(f.snippet || f.evidence || f.payload) && (
            <div style={{
              background: '#04070F', border: '1px solid var(--border)',
              borderRadius: 6, padding: '8px 12px',
              fontFamily: 'monospace', fontSize: 11, color: '#94A3B8',
              whiteSpace: 'pre-wrap', wordBreak: 'break-all',
            }}>
              {f.snippet || f.evidence || (f.payload && `Payload: ${f.payload}`)}
            </div>
          )}

          {f.remediation && (
            <div style={{ background: 'rgba(34,197,94,0.06)', border: '1px solid rgba(34,197,94,0.2)', borderRadius: 6, padding: '8px 12px' }}>
              <div style={{ fontSize: 10, color: '#22C55E', fontWeight: 700, marginBottom: 4, textTransform: 'uppercase' }}>✔ Remediation</div>
              <p style={{ fontSize: 12, color: 'var(--text2)', lineHeight: 1.65 }}>{f.remediation}</p>
            </div>
          )}

          <div style={{ display: 'flex', gap: 14, flexWrap: 'wrap', fontSize: 11, color: 'var(--text3)' }}>
            {f.cwe && <span>CWE: {f.cwe}</span>}
            {f.rule_id && <span>Rule: {f.rule_id}</span>}
            {f.test_id && <span>Test: {f.test_id}</span>}
            <span>Confidence: {Math.round((f.confidence || 0) * 100)}%</span>
            {type === 'dast' && f.method && <span>Method: {f.method}</span>}
            {f.references?.length > 0 && (
              <span>Refs: {f.references.slice(0, 2).map((r: string, i: number) => (
                <a key={i} href={r} target="_blank" rel="noopener noreferrer"
                  style={{ color: 'var(--accent)', marginLeft: 4 }}>↗</a>
              ))}</span>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

function SummaryBar({ result }: { result: any }) {
  const counts = result?.summary?.counts || {};
  const total = result?.findings_count || 0;
  return (
    <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
      <CountCard label="Critical" count={counts.critical || 0} sev="critical" />
      <CountCard label="High" count={counts.high || 0} sev="high" />
      <CountCard label="Medium" count={counts.medium || 0} sev="medium" />
      <CountCard label="Low" count={counts.low || 0} sev="low" />
      <CountCard label="Info" count={counts.info || 0} sev="info" />
      <div style={{
        flex: 1, minWidth: 70, background: 'var(--surface3)',
        borderRadius: 8, padding: '10px 14px', textAlign: 'center',
      }}>
        <div style={{ fontSize: 22, fontWeight: 800, color: 'var(--text)', lineHeight: 1 }}>{total}</div>
        <div style={{ fontSize: 10, color: 'var(--text3)', textTransform: 'uppercase', fontWeight: 600, marginTop: 3 }}>Total</div>
      </div>
    </div>
  );
}

function FindingsList({ findings, type }: { findings: any[]; type: 'sast' | 'dast' }) {
  if (!findings?.length) return (
    <div style={{
      display: 'flex', alignItems: 'center', gap: 10,
      background: 'rgba(34,197,94,0.08)', border: '1px solid rgba(34,197,94,0.2)',
      borderRadius: 10, padding: '14px 16px',
    }}>
      <CheckCircle size={16} color="#22C55E" />
      <span style={{ color: 'var(--text2)', fontSize: 13 }}>No issues detected by this scanner.</span>
    </div>
  );
  return (
    <div>
      <div style={{ fontSize: 11, color: 'var(--text3)', marginBottom: 8, fontWeight: 600 }}>
        {findings.length} finding(s) — click any row to expand details
      </div>
      {findings.map((f, i) => <FindingCard key={i} f={f} index={i} type={type} />)}
    </div>
  );
}

interface LogLine { ts: string; msg: string; level: 'info' | 'ok' | 'warn' | 'err' | 'scan' }

function LiveTerminal({ lines, scanning }: { lines: LogLine[]; scanning: boolean }) {
  const endRef = useRef<HTMLDivElement>(null);
  useEffect(() => { endRef.current?.scrollIntoView({ behavior: 'smooth' }); }, [lines]);
  const col: Record<string, string> = {
    info: '#94A3B8', ok: '#22C55E', warn: '#F59E0B', err: '#EF4444', scan: '#60A5FA',
  };
  return (
    <div style={{
      background: '#020817', border: '1px solid rgba(255,255,255,0.07)',
      borderRadius: 10, padding: '14px 16px', fontFamily: 'JetBrains Mono, monospace',
      fontSize: 11, height: 260, overflowY: 'auto',
    }}>
      {lines.length === 0 && <span style={{ color: '#334155' }}>Waiting for scan to start…</span>}
      {lines.map((l, i) => (
        <div key={i} style={{ marginBottom: 3, lineHeight: 1.7 }}>
          <span style={{ color: '#334155', marginRight: 10 }}>[{l.ts}]</span>
          <span style={{ color: col[l.level] || col.info }}>{l.msg}</span>
        </div>
      ))}
      {scanning && (
        <div style={{ marginBottom: 3, lineHeight: 1.7 }}>
          <span style={{ color: '#334155', marginRight: 10 }}>[{new Date().toLocaleTimeString('en-GB')}]</span>
          <span style={{ color: '#60A5FA' }}>█</span>
        </div>
      )}
      <div ref={endRef} />
    </div>
  );
}

function HttpWarning({ url }: { url: string }) {
  if (!url.startsWith('http://')) return null;
  return (
    <div style={{
      display: 'flex', alignItems: 'flex-start', gap: 10,
      background: 'rgba(245,158,11,0.08)', border: '1px solid rgba(245,158,11,0.3)',
      borderRadius: 8, padding: '10px 14px',
    }}>
      <AlertTriangle size={14} color="#F59E0B" style={{ marginTop: 1, flexShrink: 0 }} />
      <p style={{ fontSize: 12, color: '#FCD34D', lineHeight: 1.6 }}>
        <strong>Plain HTTP detected.</strong> Traffic is unencrypted — this will be flagged as OWASP A02 HIGH severity.
      </p>
    </div>
  );
}

const SCANNER_TABS = [
  {
    key: 'sast' as ScannerMode,
    icon: FileCode,
    label: 'SAST Scanner',
    badge: 'Static Analysis',
    color: '#3B82F6',
    desc: 'Analyses source code and JS files fetched from the URL without executing them. Detects hardcoded secrets, SQLi patterns, weak crypto, path traversal, debug modes, and more.',
  },
  {
    key: 'dast' as ScannerMode,
    icon: Globe,
    label: 'DAST Scanner',
    badge: 'Dynamic Analysis',
    color: '#EA580C',
    desc: 'Makes real HTTP requests to a running application. Probes for live SQLi, XSS, SSTI, open redirects, sensitive path exposure, security-header gaps, CSRF, and SSRF.',
  },
  {
    key: 'combined' as ScannerMode,
    icon: ShieldCheck,
    label: 'SAST + DAST',
    badge: 'Full Coverage',
    color: '#8B5CF6',
    desc: 'Runs SAST and DAST concurrently with independent timeouts. Findings are merged and deduplicated into a single unified result.',
  },
];

// ── Report builder ────────────────────────────────────────────────────────────
function buildHTMLReport(result: any, mode: string): string {
  const counts = result?.summary?.counts || {};
  const ts = new Date().toLocaleString();
  const target = result.target_url || result.filename || 'Code Scan';
  const SC: Record<string, string> = { critical: '#DC2626', high: '#EA580C', medium: '#D97706', low: '#2563EB', info: '#6B7280' };
  const SB: Record<string, string> = { critical: '#FEF2F2', high: '#FFF7ED', medium: '#FFFBEB', low: '#EFF6FF', info: '#F9FAFB' };

  const allFindings: any[] = mode === 'combined'
    ? [
        ...(result.sast?.findings || []).map((f: any) => ({ ...f, _src: 'SAST' })),
        ...(result.dast?.findings || []).map((f: any) => ({ ...f, _src: 'DAST' })),
      ]
    : (result.findings || []);

  const rows = allFindings.map((f, i) => {
    const sev = (f.severity || 'info').toLowerCase();
    return `
    <div style="background:${SB[sev]||'#F9FAFB'};border:1px solid ${SC[sev]||'#ccc'}40;border-left:4px solid ${SC[sev]||'#ccc'};border-radius:8px;padding:16px;margin-bottom:12px;">
      <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:8px;flex-wrap:wrap;gap:6px;">
        <div style="font-size:14px;font-weight:700;color:#0F172A;">#${i + 1} ${f.title || ''}</div>
        <div style="display:flex;gap:6px;flex-wrap:wrap;">
          <span style="background:${SC[sev]||'#6B7280'};color:white;padding:2px 8px;border-radius:4px;font-size:10px;font-weight:700;">${(f.severity || 'INFO').toUpperCase()}</span>
          ${f._src ? `<span style="background:#1E3A5F;color:#60A5FA;padding:2px 8px;border-radius:4px;font-size:10px;font-weight:700;">${f._src}</span>` : ''}
          ${f.category ? `<span style="background:#EFF6FF;color:#1E40AF;padding:2px 8px;border-radius:4px;font-size:10px;font-weight:700;">${f.category}</span>` : ''}
        </div>
      </div>
      ${f.url ? `<div style="font-family:monospace;font-size:11px;color:#475569;background:#F1F5F9;padding:4px 8px;border-radius:4px;margin-bottom:8px;">🔗 ${f.url}${f.parameter ? ' · param: ' + f.parameter : ''}</div>` : ''}
      ${f.file ? `<div style="font-family:monospace;font-size:11px;color:#475569;background:#F1F5F9;padding:4px 8px;border-radius:4px;margin-bottom:8px;">📄 ${f.file}${f.line ? ':' + f.line : ''}</div>` : ''}
      <p style="color:#475569;font-size:13px;line-height:1.65;margin:0 0 8px;">${f.description || ''}</p>
      ${f.evidence || f.snippet ? `<div style="background:#020817;color:#94A3B8;font-family:monospace;font-size:11px;padding:10px;border-radius:6px;margin-bottom:8px;white-space:pre-wrap;word-break:break-all;">${f.evidence || f.snippet}</div>` : ''}
      ${f.remediation ? `<div style="background:#F0FDF4;border:1px solid #BBF7D0;border-radius:6px;padding:10px;"><div style="font-size:10px;font-weight:700;color:#16A34A;margin-bottom:4px;">✔ REMEDIATION</div><p style="font-size:12px;color:#166534;margin:0;">${f.remediation}</p></div>` : ''}
      <div style="display:flex;gap:12px;margin-top:8px;font-size:11px;color:#94A3B8;flex-wrap:wrap;">
        ${f.cwe ? `<span>CWE: ${f.cwe}</span>` : ''}
        ${f.confidence !== undefined ? `<span>Confidence: ${Math.round(f.confidence * 100)}%</span>` : ''}
        ${f.method ? `<span>Method: ${f.method}</span>` : ''}
      </div>
    </div>`;
  }).join('');

  const modeLabel = mode === 'combined' ? 'SAST + DAST Combined' : mode === 'dast' ? 'DAST Dynamic Scan' : 'SAST Static Analysis';

  return `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<title>VAPTForge ${modeLabel} — ${target}</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:'Segoe UI',Arial,sans-serif;background:#F8FAFC;color:#1E293B;font-size:14px;}
  .cover{background:linear-gradient(135deg,#0F172A 0%,#1E3A5F 100%);color:white;padding:48px;min-height:280px;}
  .cover h1{font-size:32px;font-weight:800;margin:16px 0 8px;}
  .meta{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-top:28px;}
  .meta-item label{font-size:10px;color:#64748B;text-transform:uppercase;letter-spacing:1px;display:block;margin-bottom:4px;}
  .meta-item value{font-size:13px;color:#E2E8F0;font-family:monospace;}
  .counts{display:grid;grid-template-columns:repeat(5,1fr);gap:10px;margin-top:24px;}
  .cnt{background:rgba(255,255,255,0.06);border:1px solid rgba(255,255,255,0.1);border-radius:8px;padding:12px;text-align:center;}
  .cnt .n{font-size:26px;font-weight:800;}
  .cnt .l{font-size:10px;text-transform:uppercase;letter-spacing:1px;margin-top:4px;opacity:.7;}
  .page{max-width:960px;margin:0 auto;padding:40px;}
  .section-hdr{font-size:18px;font-weight:700;color:#0F172A;margin:0 0 20px;padding-bottom:10px;border-bottom:2px solid #E2E8F0;}
  @media print{.cover{page-break-after:always;}}
</style></head><body>
<div class="cover">
  <div style="font-size:11px;font-weight:600;letter-spacing:3px;color:#64748B;text-transform:uppercase;">■ VAPTForge Enterprise — Security Assessment</div>
  <h1>${modeLabel} Report</h1>
  <div style="font-size:12px;color:#94A3B8;">Generated: ${ts}</div>
  <div class="meta">
    <div class="meta-item"><label>Target</label><value>${target}</value></div>
    <div class="meta-item"><label>Scanner Mode</label><value>${modeLabel}</value></div>
    <div class="meta-item"><label>Total Findings</label><value>${allFindings.length}</value></div>
    <div class="meta-item"><label>Report Date</label><value>${ts}</value></div>
  </div>
  <div class="counts">
    <div class="cnt"><div class="n" style="color:#FCA5A5;">${counts.critical || 0}</div><div class="l">Critical</div></div>
    <div class="cnt"><div class="n" style="color:#FED7AA;">${counts.high || 0}</div><div class="l">High</div></div>
    <div class="cnt"><div class="n" style="color:#FDE68A;">${counts.medium || 0}</div><div class="l">Medium</div></div>
    <div class="cnt"><div class="n" style="color:#BFDBFE;">${counts.low || 0}</div><div class="l">Low</div></div>
    <div class="cnt"><div class="n" style="color:#E5E7EB;">${counts.info || 0}</div><div class="l">Info</div></div>
  </div>
</div>
<div class="page">
  <div class="section-hdr">Findings — ${allFindings.length} total</div>
  ${rows || '<p style="color:#64748B;padding:20px 0;">No findings detected.</p>'}
</div>
</body></html>`;
}

// ── Main component ─────────────────────────────────────────────────────────────
export default function ScannerPage() {
  const addToast = useToastStore(s => s.add);

  const [mode, setMode] = useState<ScannerMode>('sast');
  const [sastMode, setSastMode] = useState<'code' | 'url'>('url');
  const [sastCode, setSastCode] = useState('');
  const [sastFile, setSastFile] = useState('app.py');
  const [sastUrl, setSastUrl] = useState('https://');
  const [dastUrl, setDastUrl] = useState('https://');
  const [combUrl, setCombUrl] = useState('https://');
  const [timeout, setTimeoutVal] = useState(60);
  const [result, setResult] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [logLines, setLogLines] = useState<LogLine[]>([]);
  const [elapsed, setElapsed] = useState(0);
  const [downloading, setDownloading] = useState<string | null>(null);
  const [emailModal, setEmailModal]   = useState(false);
  const [emailTo, setEmailTo]         = useState('');
  const [emailSending, setEmailSending] = useState(false);
  const timerRef = useRef<any>(null);

  const now = () => new Date().toLocaleTimeString('en-GB', { hour12: false });
  const addLog = (msg: string, level: LogLine['level'] = 'info') =>
    setLogLines(prev => [...prev, { ts: now(), msg, level }]);

  const startTimer = () => {
    setElapsed(0);
    timerRef.current = setInterval(() => setElapsed(e => e + 1), 1000);
  };
  const stopTimer = () => clearInterval(timerRef.current);

  // ── Email report ──────────────────────────────────────────────────────────────
  const sendEmailReport = async () => {
    const emails = emailTo.split(',').map(e => e.trim()).filter(Boolean);
    if (!emails.length) { addToast('error', 'Enter at least one email address'); return; }
    setEmailSending(true);
    try {
      const html = buildHTMLReport(result, mode);
      await api.post('/reports/send-scanner-report', {
        recipients: emails,
        subject: `VAPTForge ${mode.toUpperCase()} Scanner Report — ${new Date().toLocaleDateString()}`,
        html_content: html,   // ← FIX: backend ka required field
        include_pdf: false,
      });
      addToast('success', 'Report emailed successfully');
      setEmailModal(false);
      setEmailTo('');
    } catch {
      addToast('error', 'Failed to send email — check SMTP settings');
    } finally {
      setEmailSending(false);
    }
  };

  // ── Download report ──────────────────────────────────────────────────────────
  const downloadReport = (format: 'html' | 'json' | 'pdf') => {
    if (!result) return;
    setDownloading(format);
    try {
      const ts = new Date().toISOString().slice(0, 19).replace(/[:.]/g, '-');
      const target = (result.target_url || result.filename || 'scan')
        .replace(/https?:\/\//, '').replace(/[^a-z0-9]/gi, '-').slice(0, 40);
      const filename = `vapt-${mode}-${target}-${ts}`;

      if (format === 'json') {
        const blob = new Blob([JSON.stringify(result, null, 2)], { type: 'application/json' });
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = `${filename}.json`;
        a.click();
        addToast('success', 'JSON report downloaded');

      } else if (format === 'html') {
        const html = buildHTMLReport(result, mode);
        const blob = new Blob([html], { type: 'text/html' });
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = `${filename}.html`;
        a.click();
        addToast('success', 'HTML report downloaded');

      } else if (format === 'pdf') {
        const html = buildHTMLReport(result, mode);
        const win = window.open('', '_blank');
        if (win) {
          win.document.write(html);
          win.document.close();
          win.onload = () => { win.focus(); win.print(); };
        }
        addToast('success', 'PDF print dialog opened');
      }
    } finally {
      setDownloading(null);
    }
  };

  // ── Run scan ──────────────────────────────────────────────────────────────────
  const run = async () => {
    setLoading(true);
    setResult(null);
    setLogLines([]);
    startTimer();

    try {
      if (mode === 'sast') {
        if (sastMode === 'code') {
          if (!sastCode.trim()) { addToast('error', 'Paste some code first'); return; }
          addLog('[SAST] Initialising static code analysis…', 'scan');
          addLog(`[SAST] Filename: ${sastFile} | Size: ${sastCode.length.toLocaleString()} chars`, 'info');
          addLog('[SAST] Running SAST rule-set patterns…', 'scan');
          const r = await api.post('/scanners/sast/code', { code: sastCode, filename: sastFile });
          setResult(r.data);
          addLog(`[SAST] Complete — ${r.data.findings_count} finding(s)`, r.data.findings_count > 0 ? 'warn' : 'ok');
          addToast(r.data.findings_count > 0 ? 'warn' : 'success', `SAST: ${r.data.findings_count} issue(s) found`);
        } else {
          if (!sastUrl.startsWith('http')) { addToast('error', 'Enter a valid URL'); return; }
          addLog(`[SAST] Target: ${sastUrl}`, 'scan');
          addLog('[SAST] Fetching page HTML…', 'info');
          addLog('[SAST] Discovering linked JavaScript files…', 'info');
          addLog('[SAST] Fetching common config/source paths…', 'info');
          addLog('[SAST] Running static analysis rules on fetched content…', 'scan');
          addLog('[SAST] Checking for secrets, weak crypto, SQLi patterns…', 'info');
          addLog('[SAST] Analysing HTTP security headers…', 'info');
          const r = await api.post('/scanners/sast/url', { target_url: sastUrl, timeout: 28 });
          setResult(r.data);
          addLog(`[SAST] Complete — ${r.data.findings_count} finding(s)`, r.data.findings_count > 0 ? 'warn' : 'ok');
          addToast(r.data.findings_count > 0 ? 'warn' : 'success', `SAST: ${r.data.findings_count} issue(s) found`);
        }

      } else if (mode === 'dast') {
        if (!dastUrl.startsWith('http')) { addToast('error', 'Enter a valid URL'); return; }
        addLog(`[DAST] Target: ${dastUrl}`, 'scan');
        addLog('[DAST] Checking TCP connectivity…', 'info');
        addLog('[DAST] Analysing HTTP response headers (A05, A02)…', 'info');
        addLog('[DAST] Probing sensitive paths (.env, .git, admin)…', 'info');
        addLog('[DAST] Crawling application URLs…', 'info');
        addLog('[DAST] Testing SQL injection payloads (A03)…', 'info');
        addLog('[DAST] Testing XSS reflection (A03)…', 'info');
        addLog('[DAST] Testing SSTI templates (A03)…', 'info');
        addLog('[DAST] Checking cookie security flags (A07)…', 'info');
        addLog('[DAST] Testing SSRF vectors (A10)…', 'info');
        addLog('[DAST] Checking CSRF protection (A01)…', 'info');
        const r = await api.post('/scanners/dast/scan', { target_url: dastUrl, timeout, max_urls: 30 });
        setResult(r.data);
        addLog(`[DAST] Complete — ${r.data.findings_count} finding(s)`, r.data.findings_count > 0 ? 'warn' : 'ok');
        addToast(r.data.findings_count > 0 ? 'warn' : 'success', `DAST: ${r.data.findings_count} issue(s) found`);

      } else {
        if (!combUrl.startsWith('http')) { addToast('error', 'Enter a valid URL'); return; }
        addLog(`[COMBINED] Target: ${combUrl}`, 'scan');
        addLog('[SAST] Fetching source files and JS bundles…', 'info');
        addLog('[DAST] Checking connectivity and headers concurrently…', 'info');
        addLog('[SAST] Running static rule patterns on fetched source…', 'info');
        addLog('[DAST] Probing sensitive paths and endpoints…', 'info');
        addLog('[DAST] Injecting test payloads (SQLi, XSS, SSTI)…', 'info');
        addLog('[COMBINED] Both engines running in parallel — merging results…', 'scan');
        const r = await api.post('/scanners/combined/scan', { target_url: combUrl, timeout, max_urls: 25 });
        setResult(r.data);
        addLog(`[SAST] ${r.data.sast?.findings_count || 0} finding(s)`, (r.data.sast?.findings_count || 0) > 0 ? 'warn' : 'ok');
        addLog(`[DAST] ${r.data.dast?.findings_count || 0} finding(s)`, (r.data.dast?.findings_count || 0) > 0 ? 'warn' : 'ok');
        addLog(`[COMBINED] Total: ${r.data.findings_count} finding(s)`, r.data.findings_count > 0 ? 'warn' : 'ok');
        addToast(r.data.findings_count > 0 ? 'warn' : 'success', `SAST+DAST: ${r.data.findings_count} issue(s) found`);
      }

    } catch (err: any) {
      const msg = err.response?.data?.detail ?? 'Scan failed';
      addLog(`[ERROR] ${msg}`, 'err');
      addToast('error', msg);
    } finally {
      stopTimer();
      setLoading(false);
    }
  };

  const activeTab = SCANNER_TABS.find(t => t.key === mode)!;

  return (
    <div className="fade-up" style={{ display: 'flex', flexDirection: 'column', gap: 20, maxWidth: 960 }}>

      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end' }}>
        <div>
          <h1 style={{ fontSize: 20, fontWeight: 800, color: 'var(--text)' }}>Security Scanners</h1>
          <p style={{ fontSize: 12, color: 'var(--text3)', marginTop: 2 }}>
            SAST · DAST · Combined — full OWASP A01–A10 coverage with downloadable reports
          </p>
        </div>
        {loading && (
          <div style={{
            display: 'flex', alignItems: 'center', gap: 8,
            background: 'rgba(59,130,246,0.08)', border: '1px solid rgba(59,130,246,0.2)',
            borderRadius: 8, padding: '6px 14px', fontSize: 12, color: 'var(--accent)',
          }}>
            <Activity size={13} />
            <span style={{ fontFamily: 'monospace' }}>{elapsed}s elapsed</span>
          </div>
        )}
      </div>

      {/* Mode selector */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 10 }}>
        {SCANNER_TABS.map(tab => {
          const Icon = tab.icon;
          const active = mode === tab.key;
          return (
            <button key={tab.key}
              onClick={() => { setMode(tab.key); setResult(null); setLogLines([]); }}
              style={{
                padding: '16px', borderRadius: 12, cursor: 'pointer', textAlign: 'left',
                border: `2px solid ${active ? tab.color : 'var(--border)'}`,
                background: active ? `${tab.color}10` : 'var(--surface)',
                transition: 'all 0.15s',
              }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
                <Icon size={16} color={active ? tab.color : 'var(--text3)'} />
                <span style={{ fontSize: 13, fontWeight: 700, color: active ? tab.color : 'var(--text)' }}>{tab.label}</span>
                <span style={{
                  marginLeft: 'auto', fontSize: 9, fontWeight: 700, textTransform: 'uppercase',
                  letterSpacing: 1, color: tab.color, background: `${tab.color}15`,
                  border: `1px solid ${tab.color}30`, padding: '2px 7px', borderRadius: 4,
                }}>{tab.badge}</span>
              </div>
              <p style={{ fontSize: 11, color: 'var(--text3)', lineHeight: 1.6 }}>{tab.desc}</p>
            </button>
          );
        })}
      </div>

      {/* Main card */}
      <div className="card" style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>

        {/* SAST controls */}
        {mode === 'sast' && (
          <>
            <div style={{ display: 'flex', gap: 6 }}>
              {[
                { key: 'url', icon: Link, label: 'Scan URL (fetch source)' },
                { key: 'code', icon: Terminal, label: 'Paste Code' },
              ].map(({ key, icon: Ic, label }) => (
                <button key={key}
                  onClick={() => { setSastMode(key as 'url' | 'code'); setResult(null); }}
                  style={{
                    display: 'flex', alignItems: 'center', gap: 6,
                    padding: '6px 14px', borderRadius: 7, cursor: 'pointer', fontSize: 12,
                    border: `1px solid ${sastMode === key ? 'var(--accent)' : 'var(--border)'}`,
                    background: sastMode === key ? 'rgba(59,130,246,0.08)' : 'var(--surface)',
                    color: sastMode === key ? 'var(--accent)' : 'var(--text2)',
                    fontWeight: sastMode === key ? 700 : 400,
                  }}>
                  <Ic size={12} /> {label}
                </button>
              ))}
            </div>

            {sastMode === 'url' ? (
              <>
                <div style={{ background: 'rgba(59,130,246,0.06)', border: '1px solid rgba(59,130,246,0.15)', borderRadius: 8, padding: '10px 14px', fontSize: 12, color: 'var(--text2)' }}>
                  <strong style={{ color: 'var(--accent)' }}>SAST — URL mode:</strong> Fetches HTML, JS files, JSON configs and common source paths, then runs all SAST rules on the downloaded content. No code execution.
                </div>
                <HttpWarning url={sastUrl} />
                <input className="input" value={sastUrl} onChange={e => setSastUrl(e.target.value)} placeholder="https://app.example.com" />
              </>
            ) : (
              <>
                <div style={{ background: 'rgba(59,130,246,0.06)', border: '1px solid rgba(59,130,246,0.15)', borderRadius: 8, padding: '10px 14px', fontSize: 12, color: 'var(--text2)' }}>
                  <strong style={{ color: 'var(--accent)' }}>SAST — Code mode:</strong> Paste source code directly. Detects SQLi, XSS, hardcoded secrets, command injection, path traversal, weak crypto, debug mode, JWT issues, SSRF.
                </div>
                <input className="input" value={sastFile} onChange={e => setSastFile(e.target.value)} placeholder="filename e.g. app.py" style={{ maxWidth: 240 }} />
                <textarea className="input" rows={11} value={sastCode} onChange={e => setSastCode(e.target.value)}
                  placeholder="Paste source code here…"
                  style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 12, resize: 'vertical' }} />
              </>
            )}
          </>
        )}

        {/* DAST controls */}
        {mode === 'dast' && (
          <>
            <div style={{ background: 'rgba(234,88,12,0.07)', border: '1px solid rgba(234,88,12,0.2)', borderRadius: 8, padding: '10px 14px', display: 'flex', gap: 8 }}>
              <AlertTriangle size={14} color="#EA580C" style={{ marginTop: 1, flexShrink: 0 }} />
              <p style={{ fontSize: 12, color: 'var(--text2)', lineHeight: 1.6 }}>
                <strong style={{ color: '#EA580C' }}>DAST — Live Scan:</strong> Makes real HTTP requests and injects test payloads. Only scan systems you own or have <strong>written authorization</strong> to test.
              </p>
            </div>
            <HttpWarning url={dastUrl} />
            <input className="input" value={dastUrl} onChange={e => setDastUrl(e.target.value)} placeholder="https://app.example.com" />
            <div>
              <label style={{ fontSize: 11, color: 'var(--text3)', fontWeight: 600, display: 'block', marginBottom: 5 }}>SCAN TIMEOUT</label>
              <select className="input" value={timeout} onChange={e => setTimeoutVal(Number(e.target.value))} style={{ maxWidth: 220 }}>
                <option value={30}>30 seconds (quick)</option>
                <option value={45}>45 seconds (standard)</option>
                <option value={60}>60 seconds (full)</option>
              </select>
            </div>
          </>
        )}

        {/* Combined controls */}
        {mode === 'combined' && (
          <>
            <div style={{ background: 'rgba(139,92,246,0.07)', border: '1px solid rgba(139,92,246,0.2)', borderRadius: 8, padding: '10px 14px', display: 'flex', gap: 8 }}>
              <Zap size={14} color="#8B5CF6" style={{ marginTop: 1, flexShrink: 0 }} />
              <p style={{ fontSize: 12, color: 'var(--text2)', lineHeight: 1.6 }}>
                <strong style={{ color: '#8B5CF6' }}>SAST + DAST — Full Coverage:</strong> Both engines run concurrently with independent timeouts. Only scan authorised targets.
              </p>
            </div>
            <HttpWarning url={combUrl} />
            <input className="input" value={combUrl} onChange={e => setCombUrl(e.target.value)} placeholder="https://app.example.com" />
            <div>
              <label style={{ fontSize: 11, color: 'var(--text3)', fontWeight: 600, display: 'block', marginBottom: 5 }}>TIMEOUT</label>
              <select className="input" value={timeout} onChange={e => setTimeoutVal(Number(e.target.value))} style={{ maxWidth: 220 }}>
                <option value={45}>45 seconds</option>
                <option value={60}>60 seconds (recommended)</option>
              </select>
            </div>
          </>
        )}

        {/* Run + Download buttons */}
        <div style={{ display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
          <button className="btn btn-primary" onClick={run} disabled={loading}
            style={{ minWidth: 180, display: 'flex', alignItems: 'center', gap: 8, justifyContent: 'center' }}>
            {loading
              ? <><Loader2 size={14} className="animate-spin" /> Scanning…</>
              : <><activeTab.icon size={14} /> Run {activeTab.label}</>}
          </button>

          {result && (
            <>
              <button className="btn btn-outline btn-sm"
                onClick={() => { setResult(null); setLogLines([]); }}>Clear</button>

              {/* ── Download buttons ── */}
              <div style={{
                marginLeft: 'auto', display: 'flex', gap: 6, alignItems: 'center',
                background: 'var(--surface2)', border: '1px solid var(--border)',
                borderRadius: 8, padding: '6px 10px',
              }}>
                <Download size={12} color="var(--text3)" />
                <span style={{ fontSize: 10, color: 'var(--text3)', fontWeight: 600, marginRight: 4 }}>DOWNLOAD</span>
                <button className="btn btn-outline btn-sm" disabled={downloading === 'html'}
                  onClick={() => downloadReport('html')}
                  style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 11, padding: '4px 10px' }}>
                  {downloading === 'html' ? <Loader2 size={11} className="animate-spin" /> : <FileCode size={11} />} HTML
                </button>
                <button className="btn btn-outline btn-sm" disabled={downloading === 'json'}
                  onClick={() => downloadReport('json')}
                  style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 11, padding: '4px 10px' }}>
                  {downloading === 'json' ? <Loader2 size={11} className="animate-spin" /> : <FileJson size={11} />} JSON
                </button>
                <button className="btn btn-outline btn-sm" disabled={downloading === 'pdf'}
                  onClick={() => downloadReport('pdf')}
                  style={{
                    display: 'flex', alignItems: 'center', gap: 4, fontSize: 11, padding: '4px 10px',
                    background: 'rgba(239,68,68,0.08)', borderColor: 'rgba(239,68,68,0.3)', color: '#FCA5A5',
                  }}>
                  {downloading === 'pdf' ? <Loader2 size={11} className="animate-spin" /> : <FileText size={11} />} PDF
                </button>
                <button className="btn btn-outline btn-sm"
                  onClick={() => setEmailModal(true)}
                  style={{
                    display: 'flex', alignItems: 'center', gap: 4, fontSize: 11, padding: '4px 10px',
                    background: 'rgba(59,130,246,0.08)', borderColor: 'rgba(59,130,246,0.3)', color: '#60A5FA',
                  }}>
                  <Mail size={11} /> Email
                </button>
              </div>
            </>
          )}

          {mode === 'sast' && sastMode === 'code' && !result && (
            <span style={{ fontSize: 11, color: 'var(--text3)', marginLeft: 'auto' }}>
              {sastCode.length.toLocaleString()} chars
            </span>
          )}
        </div>

        {/* Live terminal */}
        {(loading || logLines.length > 0) && (
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
              <Terminal size={13} color="var(--text3)" />
              <span style={{ fontSize: 11, color: 'var(--text3)', fontWeight: 600, textTransform: 'uppercase', letterSpacing: 1 }}>Scan Log</span>
              <Clock size={11} color="var(--text3)" style={{ marginLeft: 'auto' }} />
              <span style={{ fontSize: 11, color: 'var(--text3)', fontFamily: 'monospace' }}>{new Date().toLocaleString()}</span>
            </div>
            <LiveTerminal lines={logLines} scanning={loading} />
          </div>
        )}

        {/* Results */}
        {result && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 16, marginTop: 4 }}>
            <div style={{ borderTop: '1px solid var(--border)', paddingTop: 16 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 12 }}>
                <CheckCircle size={15} color="#22C55E" />
                <span style={{ fontSize: 13, fontWeight: 700, color: 'var(--text)' }}>Scan Results</span>
                <span style={{ fontSize: 11, color: 'var(--text3)', marginLeft: 'auto' }}>{new Date().toLocaleString()}</span>
              </div>
              <SummaryBar result={result} />
            </div>

            {mode !== 'combined' && (
              <FindingsList findings={result.findings || []} type={mode === 'dast' ? 'dast' : 'sast'} />
            )}

            {mode === 'combined' && (
              <>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '8px 12px', background: 'rgba(59,130,246,0.06)', border: '1px solid rgba(59,130,246,0.15)', borderRadius: 8 }}>
                    <FileCode size={14} color="var(--accent)" />
                    <span style={{ fontSize: 12, fontWeight: 700, color: 'var(--accent)' }}>SAST Findings ({result.sast?.findings_count || 0})</span>
                    {result.sast?.error && <span style={{ fontSize: 11, color: '#EF4444', marginLeft: 'auto' }}>⚠ {result.sast.error}</span>}
                  </div>
                  <FindingsList findings={result.sast?.findings || []} type="sast" />
                </div>

                <div style={{ borderTop: '1px solid var(--border)', paddingTop: 16, display: 'flex', flexDirection: 'column', gap: 8 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '8px 12px', background: 'rgba(234,88,12,0.06)', border: '1px solid rgba(234,88,12,0.15)', borderRadius: 8 }}>
                    <Globe size={14} color="#EA580C" />
                    <span style={{ fontSize: 12, fontWeight: 700, color: '#EA580C' }}>DAST Findings ({result.dast?.findings_count || 0})</span>
                    {result.dast?.error && <span style={{ fontSize: 11, color: '#EF4444', marginLeft: 'auto' }}>⚠ {result.dast.error}</span>}
                  </div>
                  <FindingsList findings={result.dast?.findings || []} type="dast" />
                </div>
              </>
            )}
          </div>
        )}
      {/* Email Report Modal */}
      {emailModal && (
        <div style={{
          position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.6)',
          display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 9999,
        }} onClick={(e) => { if (e.target === e.currentTarget) { setEmailModal(false); setEmailTo(''); } }}>
          <div style={{
            background: 'var(--surface)', border: '1px solid var(--border2)',
            borderRadius: 14, padding: 28, width: '100%', maxWidth: 440,
            boxShadow: '0 20px 60px rgba(0,0,0,0.5)',
          }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 20 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <Mail size={16} style={{ color: 'var(--accent)' }} />
                <span style={{ fontSize: 15, fontWeight: 700 }}>Email Report</span>
              </div>
              <button onClick={() => { setEmailModal(false); setEmailTo(''); setEmailSending(false); }}
                style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text3)', fontSize: 18 }}>×</button>
            </div>
            <div style={{ marginBottom: 14 }}>
              <label style={{ fontSize: 11, color: 'var(--text3)', fontWeight: 600, display: 'block', marginBottom: 6, textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                RECIPIENT EMAILS (comma separated)
              </label>
              <input
                className="input"
                type="text"
                placeholder="analyst@company.com, manager@company.com"
                value={emailTo}
                onChange={(e) => setEmailTo(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && sendEmailReport()}
                autoFocus
              />
            </div>
            <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
              <button className="btn btn-outline btn-sm"
                onClick={() => { setEmailModal(false); setEmailTo(''); setEmailSending(false); }}>
                Cancel
              </button>
              <button className="btn btn-primary btn-sm" onClick={sendEmailReport} disabled={emailSending}
                style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                {emailSending ? <><Loader2 size={13} className="animate-spin" /> Sending…</> : <><Mail size={13} /> Send Report</>}
              </button>
            </div>
          </div>
        </div>
      )}
      </div>
    </div>
  );
}