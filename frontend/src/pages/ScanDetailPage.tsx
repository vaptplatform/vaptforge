import React, { useEffect, useState, useRef, useCallback } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import {
  Download, Mail, XCircle, RefreshCw, Terminal, BarChart3,
  RefreshCcw, Send, Plus, X, Loader2, AlertTriangle, FileJson,
  Globe, FileText as FilePdf, CheckCircle2,
} from 'lucide-react';
import { scansAPI, findingsAPI, reportsAPI, downloadBlob } from '../services/api';
import { useWSLogs } from '../hooks/useWSLogs';
import { SevBadge, RiskScore, StatusDot, Modal } from '../components/shared/UI';
import DateDisplay from '../components/shared/DateDisplay';
import { formatDuration } from '../utils/dateUtils';
import { useToastStore, useUIStore } from '../store';
import type { Scan, Finding, LogLevel } from '../types';

const LOG_COLORS: Record<LogLevel, string> = {
  INFO:'#93C5FD', SCAN:'#D8B4FE', WARN:'#FDB87D',
  CRIT:'#FCA5A5', OK:'#86EFAC', ERROR:'#FCA5A5', DEBUG:'#64748B',
};

/* ── Safe number helper ─────────────────────── */
const safeNum = (v: unknown, decimals = 1): string => {
  const n = Number(v ?? 0);
  return isFinite(n) ? n.toFixed(decimals) : '0.' + '0'.repeat(decimals);
};

/* ── Regenerate & Send Modal ───────────────── */
function RegenerateModal({ open, onClose, scanId, targetUrl }: {
  open: boolean; onClose: () => void; scanId: string; targetUrl: string;
}) {
  const addToast = useToastStore(s => s.add);
  const [emails, setEmails]   = useState<string[]>(['']);
  const [sendEmail, setSend]  = useState(false);
  const [incPdf, setIncPdf]   = useState(true);
  const [loading, setLoading] = useState(false);
  const [done, setDone]       = useState<{success:boolean;msg:string}|null>(null);
  const mountedRef = useRef(true);

  // Reset state cleanly on open/close
  useEffect(() => {
    mountedRef.current = true;
    if (open) {
      setEmails(['']);
      setSend(false);
      setIncPdf(true);
      setLoading(false);
      setDone(null);
    }
    return () => { mountedRef.current = false; };
  }, [open]);

  const run = async () => {
    setLoading(true);
    try {
      const valid = emails.filter(e => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e.trim()));
      const { data } = await reportsAPI.regenerate(scanId, sendEmail ? valid : [], sendEmail, incPdf);
      if (!mountedRef.current) return;
      const emailMsg = sendEmail
        ? (data.email_sent ? ' Email sent ✓' : ' Email failed — check SMTP in .env')
        : '';
      setDone({ success: true, msg: `Report rebuilt with ${data.findings_count ?? 0} findings.${emailMsg}` });
      addToast(data.email_sent || !sendEmail ? 'success' : 'warn', 'Report regenerated');
    } catch (err: any) {
      if (!mountedRef.current) return;
      const msg = err?.response?.data?.detail ?? 'Regeneration failed';
      setDone({ success: false, msg });
      addToast('error', msg);
    } finally {
      if (mountedRef.current) setLoading(false);
    }
  };

  const reset = () => { setDone(null); setEmails(['']); setSend(false); };
  const handleClose = () => { reset(); onClose(); };

  return (
    <Modal open={open} onClose={handleClose} title="Re-Generate & Send Report" width={520}>
      {done ? (
        <div style={{ textAlign:'center', padding:'20px 0' }}>
          <div style={{ fontSize:36, marginBottom:12 }}>{done.success ? '✅' : '❌'}</div>
          <p style={{ color: done.success ? '#86EFAC' : '#FCA5A5', fontWeight:600, fontSize:15, marginBottom:8 }}>{done.success ? 'Done!' : 'Failed'}</p>
          <p style={{ color:'var(--text2)', fontSize:13, marginBottom:20 }}>{done.msg}</p>
          <div style={{ display:'flex', gap:8, justifyContent:'center' }}>
            <button className="btn btn-outline btn-sm" onClick={reset}>Try Again</button>
            <button className="btn btn-primary btn-sm" onClick={handleClose}>Close</button>
          </div>
        </div>
      ) : (
        <div style={{ display:'flex', flexDirection:'column', gap:16 }}>
          <div style={{ background:'var(--surface2)', border:'1px solid var(--border)', borderRadius:8, padding:'10px 14px' }}>
            <p style={{ fontSize:10, color:'var(--text3)', marginBottom:2 }}>TARGET</p>
            <p style={{ fontSize:13, color:'var(--accent2)', fontFamily:'monospace' }}>{targetUrl}</p>
          </div>
          <div style={{ background:'rgba(59,130,246,0.06)', border:'1px solid rgba(59,130,246,0.2)', borderRadius:8, padding:'10px 14px', fontSize:12, color:'var(--text2)', lineHeight:1.6 }}>
            Rebuilds the report from latest scan data and regenerates the PDF.
          </div>
          <label style={{ display:'flex', alignItems:'center', gap:10, cursor:'pointer' }}>
            <input type="checkbox" checked={sendEmail} onChange={e => setSend(e.target.checked)} style={{ accentColor:'var(--accent)', width:15, height:15 }}/>
            <span style={{ fontSize:13, color:'var(--text2)', fontWeight:500 }}>Send by email after regeneration</span>
          </label>
          {sendEmail && (
            <div style={{ display:'flex', flexDirection:'column', gap:8 }}>
              <label style={{ fontSize:11, color:'var(--text3)', fontWeight:600 }}>RECIPIENTS</label>
              {emails.map((email, i) => (
                <div key={i} style={{ display:'flex', gap:6 }}>
                  <input className="input" type="email" placeholder="security@company.com"
                    value={email} onChange={e => setEmails(prev => prev.map((x,idx) => idx===i ? e.target.value : x))} />
                  {emails.length > 1 && (
                    <button type="button" onClick={() => setEmails(prev => prev.filter((_,idx) => idx !== i))}
                      className="btn btn-ghost" style={{ padding:'6px 10px', color:'#EF4444' }}><X size={14}/></button>
                  )}
                </div>
              ))}
              {emails.length < 10 && (
                <button type="button" onClick={() => setEmails(prev => [...prev, ''])} className="btn btn-ghost btn-sm">
                  <Plus size={13}/> Add recipient
                </button>
              )}
              <label style={{ display:'flex', alignItems:'center', gap:10, cursor:'pointer' }}>
                <input type="checkbox" checked={incPdf} onChange={e => setIncPdf(e.target.checked)} style={{ accentColor:'var(--accent)', width:14, height:14 }}/>
                <span style={{ fontSize:12, color:'var(--text2)' }}>Attach PDF</span>
              </label>
            </div>
          )}
          <div style={{ display:'flex', gap:8, justifyContent:'flex-end' }}>
            <button className="btn btn-outline btn-sm" onClick={handleClose}>Cancel</button>
            <button className="btn btn-primary btn-sm" onClick={run} disabled={loading}>
              {loading
                ? <><Loader2 size={13} className="animate-spin"/> Processing…</>
                : <><RefreshCcw size={13}/> {sendEmail ? 'Regenerate & Send' : 'Regenerate'}</>}
            </button>
          </div>
        </div>
      )}
    </Modal>
  );
}

/* ── Send Report Modal ─────────────────────── */
function SendReportModal({ open, onClose, scanId, targetUrl }: {
  open: boolean; onClose: () => void; scanId: string; targetUrl: string;
}) {
  const addToast = useToastStore(s => s.add);
  const [emails, setEmails]     = useState<string[]>(['']);
  const [message, setMessage]   = useState('');
  const [incPdf, setIncPdf]     = useState(true);
  const [loading, setLoading]   = useState(false);
  const [sent, setSent]         = useState(false);
  const mountedRef = useRef(true);

  // ── Fully reset all state whenever the modal opens OR closes ──
  useEffect(() => {
    mountedRef.current = true;
    if (open) {
      setEmails(['']);
      setMessage('');
      setIncPdf(true);
      setLoading(false);   // ← critical: prevents stale "Sending…" on reopen
      setSent(false);
    }
    return () => { mountedRef.current = false; };
  }, [open]);

  const handleClose = useCallback(() => {
    // Synchronously reset before calling onClose so parent re-mount sees clean state
    setLoading(false);
    setSent(false);
    setEmails(['']);
    setMessage('');
    onClose();
  }, [onClose]);

  const send = async () => {
    const valid = emails.filter(e => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e.trim()));
    if (!valid.length) { addToast('error', 'Enter at least one valid email'); return; }
    setLoading(true);
    try {
      const { data } = await reportsAPI.regenerate(scanId, valid, true, incPdf);
      if (!mountedRef.current) return;
      if (data.email_sent) {
        setSent(true);
        addToast('success', `Report emailed successfully to ${valid.length} recipient${valid.length > 1 ? 's' : ''}`);
        setTimeout(() => { if (mountedRef.current) handleClose(); }, 2200);
      } else {
        addToast('warn', 'Report ready but email not sent — configure SMTP in .env');
      }
    } catch (err: any) {
      if (!mountedRef.current) return;
      addToast('error', err?.response?.data?.detail ?? 'Send failed');
    } finally {
      // Always reset loading — even on success, so reopen shows "Send Report"
      if (mountedRef.current) setLoading(false);
    }
  };

  return (
    <Modal open={open} onClose={handleClose} title="Email Security Report" width={500}>
      {sent ? (
        <div style={{ textAlign:'center', padding:'24px 0' }}>
          <CheckCircle2 size={48} style={{ color:'#22C55E', margin:'0 auto 14px' }} />
          <p style={{ color:'#86EFAC', fontWeight:700, fontSize:16, marginBottom:6 }}>Report Emailed Successfully!</p>
          <p style={{ color:'var(--text3)', fontSize:12 }}>Closing automatically…</p>
          <button className="btn btn-outline btn-sm" style={{ marginTop:18 }} onClick={handleClose}>Close Now</button>
        </div>
      ) : (
        <div style={{ display:'flex', flexDirection:'column', gap:15 }}>
          {/* Target */}
          <div style={{ background:'var(--surface2)', border:'1px solid var(--border)', borderRadius:8, padding:'10px 14px' }}>
            <p style={{ fontSize:10, color:'var(--text3)', marginBottom:2 }}>SCAN TARGET</p>
            <p style={{ fontSize:13, color:'var(--accent2)', fontFamily:'monospace', wordBreak:'break-all' }}>{targetUrl}</p>
          </div>

          {/* Recipients */}
          <div>
            <label style={{ fontSize:11, color:'var(--text3)', fontWeight:600, display:'block', marginBottom:8 }}>
              RECIPIENTS
            </label>
            {emails.map((e, i) => (
              <div key={i} style={{ display:'flex', gap:6, marginBottom:6 }}>
                <input className="input" type="email" placeholder="security@company.com"
                  value={e} onChange={ev => setEmails(prev => prev.map((x,idx) => idx===i ? ev.target.value : x))} />
                {emails.length > 1 && (
                  <button type="button" onClick={() => setEmails(prev => prev.filter((_,idx) => idx !== i))}
                    className="btn btn-ghost" style={{ padding:'6px 10px', color:'#EF4444' }}><X size={14}/></button>
                )}
              </div>
            ))}
            {emails.length < 10 && (
              <button type="button" onClick={() => setEmails(prev => [...prev, ''])} className="btn btn-ghost btn-sm" style={{ marginTop:2 }}>
                <Plus size={13}/> Add recipient
              </button>
            )}
          </div>

          {/* Optional message */}
          <div>
            <label style={{ fontSize:11, color:'var(--text3)', fontWeight:600, display:'block', marginBottom:5 }}>
              MESSAGE <span style={{ fontWeight:400, opacity:0.6 }}>(optional)</span>
            </label>
            <textarea
              className="input"
              rows={3}
              placeholder="Please find the VAPT security assessment report attached…"
              value={message}
              onChange={e => setMessage(e.target.value)}
              style={{ resize:'vertical', lineHeight:1.5 }}
            />
          </div>

          {/* Attach PDF toggle */}
          <label style={{ display:'flex', alignItems:'center', gap:10, cursor:'pointer' }}>
            <input type="checkbox" checked={incPdf} onChange={e => setIncPdf(e.target.checked)}
              style={{ accentColor:'var(--accent)', width:14, height:14 }} />
            <span style={{ fontSize:13, color:'var(--text2)' }}>Attach PDF report</span>
          </label>

          {/* Actions */}
          <div style={{ display:'flex', gap:8, justifyContent:'flex-end', paddingTop:4 }}>
            <button className="btn btn-outline btn-sm" onClick={handleClose} disabled={loading}>Cancel</button>
            <button className="btn btn-primary btn-sm" onClick={send} disabled={loading}>
              {loading
                ? <><Loader2 size={13} className="animate-spin"/> Sending…</>
                : <><Send size={13}/> Send Report</>}
            </button>
          </div>
        </div>
      )}
    </Modal>
  );
}

/* ── Main Page ─────────────────────────────── */
export default function ScanDetailPage() {
  const { id }    = useParams<{ id: string }>();
  const navigate  = useNavigate();
  const addToast  = useToastStore(s => s.add);
  const setActive = useUIStore(s => s.setActiveScan);

  const [scan,      setScan]     = useState<Scan | null>(null);
  const [findings,  setFindings] = useState<Finding[]>([]);
  const [tab,       setTab]      = useState<'terminal' | 'findings'>('terminal');
  const [sendOpen,  setSendOpen] = useState(false);
  const [regenOpen, setRegenOpen]= useState(false);
  const [dl,        setDl]       = useState('');
  const [loading,   setLoading]  = useState(true);
  const [error,     setError]    = useState('');
  const termRef = useRef<HTMLDivElement>(null);

  const { logs, progress, connected, scanComplete } = useWSLogs({
    scanId: id ?? null,
    enabled: !!id,
  });

  // Auto-scroll terminal
  useEffect(() => {
    if (termRef.current) termRef.current.scrollTop = termRef.current.scrollHeight;
  }, [logs]);

  const loadScan = async () => {
    if (!id) return;
    try {
      const { data } = await scansAPI.get(id);
      setScan(data);
      setError('');
      if (data.status === 'running') setActive(id);
      else setActive(null);
    } catch (err: any) {
      setError(err?.response?.data?.detail ?? 'Failed to load scan');
    } finally {
      setLoading(false);
    }
  };

  const loadFindings = async () => {
    if (!id) return;
    try {
      const { data } = await findingsAPI.list({ scan_id: id });
      setFindings(data.findings ?? []);
    } catch { /* silent */ }
  };

  useEffect(() => {
    loadScan();
    loadFindings();
    const t = setInterval(() => { loadScan(); loadFindings(); }, 8000);
    return () => clearInterval(t);
  }, [id]); // eslint-disable-line

  useEffect(() => {
    if (scanComplete) setTimeout(() => { loadScan(); loadFindings(); }, 1200);
  }, [scanComplete]); // eslint-disable-line

  const handleCancel = async () => {
    if (!id) return;
    try {
      await scansAPI.cancel(id);
      addToast('info', 'Scan cancelled');
      loadScan();
    } catch { addToast('error', 'Cancel failed'); }
  };

  const handleDownload = async (fmt: 'json' | 'html' | 'pdf') => {
    if (!id) return;
    setDl(fmt);
    const labels: Record<string, string> = {
      html: 'HTML report generated',
      pdf:  'PDF downloaded',
      json: 'JSON exported',
    };
    try {
      const fn = fmt === 'json' ? reportsAPI.downloadJson
               : fmt === 'html' ? reportsAPI.downloadHtml
               : reportsAPI.downloadPdf;
      const { data } = await fn(id);
      downloadBlob(data, `vapt_report_${id.slice(0, 8)}.${fmt}`);
      addToast('success', labels[fmt] ?? `${fmt.toUpperCase()} downloaded`);
    } catch {
      addToast('error', `Failed to generate ${fmt.toUpperCase()} report`);
    } finally { setDl(''); }
  };

  // ── Error / Loading states ──
  if (loading) return (
    <div style={{ display:'flex', alignItems:'center', justifyContent:'center', height:'60vh', flexDirection:'column', gap:12, color:'var(--text3)' }}>
      <Loader2 size={32} className="animate-spin" style={{ color:'var(--accent)' }}/>
      <p>Loading scan…</p>
    </div>
  );

  if (error || !scan) return (
    <div style={{ display:'flex', alignItems:'center', justifyContent:'center', height:'60vh', flexDirection:'column', gap:14 }}>
      <AlertTriangle size={40} style={{ color:'#EF4444' }}/>
      <p style={{ color:'var(--text)', fontWeight:600 }}>Scan not found</p>
      <p style={{ color:'var(--text3)', fontSize:13 }}>{error || 'The scan could not be loaded.'}</p>
      <button className="btn btn-outline btn-sm" onClick={() => navigate('/scans')}>← Back to scans</button>
    </div>
  );

  const isRunning     = scan.status === 'running' || scan.status === 'queued';
  const liveProgress  = isRunning ? (Number(progress) || 0) : (Number(scan.progress) || 0);
  const totalFindings = (scan.critical_count ?? 0) + (scan.high_count ?? 0) +
                        (scan.medium_count ?? 0)   + (scan.low_count ?? 0);

  return (
    <div className="fade-up" style={{ display:'flex', flexDirection:'column', gap:20 }}>

      {/* ── Header ── */}
      <div style={{ display:'flex', alignItems:'flex-start', justifyContent:'space-between', gap:12, flexWrap:'wrap' }}>
        <div>
          <div style={{ display:'flex', alignItems:'center', gap:10, marginBottom:6 }}>
            <StatusDot status={scan.status}/>
            <h1 style={{ fontSize:17, fontWeight:800, color:'var(--text)', fontFamily:'monospace', wordBreak:'break-all' }}>
              {scan.target_url}
            </h1>
          </div>
          <div style={{ display:'flex', gap:20, flexWrap:'wrap' }}>
            <div>
              <p style={{ fontSize:10, color:'var(--text3)', textTransform:'uppercase', letterSpacing:'0.5px', marginBottom:2 }}>Started</p>
              <DateDisplay value={scan.started_at ?? scan.created_at} />
            </div>
            {scan.completed_at && (
              <div>
                <p style={{ fontSize:10, color:'var(--text3)', textTransform:'uppercase', letterSpacing:'0.5px', marginBottom:2 }}>Completed</p>
                <DateDisplay value={scan.completed_at} />
              </div>
            )}
            {scan.started_at && scan.completed_at && (
              <div>
                <p style={{ fontSize:10, color:'var(--text3)', textTransform:'uppercase', letterSpacing:'0.5px', marginBottom:2 }}>Duration</p>
                <p style={{ fontSize:13, color:'var(--text)', fontWeight:500 }}>
                  {formatDuration(scan.started_at, scan.completed_at)}
                </p>
              </div>
            )}
            <div>
              <p style={{ fontSize:10, color:'var(--text3)', textTransform:'uppercase', letterSpacing:'0.5px', marginBottom:2 }}>Profile</p>
              <p style={{ fontSize:13, color:'var(--text)', fontWeight:500 }}>{scan.profile}</p>
            </div>
          </div>
        </div>

        {/* ── Action buttons ── */}
        <div style={{ display:'flex', gap:6, flexWrap:'wrap', alignItems:'center' }}>
          {isRunning && (
            <button className="btn btn-danger btn-sm" onClick={handleCancel}>
              <XCircle size={13}/> Cancel
            </button>
          )}
          {scan.status === 'completed' && (
            <>
              <button className="btn btn-outline btn-sm" onClick={() => setRegenOpen(true)}>
                <RefreshCcw size={13}/> Re-Generate & Send
              </button>

              {/* ── Export Reports Group ── */}
              <div style={{
                display: 'flex', alignItems: 'stretch',
                background: 'var(--surface2)',
                border: '1px solid var(--border2)',
                borderRadius: 8, overflow: 'hidden',
                height: 32,
              }}>
                <span style={{
                  fontSize: 9, fontWeight: 700, color: 'var(--text3)',
                  padding: '0 10px', borderRight: '1px solid var(--border)',
                  textTransform: 'uppercase', letterSpacing: '0.7px',
                  display: 'flex', alignItems: 'center', whiteSpace: 'nowrap',
                  userSelect: 'none',
                }}>
                  Export Reports
                </span>

                {/* Email Report button — inside the export group */}
                <div style={{ position: 'relative' }} className="export-btn-wrap">
                  <button
                    className="btn btn-ghost btn-sm export-btn email-export-btn"
                    onClick={() => setSendOpen(true)}
                    aria-label="Email Report — Send report to recipients via email"
                    style={{
                      borderRadius: 0,
                      borderLeft: '1px solid var(--border)',
                      height: '100%',
                      padding: '0 11px',
                      gap: 5,
                      fontSize: 12,
                      fontWeight: 600,
                      transition: 'background 0.15s, color 0.15s',
                      color: 'var(--accent2)',
                    }}
                  >
                    <Mail size={12} />
                    <span>Email Report</span>
                  </button>
                  <div className="export-tooltip" role="tooltip">Send report to recipients via email</div>
                </div>

                {/* HTML / PDF / JSON export buttons */}
                {([
                  { fmt: 'html', label: 'Interactive HTML', icon: <Globe size={12}/>, tooltip: 'Best for browser viewing and sharing' },
                  { fmt: 'pdf',  label: 'Printable PDF',    icon: <FilePdf size={12}/>, tooltip: 'Best for official documentation and offline sharing' },
                  { fmt: 'json', label: 'Raw JSON Data',    icon: <FileJson size={12}/>, tooltip: 'Best for API integration and developers' },
                ] as const).map(({ fmt, label, icon, tooltip }) => (
                  <div key={fmt} style={{ position: 'relative' }} className="export-btn-wrap">
                    <button
                      className="btn btn-ghost btn-sm export-btn"
                      disabled={dl === fmt}
                      onClick={() => handleDownload(fmt)}
                      aria-label={`${label} — ${tooltip}`}
                      style={{
                        borderRadius: 0,
                        borderLeft: '1px solid var(--border)',
                        height: '100%',
                        padding: '0 11px',
                        gap: 5,
                        fontSize: 12,
                        fontWeight: 600,
                        transition: 'background 0.15s, color 0.15s',
                      }}
                    >
                      {dl === fmt
                        ? <Loader2 size={12} className="animate-spin"/>
                        : icon}
                      <span>{dl === fmt ? 'Downloading…' : label}</span>
                    </button>
                    <div className="export-tooltip" role="tooltip">{tooltip}</div>
                  </div>
                ))}
              </div>
            </>
          )}
          <button className="btn btn-ghost btn-sm" onClick={() => { loadScan(); loadFindings(); }} title="Refresh">
            <RefreshCw size={13}/>
          </button>
        </div>
      </div>

      {/* ── Progress bar ── */}
      {isRunning && (
        <div>
          <div style={{ display:'flex', justifyContent:'space-between', fontSize:11, color:'var(--text3)', marginBottom:6, fontFamily:'monospace' }}>
            <span>Scanning… {liveProgress.toFixed(0)}%</span>
            <span style={{ display:'flex', alignItems:'center', gap:5 }}>
              <span style={{ width:6, height:6, borderRadius:'50%', background: connected ? '#22C55E' : '#EF4444', display:'inline-block' }}/>
              WS {connected ? 'live' : 'reconnecting…'}
            </span>
          </div>
          <div className="progress-track">
            <div className="progress-fill" style={{ width:`${liveProgress}%` }}/>
          </div>
        </div>
      )}

      {/* ── Stats ── */}
      <div style={{ display:'grid', gridTemplateColumns:'repeat(5,1fr)', gap:10 }}>
        {[
          { label:'Critical', val: scan.critical_count ?? 0, color:'#EF4444' },
          { label:'High',     val: scan.high_count     ?? 0, color:'#F97316' },
          { label:'Medium',   val: scan.medium_count   ?? 0, color:'#EAB308' },
          { label:'Low/Info', val: scan.low_count      ?? 0, color:'#22C55E' },
          { label:'Risk Score',
            val: scan.risk_score != null ? safeNum(scan.risk_score) : '—',
            color: (scan.risk_score ?? 0) >= 7 ? '#EF4444' : '#F97316' },
        ].map(({ label, val, color }) => (
          <div key={label} className="card-sm" style={{ textAlign:'center' }}>
            <p style={{ fontSize:10, color:'var(--text3)', textTransform:'uppercase', marginBottom:4 }}>{label}</p>
            <p style={{ fontSize:24, fontWeight:800, color }}>{val}</p>
          </div>
        ))}
      </div>

      {/* ── Tabs ── */}
      <div style={{ display:'flex', gap:4, borderBottom:'1px solid var(--border)', paddingBottom:0 }}>
        {([
          ['terminal', `Live Terminal`, Terminal],
          ['findings', `Findings (${totalFindings})`, BarChart3],
        ] as const).map(([t, label, Icon]) => (
          <button key={t} onClick={() => setTab(t as 'terminal' | 'findings')}
            className="btn btn-ghost btn-sm"
            style={{
              borderBottom: tab === t ? '2px solid var(--accent)' : '2px solid transparent',
              borderRadius:0, color: tab === t ? 'var(--accent2)' : 'var(--text3)',
              marginBottom:-1, padding:'8px 14px',
            }}>
            <Icon size={13}/> {label}
          </button>
        ))}
      </div>

      {/* ── Terminal ── */}
      {tab === 'terminal' && (
        <div className="terminal" ref={termRef} style={{ height:420 }}>
          {logs.length === 0 ? (
            <p style={{ color:'var(--text3)' }}>
              {scan.status === 'queued'     ? '⏳ Queued — waiting to start…' :
               scan.status === 'completed'  ? '✓ Scan completed.' :
               scan.status === 'failed'     ? '✗ Scan failed.' :
               'Connecting to live log stream…'}
            </p>
          ) : logs.map((log, i) => (
            <div key={`${log.id ?? i}-${i}`} style={{ display:'flex', gap:10, padding:'1.5px 0', lineHeight:1.6 }}>
              <span style={{ color:'#475569', flexShrink:0, fontSize:11 }}>
                {new Date(log.timestamp).toLocaleTimeString()}
              </span>
              <span style={{
                background:`${LOG_COLORS[log.level as LogLevel] || '#64748B'}20`,
                color: LOG_COLORS[log.level as LogLevel] || '#64748B',
                padding:'0 6px', borderRadius:3, fontSize:10, fontWeight:700, flexShrink:0,
              }}>{log.level}</span>
              <span style={{ color:'var(--text2)', wordBreak:'break-all', fontSize:12 }}>
                {log.url && <span style={{ color:'var(--accent2)', marginRight:6 }}>{log.url}</span>}
                {log.message}
                {log.progress != null &&
                  <span style={{ color:'#475569', marginLeft:6 }}>[{Number(log.progress).toFixed(0)}%]</span>}
              </span>
            </div>
          ))}
        </div>
      )}

      {/* ── Findings ── */}
      {tab === 'findings' && (
        <div className="card" style={{ padding:0, overflow:'hidden' }}>
          {findings.length === 0 ? (
            <div style={{ padding:40, textAlign:'center', color:'var(--text3)' }}>
              {isRunning ? '🔍 Scan in progress — findings will appear here' : 'No findings detected'}
            </div>
          ) : (
            <table style={{ width:'100%', borderCollapse:'collapse', fontSize:12 }}>
              <thead style={{ background:'var(--surface2)' }}>
                <tr>
                  {['#','Vulnerability','OWASP','Endpoint','Severity','Risk','Confidence','Status'].map(h => (
                    <th key={h} style={{ padding:'10px 12px', textAlign:'left', fontSize:10,
                      color:'var(--text3)', fontWeight:600, textTransform:'uppercase',
                      borderBottom:'1px solid var(--border)', whiteSpace:'nowrap' }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {findings.map((f, idx) => (
                  <tr key={f.id}
                    style={{ borderBottom:'1px solid var(--border)' }}
                    onMouseEnter={e => (e.currentTarget.style.background='var(--surface2)')}
                    onMouseLeave={e => (e.currentTarget.style.background='transparent')}>
                    <td style={{ padding:'10px 12px', color:'var(--text3)', fontSize:11, fontFamily:'monospace' }}>
                      {idx + 1}
                    </td>
                    <td style={{ padding:'10px 12px', color:'var(--text)', fontWeight:500,
                      maxWidth:200, overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap' }}>
                      {f.title}
                    </td>
                    <td style={{ padding:'10px 12px', fontFamily:'monospace', fontSize:11, color:'var(--text3)' }}>
                      {f.owasp_category}
                    </td>
                    <td style={{ padding:'10px 12px', fontFamily:'monospace', fontSize:11,
                      color:'var(--accent2)', maxWidth:160, overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap' }}>
                      {f.affected_url}
                    </td>
                    <td style={{ padding:'10px 12px' }}><SevBadge sev={f.severity}/></td>
                    <td style={{ padding:'10px 12px' }}><RiskScore score={f.risk_score}/></td>
                    <td style={{ padding:'10px 12px', fontFamily:'monospace', fontSize:11, color:'var(--text2)' }}>
                      {safeNum((f.confidence ?? 0) * 100, 0)}%
                    </td>
                    <td style={{ padding:'10px 12px', fontFamily:'monospace', fontSize:10,
                      color: f.status==='fixed' ? '#22C55E'
                           : f.status==='false_positive' ? '#64748B' : '#F97316' }}>
                      {f.status}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}

      {/* ── Modals ── */}
      <RegenerateModal open={regenOpen} onClose={() => setRegenOpen(false)}
        scanId={scan.id} targetUrl={scan.target_url} />
      <SendReportModal open={sendOpen} onClose={() => setSendOpen(false)}
        scanId={scan.id} targetUrl={scan.target_url} />
    </div>
  );
}
