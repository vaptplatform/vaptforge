import React, { useEffect, useState } from 'react';
import { FileText, Download, Mail, FileJson, RefreshCcw, Loader2 } from 'lucide-react';
import { scansAPI, reportsAPI, downloadBlob } from '../services/api';
import { useToastStore } from '../store';
import { RiskScore, StatusDot, Modal } from '../components/shared/UI';
import type { Scan } from '../types';
import { formatDistanceToNow } from 'date-fns';
import { X, Plus, Send } from 'lucide-react';

/* ── Quick email send modal ─────────────────────────────────────────────── */
function QuickEmailModal({ scan, open, onClose }: {
  scan: Scan; open: boolean; onClose: () => void;
}) {
  const addToast = useToastStore(s => s.add);
  const [emails, setEmails]   = useState(['']);
  const [loading, setLoading] = useState(false);
  const [sent, setSent]       = useState(false);

  const addEmail = () => setEmails(e => [...e, '']);
  const rmEmail  = (i: number) => setEmails(e => e.filter((_,idx) => idx !== i));
  const setEmail = (i: number, v: string) => setEmails(e => e.map((x,idx) => idx===i ? v : x));

  const send = async () => {
    const valid = emails.filter(e => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e));
    if (!valid.length) { addToast('error', 'Enter at least one valid email'); return; }
    setLoading(true);
    try {
      const { data } = await reportsAPI.regenerate(scan.id, valid, true, true);
      if (data.email_sent) {
        setSent(true);
        addToast('success', `Report sent to ${valid.length} recipient(s)`);
      } else {
        addToast('warn', 'Report generated but email not sent — configure SMTP in .env');
      }
    } catch (err: any) {
      addToast('error', err.response?.data?.detail ?? 'Send failed');
    } finally { setLoading(false); }
  };

  return (
    <Modal open={open} onClose={onClose} title="Email Report" width={480}>
      {sent ? (
        <div style={{ textAlign:'center', padding:'20px 0' }}>
          <div style={{ fontSize:36, marginBottom:10 }}>✓</div>
          <p style={{ color:'#86EFAC', fontWeight:600 }}>Report sent!</p>
          <button className="btn btn-outline btn-sm" style={{ marginTop:16 }} onClick={onClose}>Close</button>
        </div>
      ) : (
        <div style={{ display:'flex', flexDirection:'column', gap:14 }}>
          <div style={{ background:'var(--surface2)', borderRadius:8, padding:'10px 14px', fontSize:12 }}>
            <p style={{ color:'var(--text3)', marginBottom:2, fontSize:10 }}>SCAN</p>
            <p style={{ color:'#60A5FA', fontFamily:'monospace' }}>{scan.target_url}</p>
          </div>
          <div>
            <label style={{ fontSize:11, color:'var(--text3)', fontWeight:600, display:'block', marginBottom:8 }}>RECIPIENTS</label>
            {emails.map((e,i) => (
              <div key={i} style={{ display:'flex', gap:6, marginBottom:6 }}>
                <input className="input" type="email" placeholder="security@company.com"
                  value={e} onChange={ev => setEmail(i, ev.target.value)} />
                {emails.length > 1 && (
                  <button type="button" onClick={() => rmEmail(i)}
                    className="btn btn-ghost" style={{ padding:'6px 10px', color:'#FCA5A5' }}>
                    <X size={14}/>
                  </button>
                )}
              </div>
            ))}
            {emails.length < 10 && (
              <button type="button" onClick={addEmail} className="btn btn-ghost btn-sm">
                <Plus size={13}/> Add
              </button>
            )}
          </div>
          <div style={{ display:'flex', gap:8, justifyContent:'flex-end' }}>
            <button className="btn btn-outline btn-sm" onClick={onClose}>Cancel</button>
            <button className="btn btn-primary btn-sm" onClick={send} disabled={loading}>
              {loading ? <><Loader2 size={13}/> Sending…</> : <><Send size={13}/> Send</>}
            </button>
          </div>
        </div>
      )}
    </Modal>
  );
}

/* ── Reports Page ───────────────────────────────────────────────────────── */
export default function ReportsPage() {
  const [scans, setScans]     = useState<Scan[]>([]);
  const [allScans, setAll]    = useState<Scan[]>([]);
  const [filter, setFilter]   = useState('completed');
  const addToast = useToastStore(s => s.add);
  const [dl, setDl]           = useState<{id:string;fmt:string}|null>(null);
  const [regen, setRegen]     = useState<{id:string;loading:boolean}|null>(null);
  const [emailScan, setEmail] = useState<Scan|null>(null);

  useEffect(() => {
    scansAPI.list(1, filter || undefined).then(r => setScans(r.data.scans));
    scansAPI.list(1).then(r => setAll(r.data.scans));
  }, [filter]);

  const download = async (scan: Scan, fmt: 'html'|'pdf'|'json') => {
    setDl({ id: scan.id, fmt });
    try {
      const fn = fmt==='html' ? reportsAPI.downloadHtml : fmt==='pdf' ? reportsAPI.downloadPdf : reportsAPI.downloadJson;
      const { data } = await fn(scan.id);
      downloadBlob(data, `vapt_report_${scan.id.slice(0,8)}.${fmt}`);
      addToast('success', `${fmt.toUpperCase()} downloaded`);
    } catch { addToast('error', `Failed to generate ${fmt.toUpperCase()}`); }
    finally { setDl(null); }
  };

  const regenerate = async (scan: Scan) => {
    setRegen({ id: scan.id, loading: true });
    try {
      const { data } = await reportsAPI.regenerate(scan.id, [], false, true);
      addToast('success', `Report regenerated — ${data.findings_count} findings`);
    } catch { addToast('error', 'Regeneration failed'); }
    finally { setRegen(null); }
  };

  const stats = {
    total: allScans.length,
    completed: allScans.filter(s => s.status==='completed').length,
    critical: allScans.reduce((a,s) => a + s.critical_count, 0),
    high: allScans.reduce((a,s) => a + s.high_count, 0),
  };

  return (
    <div className="fade-up" style={{ display:'flex', flexDirection:'column', gap:20 }}>
      <div>
        <h1 style={{ fontSize:20, fontWeight:800, color:'var(--text)' }}>Reports</h1>
        <p style={{ fontSize:12, color:'var(--text3)', marginTop:2 }}>
          Generate and share professional security audit reports
        </p>
      </div>

      {/* Stats */}
      <div style={{ display:'grid', gridTemplateColumns:'repeat(4,1fr)', gap:12 }}>
        {[
          { label:'Total Scans',      val: stats.total,     color:'var(--accent2)' },
          { label:'Completed',        val: stats.completed, color:'#22C55E' },
          { label:'Critical Findings',val: stats.critical,  color:'#EF4444' },
          { label:'High Findings',    val: stats.high,      color:'#F97316' },
        ].map(({ label, val, color }) => (
          <div key={label} className="card-sm" style={{ textAlign:'center' }}>
            <p style={{ fontSize:10, color:'var(--text3)', textTransform:'uppercase', marginBottom:4 }}>{label}</p>
            <p style={{ fontSize:26, fontWeight:800, color }}>{val}</p>
          </div>
        ))}
      </div>

      {/* Format cards */}
      <div style={{ display:'grid', gridTemplateColumns:'repeat(3,1fr)', gap:12 }}>
        {[
          { fmt:'HTML', icon:<FileText size={22}/>, desc:'Interactive report with charts, findings and evidence', color:'#3B82F6' },
          { fmt:'PDF',  icon:<FileText size={22}/>, desc:'Professional audit PDF for compliance and executives', color:'#EF4444' },
          { fmt:'JSON', icon:<FileJson size={22}/>, desc:'Machine-readable output for SIEM/SOAR/CI/CD pipelines', color:'#22C55E' },
        ].map(({ fmt, icon, desc, color }) => (
          <div key={fmt} className="card" style={{ textAlign:'center',
            background:`${color}08`, border:`1px solid ${color}25` }}>
            <div style={{ color, margin:'0 auto 10px', width:42, height:42,
              background:`${color}15`, borderRadius:10,
              display:'flex', alignItems:'center', justifyContent:'center' }}>{icon}</div>
            <p style={{ fontSize:14, fontWeight:700, color:'var(--text)', marginBottom:5 }}>{fmt} Report</p>
            <p style={{ fontSize:11, color:'var(--text3)', lineHeight:1.5 }}>{desc}</p>
          </div>
        ))}
      </div>

      {/* Table */}
      <div className="card" style={{ padding:0, overflow:'hidden' }}>
        <div style={{ padding:'14px 20px', borderBottom:'1px solid var(--border)',
          display:'flex', alignItems:'center', justifyContent:'space-between' }}>
          <p className="card-title" style={{ marginBottom:0 }}>Scan Reports</p>
          <select className="input" style={{ width:160 }} value={filter}
            onChange={e => setFilter(e.target.value)}>
            <option value="">All Status</option>
            <option value="completed">Completed</option>
            <option value="failed">Failed</option>
          </select>
        </div>
        <table style={{ width:'100%', borderCollapse:'collapse', fontSize:12 }}>
          <thead style={{ background:'var(--surface2)' }}>
            <tr>
              {['Target','Status','Risk','Findings','Date','Actions'].map(h => (
                <th key={h} style={{ padding:'10px 12px', textAlign:'left', fontSize:10,
                  color:'var(--text3)', fontWeight:600, textTransform:'uppercase',
                  borderBottom:'1px solid var(--border)' }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {scans.map(s => (
              <tr key={s.id} style={{ borderBottom:'1px solid var(--border)' }}
                onMouseEnter={e => (e.currentTarget.style.background='var(--surface2)')}
                onMouseLeave={e => (e.currentTarget.style.background='transparent')}>
                <td style={{ padding:'10px 12px' }}>
                  <div style={{ display:'flex', alignItems:'center', gap:8 }}>
                    <StatusDot status={s.status}/>
                    <span style={{ fontFamily:'monospace', fontSize:11, color:'var(--accent2)',
                      maxWidth:160, overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap' }}>
                      {s.target_domain}
                    </span>
                  </div>
                </td>
                <td style={{ padding:'10px 12px' }}>
                  <span style={{ fontSize:10, fontFamily:'monospace', padding:'2px 7px',
                    borderRadius:4,
                    background: s.status==='completed'?'rgba(59,130,246,0.1)':'rgba(100,116,139,0.1)',
                    color: s.status==='completed'?'#93C5FD':'#94A3B8' }}>
                    {s.status}
                  </span>
                </td>
                <td style={{ padding:'10px 12px' }}><RiskScore score={s.risk_score}/></td>
                <td style={{ padding:'10px 12px', fontSize:11, fontFamily:'monospace' }}>
                  <span style={{ color:'#EF4444' }}>{s.critical_count}C </span>
                  <span style={{ color:'#F97316' }}>{s.high_count}H </span>
                  <span style={{ color:'#EAB308' }}>{s.medium_count}M</span>
                </td>
                <td style={{ padding:'10px 12px', fontSize:11, color:'var(--text3)' }}>
                  {formatDistanceToNow(new Date(s.created_at), { addSuffix:true })}
                </td>
                <td style={{ padding:'10px 8px' }}>
                  <div style={{ display:'flex', gap:4, flexWrap:'wrap' }}>
                    {/* Re-generate */}
                    <button className="btn btn-outline btn-sm"
                      disabled={regen?.id===s.id}
                      onClick={() => regenerate(s)}
                      style={{ fontSize:10, padding:'4px 8px' }}
                      title="Re-generate report">
                      {regen?.id===s.id
                        ? <Loader2 size={11} style={{ animation:'spin 0.8s linear infinite' }}/>
                        : <RefreshCcw size={11}/>}
                    </button>
                    {/* Email */}
                    <button className="btn btn-outline btn-sm"
                      onClick={() => setEmail(s)}
                      style={{ fontSize:10, padding:'4px 8px' }} title="Email report">
                      <Mail size={11}/>
                    </button>
                    {/* Downloads */}
                    {(['html','pdf','json'] as const).map(fmt => (
                      <button key={fmt} className="btn btn-outline btn-sm"
                        disabled={dl?.id===s.id && dl?.fmt===fmt}
                        onClick={() => download(s, fmt)}
                        style={{ fontSize:10, padding:'4px 8px' }}>
                        {dl?.id===s.id && dl?.fmt===fmt
                          ? <Loader2 size={11} style={{ animation:'spin 0.8s linear infinite' }}/>
                          : <><Download size={11}/> {fmt.toUpperCase()}</>}
                      </button>
                    ))}
                  </div>
                </td>
              </tr>
            ))}
            {!scans.length && (
              <tr><td colSpan={6} style={{ padding:30, textAlign:'center', color:'var(--text3)' }}>
                No scans found
              </td></tr>
            )}
          </tbody>
        </table>
      </div>

      {emailScan && (
        <QuickEmailModal scan={emailScan} open={!!emailScan}
          onClose={() => setEmail(null)} />
      )}
    </div>
  );
}
