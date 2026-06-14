import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { scansAPI } from '../services/api';
import { StatusDot, RiskScore, EmptyState } from '../components/shared/UI';
import DateDisplay from '../components/shared/DateDisplay';
import { formatDuration } from '../utils/dateUtils';
import type { Scan } from '../types';
import { List, RefreshCw, Play, Trash2 } from 'lucide-react';

export default function ScanHistoryPage() {
  const [scans,    setScans]    = useState<Scan[]>([]);
  const [filter,   setFilter]   = useState('');
  const [loading,  setLoad]     = useState(true);
  const [deleting, setDeleting] = useState<string | null>(null);
  const navigate = useNavigate();

  const handleDelete = async (e: React.MouseEvent, scanId: string) => {
    e.stopPropagation();
    if (!window.confirm('Are you sure you want to delete this scan?')) return;
    setDeleting(scanId);
    try {
      await scansAPI.delete(scanId);
      setScans(prev => prev.filter(s => s.id !== scanId));
    } catch {
      alert('Failed to delete scan.');
    } finally {
      setDeleting(null);
    }
  };

  const load = () => {
    setLoad(true);
    scansAPI.list(1, filter || undefined)
      .then(r => setScans(r.data.scans ?? []))
      .catch(() => setScans([]))
      .finally(() => setLoad(false));
  };

  useEffect(() => { load(); }, [filter]); // eslint-disable-line

  return (
    <div className="fade-up" style={{ display:'flex', flexDirection:'column', gap:16 }}>
      <div style={{ display:'flex', alignItems:'center', justifyContent:'space-between' }}>
        <div>
          <h1 style={{ fontSize:20, fontWeight:800, color:'var(--text)' }}>Scan History</h1>
          <p style={{ fontSize:12, color:'var(--text3)', marginTop:2 }}>{scans.length} scans</p>
        </div>
        <div style={{ display:'flex', gap:8 }}>
          <select className="input" style={{ width:160 }} value={filter} onChange={e => setFilter(e.target.value)}>
            <option value="">All Status</option>
            {['running','completed','failed','cancelled','queued'].map(s =>
              <option key={s} value={s}>{s.charAt(0).toUpperCase()+s.slice(1)}</option>
            )}
          </select>
          <button className="btn btn-outline btn-sm" onClick={load}><RefreshCw size={13}/> Refresh</button>
          <button className="btn btn-primary btn-sm" onClick={() => navigate('/scans/new')}><Play size={13}/> New Scan</button>
        </div>
      </div>

      {loading && !scans.length ? (
        <div style={{ textAlign:'center', color:'var(--text3)', padding:40 }}>Loading…</div>
      ) : !scans.length ? (
        <EmptyState icon={<List size={40}/>} title="No scans found"
          desc="Launch your first scan to get started."
          action={<button className="btn btn-primary btn-sm" onClick={() => navigate('/scans/new')}>New Scan</button>}/>
      ) : (
        <div className="card" style={{ padding:0, overflow:'hidden' }}>
          <table style={{ width:'100%', borderCollapse:'collapse', fontSize:12 }}>
            <thead style={{ background:'var(--surface2)' }}>
              <tr>
                {['Target','Profile','Status','Crit','High','Med','Risk','Duration','Date',''].map(h => (
                  <th key={h} style={{ padding:'10px 12px', textAlign:'left', fontSize:10,
                    color:'var(--text3)', fontWeight:600, textTransform:'uppercase',
                    borderBottom:'1px solid var(--border)', whiteSpace:'nowrap' }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {scans.map(s => (
                <tr key={s.id} onClick={() => navigate(`/scans/${s.id}`)}
                  style={{ borderBottom:'1px solid var(--border)', cursor:'pointer' }}
                  onMouseEnter={e => (e.currentTarget.style.background='var(--surface2)')}
                  onMouseLeave={e => (e.currentTarget.style.background='transparent')}>
                  <td style={{ padding:'10px 12px' }}>
                    <div style={{ display:'flex', alignItems:'center', gap:8 }}>
                      <StatusDot status={s.status}/>
                      <span style={{ fontFamily:'monospace', fontSize:11, color:'var(--accent2)',
                        maxWidth:170, overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap' }}>
                        {s.target_domain}
                      </span>
                    </div>
                  </td>
                  <td style={{ padding:'10px 12px', fontSize:11, color:'var(--text3)' }}>{s.profile}</td>
                  <td style={{ padding:'10px 12px' }}>
                    <span style={{ fontSize:10, fontFamily:'monospace', padding:'2px 7px', borderRadius:4,
                      background: s.status==='completed'?'rgba(59,130,246,0.1)':s.status==='running'?'rgba(34,197,94,0.1)':s.status==='failed'?'rgba(239,68,68,0.1)':'rgba(100,116,139,0.1)',
                      color:      s.status==='completed'?'#93C5FD':s.status==='running'?'#86EFAC':s.status==='failed'?'#FCA5A5':'#94A3B8' }}>
                      {s.status}
                    </span>
                  </td>
                  <td style={{ padding:'10px 12px', fontFamily:'monospace', color:(s.critical_count??0)>0?'#EF4444':'var(--text3)', fontWeight:(s.critical_count??0)>0?700:400 }}>{s.critical_count??0}</td>
                  <td style={{ padding:'10px 12px', fontFamily:'monospace', color:(s.high_count??0)>0?'#F97316':'var(--text3)' }}>{s.high_count??0}</td>
                  <td style={{ padding:'10px 12px', fontFamily:'monospace', color:(s.medium_count??0)>0?'#EAB308':'var(--text3)' }}>{s.medium_count??0}</td>
                  <td style={{ padding:'10px 12px' }}><RiskScore score={s.risk_score}/></td>
                  <td style={{ padding:'10px 12px', fontSize:11, color:'var(--text3)', fontFamily:'monospace' }}>
                    {formatDuration(s.started_at, s.completed_at)}
                  </td>
                  {/* FIXED: Both exact + relative date */}
                  <td style={{ padding:'10px 12px' }}>
                    <DateDisplay value={s.created_at}
                      exactStyle={{ fontSize:12 }}
                      relativeStyle={{ fontSize:10 }}/>
                  </td>
                  <td style={{ padding:'10px 8px' }}>
                    <div style={{ display:'flex', gap:4 }}>
                      <button className="btn btn-ghost btn-sm"
                        onClick={e => { e.stopPropagation(); navigate(`/scans/${s.id}`); }}
                        style={{ fontSize:11 }}>View →</button>
                      <button className="btn btn-ghost btn-sm"
                        onClick={e => handleDelete(e, s.id)}
                        disabled={deleting === s.id || s.status === 'running' || s.status === 'queued'}
                        style={{ fontSize:11, color:'#EF4444', opacity: (s.status === 'running' || s.status === 'queued') ? 0.4 : 1 }}
                        title={s.status === 'running' || s.status === 'queued' ? 'Cancel scan before deleting' : 'Delete scan'}>
                        {deleting === s.id ? '…' : <Trash2 size={13}/>}
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
  );
}