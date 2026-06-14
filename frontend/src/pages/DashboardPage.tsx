import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Doughnut, Line } from 'react-chartjs-2';
import {
  Chart as ChartJS, ArcElement, Tooltip, Legend,
  CategoryScale, LinearScale, PointElement, LineElement, Filler,
} from 'chart.js';
import { RefreshCw, Play } from 'lucide-react';
import { scansAPI, findingsAPI } from '../services/api';
import { StatCard, SevBadge, StatusDot, RiskScore } from '../components/shared/UI';
import DateDisplay from '../components/shared/DateDisplay';
import { useUIStore } from '../store';
import type { Scan, Finding } from '../types';

ChartJS.register(ArcElement, Tooltip, Legend, CategoryScale, LinearScale, PointElement, LineElement, Filler);

const DONUT_OPTS: any = {
  responsive: true, maintainAspectRatio: false,
  plugins: { legend: { display: false } },
  cutout: '72%',
};

export default function DashboardPage() {
  const navigate = useNavigate();
  const { activeScanId } = useUIStore();
  const [scans,    setScans]    = useState<Scan[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading,  setLoading]  = useState(true);

  const [refreshing, setRefreshing] = useState(false);

  const load = async (manual = false) => {
    if (manual) setRefreshing(true);
    else setLoading(true);
    try {
      const [sRes, fRes] = await Promise.all([
        scansAPI.list(1),
        findingsAPI.list({ page: 1 }),
      ]);
      setScans(sRes.data.scans ?? []);
      setFindings(fRes.data.findings ?? []);
    } catch { /* silent */ }
    finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  useEffect(() => {
    load();
    const t = setInterval(() => load(false), 15000);
    return () => clearInterval(t);
  }, []); // eslint-disable-line

  // Aggregate stats — null-safe
  const totals = findings.reduce((acc, f) => {
    const k = f.severity ?? 'info';
    acc[k] = (acc[k] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);
  const critical = totals.critical || 0;
  const high     = totals.high     || 0;
  const medium   = totals.medium   || 0;
  const low      = (totals.low || 0) + (totals.info || 0);
  const total    = critical + high + medium + low;
  const running  = scans.filter(s => s.status === 'running');
  const topRisk  = scans
    .filter(s => s.risk_score != null)
    .sort((a, b) => (b.risk_score! - a.risk_score!))[0];

  const donutData = {
    labels: ['Critical','High','Medium','Low/Info'],
    datasets: [{
      data: [critical, high, medium, low],
      backgroundColor: ['#EF4444','#F97316','#EAB308','#22C55E'],
      borderWidth: 0, hoverOffset: 4,
    }],
  };

  const recentScans = [...scans].slice(0, 7).reverse();
  const lineData = {
    labels: recentScans.map(s => {
      const d = new Date(s.created_at);
      return isNaN(d.getTime()) ? '' : d.toLocaleDateString('en', { month:'short', day:'numeric' });
    }),
    datasets: [
      { label:'Critical', data: recentScans.map(s => s.critical_count ?? 0), borderColor:'#EF4444', backgroundColor:'rgba(239,68,68,0.07)', tension:0.4, fill:true, pointRadius:3 },
      { label:'High',     data: recentScans.map(s => s.high_count     ?? 0), borderColor:'#F97316', backgroundColor:'rgba(249,115,22,0.05)', tension:0.4, fill:true, pointRadius:3 },
    ],
  };
  const lineOpts: any = {
    responsive:true, maintainAspectRatio:false,
    plugins:{ legend:{ display:false } },
    scales:{
      x:{ grid:{ color:'rgba(100,116,139,0.1)' }, ticks:{ color:'var(--text3)', font:{ size:10 } } },
      y:{ grid:{ color:'rgba(100,116,139,0.1)' }, ticks:{ color:'var(--text3)', font:{ size:10 } } },
    },
  };

  if (loading && !scans.length) return (
    <div style={{ display:'flex', alignItems:'center', justifyContent:'center', height:'60vh', color:'var(--text3)' }}>
      Loading dashboard…
    </div>
  );

  return (
    <div className="fade-up" style={{ display:'flex', flexDirection:'column', gap:20 }}>

      {/* Header */}
      <div style={{ display:'flex', alignItems:'center', justifyContent:'space-between' }}>
        <div>
          <h1 style={{ fontSize:20, fontWeight:800, color:'var(--text)' }}>Security Dashboard</h1>
          <p style={{ fontSize:12, color:'var(--text3)', marginTop:2 }}>
            {total} findings across {scans.length} scans
          </p>
        </div>
        <div style={{ display:'flex', gap:8 }}>
          <button className="btn btn-outline btn-sm" onClick={() => load(true)} disabled={refreshing} style={{ minWidth: 90 }}><RefreshCw size={13} style={{ animation: refreshing ? 'spin 0.6s linear infinite' : 'none' }}/> {refreshing ? 'Refreshing…' : 'Refresh'}</button>
          <button className="btn btn-primary btn-sm" onClick={() => navigate('/scans/new')}><Play size={13}/> New Scan</button>
        </div>
      </div>

      {/* Active scan banner */}
      {running.length > 0 && (
        <div style={{ background:'rgba(34,197,94,0.06)', border:'1px solid rgba(34,197,94,0.25)', borderRadius:10, padding:'12px 16px', display:'flex', alignItems:'center', gap:10 }}>
          <StatusDot status="running"/>
          <span style={{ fontSize:13, color:'#86EFAC', fontWeight:600 }}>{running.length} scan{running.length > 1 ? 's':''} running</span>
          {running.map(s => (
            <button key={s.id} className="btn btn-sm"
              onClick={() => navigate(`/scans/${s.id}`)}
              style={{ background:'rgba(34,197,94,0.1)', color:'#86EFAC', border:'1px solid rgba(34,197,94,0.2)', fontFamily:'monospace', fontSize:11 }}>
              {s.target_domain} — {(s.progress ?? 0).toFixed(0)}%
            </button>
          ))}
        </div>
      )}

      {/* Stats */}
      <div style={{ display:'grid', gridTemplateColumns:'repeat(4,1fr)', gap:12 }}>
        <StatCard label="Critical"   value={critical} color="#EF4444" sub={`${high} high findings`}/>
        <StatCard label="Medium"     value={medium}   color="#F97316" sub="Needs attention"/>
        <StatCard label="Low / Info" value={low}      color="#EAB308" sub="Monitor"/>
        <StatCard label="Risk Score"
          value={topRisk ? <RiskScore score={topRisk.risk_score}/> : '—'}
          color="#F97316"
          sub={topRisk ? topRisk.target_domain : 'No scans yet'}/>
      </div>

      {/* Charts */}
      <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:16 }}>
        <div className="card">
          <p className="card-title">Vulnerability Trend</p>
          <div style={{ height:180, position:'relative' }}>
            {recentScans.length > 1
              ? <Line data={lineData} options={lineOpts}/>
              : <div style={{ display:'flex', alignItems:'center', justifyContent:'center', height:'100%', color:'var(--text3)', fontSize:12 }}>Run more scans to see trends</div>}
          </div>
        </div>
        <div className="card">
          <p className="card-title">Risk Distribution</p>
          <div style={{ display:'flex', alignItems:'center', gap:20 }}>
            <div style={{ height:160, width:160, flexShrink:0, position:'relative' }}>
              <Doughnut data={donutData} options={DONUT_OPTS}/>
              <div style={{ position:'absolute', inset:0, display:'flex', flexDirection:'column', alignItems:'center', justifyContent:'center' }}>
                <p style={{ fontSize:22, fontWeight:800, color:'var(--text)' }}>{total}</p>
                <p style={{ fontSize:10, color:'var(--text3)' }}>TOTAL</p>
              </div>
            </div>
            <div style={{ display:'flex', flexDirection:'column', gap:8, fontSize:12 }}>
              {[['Critical',critical,'#EF4444'],['High',high,'#F97316'],['Medium',medium,'#EAB308'],['Low/Info',low,'#22C55E']].map(([l,v,c]) => (
                <div key={l as string} style={{ display:'flex', alignItems:'center', gap:8 }}>
                  <span style={{ width:10, height:10, borderRadius:2, background:c as string, flexShrink:0, display:'inline-block' }}/>
                  <span style={{ color:'var(--text2)' }}>{l}</span>
                  <span style={{ marginLeft:'auto', fontFamily:'monospace', color:'var(--text)', fontWeight:600 }}>{v}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Recent findings + Scan history */}
      <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:16 }}>
        <div className="card">
          <div style={{ display:'flex', alignItems:'center', justifyContent:'space-between', marginBottom:14 }}>
            <p className="card-title" style={{ marginBottom:0 }}>Recent Findings</p>
            <button className="btn btn-ghost btn-sm" onClick={() => navigate('/findings')}>View all</button>
          </div>
          <table style={{ width:'100%', borderCollapse:'collapse', fontSize:12 }}>
            <thead>
              <tr style={{ borderBottom:'1px solid var(--border)' }}>
                {['Vulnerability','OWASP','Severity'].map(h => (
                  <th key={h} style={{ padding:'4px 8px', textAlign:'left', fontSize:10, color:'var(--text3)', fontWeight:600, textTransform:'uppercase', letterSpacing:'0.6px' }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {findings.slice(0, 7).map((f) => (
                <tr key={f.id} style={{ borderBottom:'1px solid var(--border)', cursor:'pointer' }}
                  onClick={() => navigate('/findings')}>
                  <td style={{ padding:'8px', color:'var(--text)', maxWidth:180, overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap' }}>{f.title}</td>
                  <td style={{ padding:'8px', fontFamily:'monospace', fontSize:11, color:'var(--text3)' }}>{f.owasp_category}</td>
                  <td style={{ padding:'8px' }}><SevBadge sev={f.severity}/></td>
                </tr>
              ))}
              {!findings.length && (
                <tr><td colSpan={3} style={{ padding:20, textAlign:'center', color:'var(--text3)', fontSize:12 }}>No findings yet — start a scan</td></tr>
              )}
            </tbody>
          </table>
        </div>

        <div className="card">
          <div style={{ display:'flex', alignItems:'center', justifyContent:'space-between', marginBottom:14 }}>
            <p className="card-title" style={{ marginBottom:0 }}>Scan History</p>
            <button className="btn btn-ghost btn-sm" onClick={() => navigate('/scans')}>View all</button>
          </div>
          <div style={{ display:'flex', flexDirection:'column', gap:8 }}>
            {scans.slice(0, 5).map(s => (
              <div key={s.id}
                style={{ display:'flex', alignItems:'center', gap:10, padding:'10px', background:'var(--surface2)', borderRadius:8, cursor:'pointer' }}
                onClick={() => navigate(`/scans/${s.id}`)}>
                <StatusDot status={s.status}/>
                <div style={{ flex:1, overflow:'hidden' }}>
                  <p style={{ fontSize:12, fontWeight:600, color:'var(--text)', fontFamily:'monospace', whiteSpace:'nowrap', overflow:'hidden', textOverflow:'ellipsis' }}>
                    {s.target_domain}
                  </p>
                  {/* FIXED: Both exact + relative time */}
                  <DateDisplay value={s.created_at} exactStyle={{ fontSize:11 }}
                    relativeStyle={{ fontSize:10 }}/>
                </div>
                <RiskScore score={s.risk_score}/>
                <span style={{ fontSize:11, color:'var(--text3)', whiteSpace:'nowrap' }}>
                  {(s.critical_count ?? 0) + (s.high_count ?? 0) + (s.medium_count ?? 0)} issues
                </span>
              </div>
            ))}
            {!scans.length && (
              <p style={{ textAlign:'center', color:'var(--text3)', fontSize:12, padding:20 }}>No scans yet</p>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
