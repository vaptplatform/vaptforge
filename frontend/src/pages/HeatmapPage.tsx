import React, { useEffect, useState } from 'react';
import { findingsAPI } from '../services/api';
import type { Finding } from '../types';

type Severity = 'critical' | 'high' | 'medium' | 'low';
type EP = { url:string; critical:number; high:number; medium:number; low:number; riskScore:number; count:number };

export default function HeatmapPage() {
  const [findings, setFindings] = useState<Finding[]>([]);

  useEffect(() => {
    // dedupe=true → backend already merged SAST+DAST duplicates
    findingsAPI.list({ dedupe: true }).then(r => setFindings(r.data.findings));
  }, []);

  // Aggregate by endpoint — for grouped findings (e.g. 8× TRACE), expand affected_urls
  const epMap = new Map<string, EP>();

  for (const f of findings) {
    // Use affected_urls if available (multi-URL grouped finding), else single url
    const urls = f.affected_urls && f.affected_urls.length > 0 ? f.affected_urls : [f.affected_url];

    for (const u of urls) {
      if (!epMap.has(u)) epMap.set(u, { url: u, critical: 0, high: 0, medium: 0, low: 0, riskScore: 0, count: 0 });
      const ep = epMap.get(u)!;
      const sev = f.severity as Severity;
      if (sev in ep) ep[sev] = (ep[sev] || 0) + 1;
      ep.riskScore = Math.max(ep.riskScore, f.risk_score);
      ep.count++;
    }
  }

  const endpoints = Array.from(epMap.values()).sort((a, b) => b.riskScore - a.riskScore);
  const maxRisk   = Math.max(...endpoints.map(e => e.riskScore), 1);

  const riskColor = (score: number) =>
    score >= 7 ? '#EF4444' : score >= 4 ? '#F97316' : score >= 2 ? '#EAB308' : '#22C55E';

  return (
    <div className="fade-up" style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <div>
        <h1 style={{ fontSize: 20, fontWeight: 800, color: 'var(--text)' }}>Endpoint Risk Heatmap</h1>
        <p style={{ fontSize: 12, color: 'var(--text3)', marginTop: 2 }}>
          Risk = Severity × Confidence × Exposure &nbsp;·&nbsp; {endpoints.length} endpoints
          &nbsp;·&nbsp; <span style={{ color: 'var(--text3)' }}>duplicates merged</span>
        </p>
      </div>

      {/* Legend */}
      <div className="card" style={{ background: 'rgba(59,130,246,0.04)', border: '1px solid rgba(59,130,246,0.15)' }}>
        <div style={{ display: 'flex', gap: 20, fontSize: 12, flexWrap: 'wrap' }}>
          {([['≥ 7.0','Critical','#EF4444'],['4.0–6.9','High','#F97316'],['2.0–3.9','Medium','#EAB308'],['< 2.0','Low','#22C55E']] as [string,string,string][]).map(([range,label,color]) => (
            <div key={label} style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              <span style={{ width: 10, height: 10, borderRadius: 2, background: color, display: 'inline-block' }}/>
              <span style={{ color: 'var(--text2)' }}>{label}</span>
              <span style={{ color: 'var(--text3)', fontSize: 11 }}>{range}</span>
            </div>
          ))}
        </div>
      </div>

      {!endpoints.length ? (
        <div className="card" style={{ textAlign: 'center', padding: 40, color: 'var(--text3)' }}>
          No findings yet. Run a scan to populate the heatmap.
        </div>
      ) : (
        <div className="card" style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          {endpoints.map(ep => {
            const pct   = (ep.riskScore / maxRisk) * 100;
            const color = riskColor(ep.riskScore);
            return (
              <div key={ep.url} style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                <span style={{ fontFamily: 'monospace', fontSize: 11, color: 'var(--text2)', width: 220, flexShrink: 0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={ep.url}>
                  {ep.url}
                </span>
                <div style={{ flex: 1, height: 22, background: 'var(--surface3)', borderRadius: 4, overflow: 'hidden', position: 'relative' }}>
                  <div style={{ height: '100%', width: `${pct}%`, background: `linear-gradient(90deg,${color}cc,${color}55)`, borderRadius: 4, transition: 'width 0.6s ease', display: 'flex', alignItems: 'center', paddingLeft: 8 }}>
                    {pct > 15 && <span style={{ fontSize: 10, fontFamily: 'monospace', fontWeight: 700, color: 'white' }}>{ep.riskScore.toFixed(1)}</span>}
                  </div>
                  {pct <= 15 && <span style={{ position: 'absolute', left: 8, top: '50%', transform: 'translateY(-50%)', fontSize: 10, fontFamily: 'monospace', color, fontWeight: 700 }}>{ep.riskScore.toFixed(1)}</span>}
                </div>
                <div style={{ display: 'flex', gap: 6, flexShrink: 0, fontSize: 10, fontFamily: 'monospace' }}>
                  {ep.critical > 0 && <span style={{ color: '#EF4444', fontWeight: 700 }}>{ep.critical}C</span>}
                  {ep.high     > 0 && <span style={{ color: '#F97316', fontWeight: 700 }}>{ep.high}H</span>}
                  {ep.medium   > 0 && <span style={{ color: '#EAB308' }}>{ep.medium}M</span>}
                  <span style={{ color: 'var(--text3)' }}>{ep.count} total</span>
                </div>
              </div>
            );
          })}
        </div>
      )}

      <div className="card" style={{ background: 'var(--surface2)' }}>
        <p className="card-title">Risk Formula</p>
        <div style={{ fontFamily: 'monospace', fontSize: 13, color: 'var(--accent2)', background: 'var(--bg)', padding: 14, borderRadius: 8, border: '1px solid var(--border)' }}>
          Risk Score = Severity Weight × Confidence × Exposure
          <div style={{ marginTop: 8, fontSize: 11, color: 'var(--text3)' }}>
            Severity Weight: Critical=9, High=7, Medium=5.5, Low=3 &nbsp;|&nbsp;
            Confidence: 0.0–1.0 (detection certainty) &nbsp;|&nbsp;
            Exposure: 1.0=public, 0.6=internal
          </div>
        </div>
      </div>
    </div>
  );
}