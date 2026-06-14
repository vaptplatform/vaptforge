import React, { useEffect, useState } from 'react';
import { findingsAPI } from '../services/api';
import { SevBadge, RiskScore, EmptyState } from '../components/shared/UI';
import { ShieldAlert } from 'lucide-react';
import { OWASP_MAP } from '../types';
import type { Finding, DetectionMethod } from '../types';
import axios from 'axios';

// ── ML Severity Badge ─────────────────────────────────────────────────────────
function MLBadge({ findingId }: { findingId: string }) {
  const [ml, setMl]       = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [open, setOpen]   = useState(false);

  const fetch = async () => {
    if (ml) { setOpen(o => !o); return; }
    setLoading(true);
    try {
      const token = localStorage.getItem('vapt_token') || sessionStorage.getItem('vapt_token') || '';
      const res = await axios.get(`/api/v1/findings/${findingId}/ml-predict`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      setMl(res.data);
      setOpen(true);
    } catch { /* silent */ }
    finally { setLoading(false); }
  };

  const SEV_COLOR: Record<string, string> = {
    critical: '#F87171', high: '#FB923C', medium: '#FBBF24', low: '#60A5FA', info: '#A3A3A3'
  };

  return (
    <span style={{ position: 'relative', display: 'inline-block' }}>
      <span
        onClick={fetch}
        title="ML Severity Prediction"
        style={{
          fontSize: 9, fontFamily: 'monospace', fontWeight: 700, cursor: 'pointer',
          padding: '1px 6px', borderRadius: 3,
          background: 'rgba(139,92,246,0.15)', color: '#A78BFA',
          border: '1px solid rgba(139,92,246,0.35)',
          userSelect: 'none',
        }}
      >
        {loading ? '⏳ ML' : '🤖 ML'}
      </span>
      {open && ml && (
        <div style={{
          position: 'absolute', top: '110%', left: 0, zIndex: 999,
          background: 'var(--color-background-secondary)',
          border: '1px solid var(--color-border-primary)',
          borderRadius: 8, padding: '10px 14px', minWidth: 220,
          boxShadow: '0 4px 16px rgba(0,0,0,0.25)', fontSize: 12,
        }}>
          <div style={{ fontWeight: 600, marginBottom: 6, color: 'var(--color-text-primary)' }}>
            🤖 ML Prediction
          </div>
          <div style={{ marginBottom: 4 }}>
            Predicted: <b style={{ color: SEV_COLOR[ml.ml_severity] ?? '#ccc' }}>
              {ml.ml_severity?.toUpperCase()}
            </b>
            <span style={{ color: 'var(--color-text-secondary)', marginLeft: 6 }}>
              ({Math.round((ml.ml_confidence ?? 0) * 100)}% conf)
            </span>
          </div>
          <div style={{ marginBottom: 6, color: ml.agrees_with_rule_based ? '#4ADE80' : '#F87171' }}>
            {ml.agrees_with_rule_based ? '✓ Agrees with rule-based' : '⚠ Differs from rule-based'}
          </div>
          <div style={{ color: 'var(--color-text-tertiary)', fontSize: 11 }}>
            {Object.entries(ml.ml_probabilities ?? {}).map(([sev, prob]: any) => (
              <span key={sev} style={{ marginRight: 8 }}>
                {sev}: {Math.round(prob * 100)}%
              </span>
            ))}
          </div>
          <div
            onClick={() => setOpen(false)}
            style={{ marginTop: 8, cursor: 'pointer', color: 'var(--color-text-tertiary)', fontSize: 11 }}
          >
            ✕ close
          </div>
        </div>
      )}
    </span>
  );
}

// ── Detection method badge ────────────────────────────────────────────────────
function MethodBadge({ method }: { method: DetectionMethod }) {
  const isSast = method === 'SAST';
  return (
    <span style={{
      fontSize: 9, fontFamily: 'monospace', fontWeight: 700,
      padding: '1px 5px', borderRadius: 3,
      background: isSast ? 'rgba(168,85,247,0.15)' : 'rgba(59,130,246,0.15)',
      color: isSast ? '#C084FC' : '#60A5FA',
      border: `1px solid ${isSast ? 'rgba(168,85,247,0.3)' : 'rgba(59,130,246,0.3)'}`,
    }}>
      {method}
    </span>
  );
}

// ── Confirmed badge (both SAST + DAST detected same issue) ────────────────────
function ConfirmedBadge() {
  return (
    <span title="Confirmed by both SAST and DAST" style={{
      fontSize: 9, fontFamily: 'monospace', fontWeight: 700,
      padding: '1px 6px', borderRadius: 3,
      background: 'rgba(34,197,94,0.15)', color: '#4ADE80',
      border: '1px solid rgba(34,197,94,0.3)',
    }}>
      ✓ CONFIRMED
    </span>
  );
}

// ── Grouped-URLs badge (e.g. 8× TRACE) ───────────────────────────────────────
function GroupedBadge({ count }: { count: number }) {
  return (
    <span title={`Same issue found on ${count} endpoints`} style={{
      fontSize: 9, fontFamily: 'monospace', fontWeight: 700,
      padding: '1px 6px', borderRadius: 3,
      background: 'rgba(249,115,22,0.15)', color: '#FB923C',
      border: '1px solid rgba(249,115,22,0.3)',
    }}>
      ×{count} URLs
    </span>
  );
}

export function FindingsPage() {
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading]   = useState(true);
  const [sevFilter, setSev]     = useState('');
  const [owaspFilter, setOwasp] = useState('');
  const [selected, setSelected] = useState<Finding | null>(null);

  useEffect(() => {
    setLoading(true);
    findingsAPI.list({
      severity: sevFilter || undefined,
      owasp:    owaspFilter || undefined,
      dedupe:   true,                        // ← always request deduplicated
    })
      .then(r => setFindings(r.data.findings))
      .finally(() => setLoading(false));
  }, [sevFilter, owaspFilter]);

  const totalRaw = findings.reduce((s, f) => s + (f.duplicate_count ?? 1), 0);

  return (
    <div className="fade-up" style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div>
          <h1 style={{ fontSize: 20, fontWeight: 800, color: 'var(--text)' }}>Vulnerabilities</h1>
          <p style={{ fontSize: 12, color: 'var(--text3)', marginTop: 2 }}>
            {findings.length} unique findings
            {totalRaw > findings.length && (
              <span style={{ color: 'var(--text3)', marginLeft: 6 }}>
                ({totalRaw} raw · {totalRaw - findings.length} deduplicated)
              </span>
            )}
          </p>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <select className="input" style={{ width: 160 }} value={sevFilter} onChange={e => setSev(e.target.value)}>
            <option value="">All Severity</option>
            {['critical','high','medium','low','info'].map(s =>
              <option key={s} value={s}>{s.charAt(0).toUpperCase()+s.slice(1)}</option>
            )}
          </select>
          <select className="input" style={{ width: 180 }} value={owaspFilter} onChange={e => setOwasp(e.target.value)}>
            <option value="">All OWASP</option>
            {Object.entries(OWASP_MAP).map(([k, v]) =>
              <option key={k} value={k}>{k} – {v}</option>
            )}
          </select>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: selected ? '1fr 420px' : '1fr', gap: 16 }}>
        <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
            <thead style={{ background: 'var(--surface2)' }}>
              <tr>
                {['ID','Title','Detection','OWASP','Endpoint','Severity','Risk','Status'].map(h => (
                  <th key={h} style={{ padding: '10px 12px', textAlign: 'left', fontSize: 10, color: 'var(--text3)', fontWeight: 600, textTransform: 'uppercase', borderBottom: '1px solid var(--border)' }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {!loading && findings.map(f => (
                <tr key={f.id}
                  onClick={() => setSelected(selected?.id === f.id ? null : f)}
                  style={{
                    borderBottom: '1px solid var(--border)', cursor: 'pointer',
                    background: selected?.id === f.id ? 'rgba(59,130,246,0.06)' : 'transparent',
                  }}
                  onMouseEnter={e => { if (selected?.id !== f.id) e.currentTarget.style.background = 'var(--surface2)'; }}
                  onMouseLeave={e => { if (selected?.id !== f.id) e.currentTarget.style.background = 'transparent'; }}
                >
                  <td style={{ padding: '9px 12px', fontFamily: 'monospace', fontSize: 10, color: 'var(--text3)' }}>{f.id.slice(0,8)}</td>
                  <td style={{ padding: '9px 12px', color: 'var(--text)', fontWeight: 500, maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{f.title}</td>

                  {/* ── Detection method badges ── */}
                  <td style={{ padding: '9px 12px' }}>
                    <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                      {f.detection_methods?.includes('SAST') && f.detection_methods?.includes('DAST')
                        ? <ConfirmedBadge />
                        : f.detection_methods?.map(m => <MethodBadge key={m} method={m} />)
                      }
                      {(f.affected_urls?.length ?? 0) > 1 && <GroupedBadge count={f.affected_urls!.length} />}
                      <MLBadge findingId={f.id} />
                    </div>
                  </td>

                  <td style={{ padding: '9px 12px', fontFamily: 'monospace', fontSize: 11, color: 'var(--text3)' }}>{f.owasp_category}</td>
                  <td style={{ padding: '9px 12px', fontFamily: 'monospace', fontSize: 11, color: '#60A5FA', maxWidth: 150, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{f.affected_url}</td>
                  <td style={{ padding: '9px 12px' }}><SevBadge sev={f.severity} /></td>
                  <td style={{ padding: '9px 12px' }}><RiskScore score={f.risk_score} /></td>
                  <td style={{ padding: '9px 12px', fontFamily: 'monospace', fontSize: 10,
                    color: f.status==='fixed' ? '#22C55E' : f.status==='false_positive' ? '#64748B' : '#F97316' }}>
                    {f.status}
                  </td>
                </tr>
              ))}
              {!loading && !findings.length && (
                <tr><td colSpan={8}>
                  <EmptyState icon={<ShieldAlert size={36}/>} title="No findings" desc="Run a scan to detect vulnerabilities" />
                </td></tr>
              )}
              {loading && (
                <tr><td colSpan={8} style={{ padding: 30, textAlign: 'center', color: 'var(--text3)' }}>Loading…</td></tr>
              )}
            </tbody>
          </table>
        </div>

        {selected && <FindingDetail finding={selected} onClose={() => setSelected(null)} />}
      </div>
    </div>
  );
}

// ── Detail panel ──────────────────────────────────────────────────────────────

function FindingDetail({ finding: f, onClose }: { finding: Finding; onClose: () => void }) {
  const isConfirmed = f.detection_methods?.includes('SAST') && f.detection_methods?.includes('DAST');
  const isGrouped   = (f.affected_urls?.length ?? 0) > 1;

  return (
    <div className="card fade-up" style={{ display: 'flex', flexDirection: 'column', gap: 14, alignSelf: 'flex-start', position: 'sticky', top: 0, maxHeight: 'calc(100vh - 120px)', overflowY: 'auto' }}>
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 8 }}>
        <h3 style={{ fontSize: 14, fontWeight: 700, color: 'var(--text)', lineHeight: 1.4 }}>{f.title}</h3>
        <button onClick={onClose} style={{ background: 'none', border: 'none', color: 'var(--text3)', cursor: 'pointer', padding: 2, flexShrink: 0 }}>✕</button>
      </div>

      {/* Badges row */}
      <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', alignItems: 'center' }}>
        <SevBadge sev={f.severity} />
        <span style={{ fontSize: 11, fontFamily: 'monospace', padding: '2px 8px', borderRadius: 4, background: 'rgba(59,130,246,0.1)', color: '#93C5FD', border: '1px solid rgba(59,130,246,0.2)' }}>
          {f.owasp_category}
        </span>
        <span style={{ fontSize: 11, color: 'var(--text3)', fontFamily: 'monospace' }}>conf: {(f.confidence*100).toFixed(0)}%</span>
        {isConfirmed
          ? <ConfirmedBadge />
          : f.detection_methods?.map(m => <MethodBadge key={m} method={m} />)
        }
        {f.duplicate_count && f.duplicate_count > 1 && (
          <span style={{ fontSize: 10, color: 'var(--text3)', fontFamily: 'monospace' }}>
            ({f.duplicate_count} raw merged)
          </span>
        )}
      </div>

      {/* Affected URL(s) */}
      {isGrouped ? (
        <div>
          <p style={{ fontSize: 10, color: 'var(--text3)', fontWeight: 600, marginBottom: 6 }}>
            AFFECTED ENDPOINTS ({f.affected_urls!.length})
          </p>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 3, maxHeight: 120, overflowY: 'auto' }}>
            {f.affected_urls!.map(u => (
              <span key={u} style={{ fontFamily: 'monospace', fontSize: 11, color: '#60A5FA', wordBreak: 'break-all' }}>{u}</span>
            ))}
          </div>
        </div>
      ) : (
        <DetailRow label="Endpoint" value={<span style={{ fontFamily:'monospace', fontSize:11, color:'#60A5FA' }}>{f.affected_url}</span>} />
      )}

      {f.affected_parameter && <DetailRow label="Parameter" value={<code style={{ fontFamily:'monospace', fontSize:11 }}>{f.affected_parameter}</code>} />}
      <DetailRow label="Risk Score" value={<RiskScore score={f.risk_score} />} />

      <hr style={{ border: 'none', borderTop: '1px solid var(--border)' }} />

      <div>
        <p style={{ fontSize: 10, color: 'var(--text3)', fontWeight: 600, marginBottom: 4 }}>DESCRIPTION</p>
        <p style={{ fontSize: 12, color: 'var(--text2)', lineHeight: 1.7 }}>{f.description}</p>
      </div>

      {Object.keys(f.evidence).length > 0 && (
        <div>
          <p style={{ fontSize: 10, color: 'var(--text3)', fontWeight: 600, marginBottom: 6 }}>EVIDENCE</p>
          <div className="terminal" style={{ fontSize: 11, maxHeight: 160, overflowY: 'auto' }}>
            {JSON.stringify(f.evidence, null, 2)}
          </div>
        </div>
      )}

      <div>
        <p style={{ fontSize: 10, color: 'var(--text3)', fontWeight: 600, marginBottom: 4 }}>REMEDIATION</p>
        <div style={{ background: 'rgba(34,197,94,0.06)', border: '1px solid rgba(34,197,94,0.2)', borderRadius: 6, padding: '10px 12px', fontSize: 12, color: '#86EFAC', lineHeight: 1.7 }}>
          {f.remediation}
        </div>
      </div>

      {f.references.length > 0 && (
        <div>
          <p style={{ fontSize: 10, color: 'var(--text3)', fontWeight: 600, marginBottom: 4 }}>REFERENCES</p>
          {f.references.map((r, i) => (
            <a key={i} href={r} target="_blank" rel="noreferrer"
              style={{ display: 'block', fontSize: 11, color: '#60A5FA', marginBottom: 2, wordBreak: 'break-all' }}>
              {r}
            </a>
          ))}
        </div>
      )}
    </div>
  );
}

function DetailRow({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: 12 }}>
      <span style={{ color: 'var(--text3)' }}>{label}</span>
      <span style={{ color: 'var(--text)' }}>{value}</span>
    </div>
  );
}