import React, { useEffect, useState } from 'react';
import { ScrollText, RefreshCw } from 'lucide-react';
import api from '../services/api';
import { formatDistanceToNow } from 'date-fns';

interface AuditEntry {
  id: string;
  action: string;
  user_email: string;
  resource_type: string | null;
  resource_id: string | null;
  details: Record<string, unknown>;
  ip_address: string | null;
  created_at: string;
}

const ACTION_COLORS: Record<string, string> = {
  SCAN_START:       '#22C55E',
  SCAN_CANCEL:      '#F97316',
  SCAN_COMPLETE:    '#3B82F6',
  VULN_FOUND:       '#EF4444',
  ALERT_SENT:       '#FDB87D',
  REPORT_GENERATED: '#A855F7',
  REPORT_SHARED:    '#06B6D4',
  USER_LOGIN:       '#60A5FA',
  USER_REGISTER:    '#22C55E',
  USER_CREATED:     '#22C55E',
  DOMAIN_ADDED:     '#60A5FA',
  DOMAIN_VERIFIED:  '#22C55E',
  DOMAIN_REMOVED:   '#EF4444',
};

export default function AuditPage() {
  const [logs, setLogs] = useState<AuditEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState('');

  const load = () => {
    setLoading(true);
    api.get('/audit', { params: { per_page: 200, action: filter || undefined } })
      .then(r => setLogs(r.data.logs))
      .finally(() => setLoading(false));
  };

  useEffect(() => { load(); }, [filter]);

  const actionGroups = [
    'All Actions', 'SCAN_START', 'REPORT_GENERATED', 'REPORT_SHARED',
    'ALERT_SENT', 'USER_LOGIN', 'DOMAIN_ADDED', 'DOMAIN_VERIFIED',
  ];

  return (
    <div className="fade-up" style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div>
          <h1 style={{ fontSize: 20, fontWeight: 800, color: 'var(--text)' }}>Audit Log</h1>
          <p style={{ fontSize: 12, color: 'var(--text3)', marginTop: 2 }}>
            Immutable record of all platform activity — {logs.length} entries
          </p>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <select className="input" style={{ width: 200 }} value={filter} onChange={e => setFilter(e.target.value)}>
            {actionGroups.map(a => <option key={a} value={a === 'All Actions' ? '' : a}>{a}</option>)}
          </select>
          <button className="btn btn-outline btn-sm" onClick={load}><RefreshCw size={13} /></button>
        </div>
      </div>

      <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
        <div className="terminal" style={{ height: 600, borderRadius: 0, border: 'none', padding: '16px 20px' }}>
          {loading && (
            <p style={{ color: 'var(--text3)' }}>Loading audit log…</p>
          )}
          {!loading && !logs.length && (
            <p style={{ color: 'var(--text3)' }}>No audit entries found.</p>
          )}
          {logs.map(log => {
            const actionColor = ACTION_COLORS[log.action] || '#94A3B8';
            const detailsStr = Object.entries(log.details)
              .filter(([k]) => k !== 'password' && k !== 'token')
              .map(([k, v]) => `${k}=${JSON.stringify(v)}`)
              .join(' ')
              .slice(0, 100);

            return (
              <div key={log.id} style={{ display: 'flex', gap: 12, padding: '3px 0', lineHeight: 1.7, fontSize: 12 }}>
                <span style={{ color: '#475569', flexShrink: 0, fontSize: 11 }}>
                  {formatDistanceToNow(new Date(log.created_at), { addSuffix: true })}
                </span>
                <span style={{
                  background: `${actionColor}20`, color: actionColor,
                  padding: '0 7px', borderRadius: 3, fontSize: 10, fontWeight: 700,
                  flexShrink: 0, lineHeight: '18px', alignSelf: 'center',
                }}>
                  {log.action}
                </span>
                <span style={{ color: '#60A5FA', flexShrink: 0, fontSize: 11 }}>{log.user_email}</span>
                {detailsStr && (
                  <span style={{ color: 'var(--text3)', fontSize: 11, wordBreak: 'break-all' }}>{detailsStr}</span>
                )}
                {log.ip_address && (
                  <span style={{ color: '#475569', fontSize: 10, marginLeft: 'auto', flexShrink: 0 }}>
                    {log.ip_address}
                  </span>
                )}
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
