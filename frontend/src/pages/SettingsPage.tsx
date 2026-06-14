import React, { useEffect, useState } from 'react';
import {
  Shield, Users, Globe, Bell, Lock, Plus, Trash2,
  CheckCircle, Clock, RefreshCw, Save, ExternalLink
} from 'lucide-react';
import { domainsAPI, usersAPI, alertsAPI } from '../services/api';
import { useAuthStore, useToastStore } from '../store';
import { Modal, ConfirmDialog, Spinner } from '../components/shared/UI';
import type { Domain, OrgUser } from '../types';

type Tab = 'domains' | 'users' | 'notifications' | 'security';

export default function SettingsPage() {
  const [tab, setTab] = useState<Tab>('domains');
  const { user } = useAuthStore();
  const isAdmin = user?.role === 'admin';

  const tabs: { key: Tab; label: string; icon: React.ReactNode }[] = [
    { key: 'domains',       label: 'Whitelisted Domains', icon: <Globe size={14} /> },
    { key: 'users',         label: 'Access Control',      icon: <Users size={14} /> },
    { key: 'notifications', label: 'Notifications',       icon: <Bell size={14} /> },
    { key: 'security',      label: 'Security',            icon: <Lock size={14} /> },
  ];

  return (
    <div className="fade-up" style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <div>
        <h1 style={{ fontSize: 20, fontWeight: 800, color: 'var(--text)' }}>Settings</h1>
        <p style={{ fontSize: 12, color: 'var(--text3)', marginTop: 2 }}>
          Platform configuration for your organization
        </p>
      </div>

      {/* Tab bar */}
      <div style={{ display: 'flex', gap: 4, borderBottom: '1px solid var(--border)', paddingBottom: 0 }}>
        {tabs.map(t => (
          <button
            key={t.key}
            onClick={() => setTab(t.key)}
            style={{
              display: 'flex', alignItems: 'center', gap: 7,
              padding: '8px 16px', background: 'transparent', border: 'none',
              borderBottom: tab === t.key ? '2px solid var(--accent)' : '2px solid transparent',
              color: tab === t.key ? 'var(--accent2)' : 'var(--text3)',
              fontSize: 13, fontWeight: 500, cursor: 'pointer',
              marginBottom: -1, fontFamily: 'inherit',
            }}
          >
            {t.icon}{t.label}
          </button>
        ))}
      </div>

      {tab === 'domains'       && <DomainsTab isAdmin={isAdmin} />}
      {tab === 'users'         && <UsersTab   isAdmin={isAdmin} />}
      {tab === 'notifications' && <NotificationsTab />}
      {tab === 'security'      && <SecurityTab />}
    </div>
  );
}

/* ── Domains Tab ─────────────────────────────────────────────── */
function DomainsTab({ isAdmin }: { isAdmin: boolean }) {
  const [domains, setDomains] = useState<Domain[]>([]);
  const [newDomain, setNewDomain] = useState('');
  const [notes, setNotes] = useState('');
  const [addOpen, setAddOpen] = useState(false);
  const [verifyToken, setVerifyToken] = useState<{ domain: string; token: string } | null>(null);
  const [loading, setLoading] = useState(false);
  const addToast = useToastStore(s => s.add);

  const load = () => domainsAPI.list().then(r => setDomains(r.data.domains));
  useEffect(() => { load(); }, []);

  const add = async () => {
    if (!newDomain.trim()) return;
    setLoading(true);
    try {
      const { data } = await domainsAPI.add(newDomain.trim(), notes);
      setVerifyToken({ domain: data.domain, token: data.verification_token });
      setAddOpen(false);
      setNewDomain(''); setNotes('');
      load();
      addToast('success', `Domain '${data.domain}' added — verify via DNS`);
    } catch (e: any) {
      addToast('error', e.response?.data?.detail ?? 'Failed to add domain');
    } finally { setLoading(false); }
  };

  const verify = async (id: string, domain: string) => {
    try {
      await domainsAPI.verify(id);
      addToast('success', `${domain} verified`);
      load();
    } catch { addToast('error', 'Verification failed'); }
  };

  const remove = async (id: string) => {
    try {
      await domainsAPI.remove(id);
      addToast('info', 'Domain removed');
      load();
    } catch { addToast('error', 'Failed to remove domain'); }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div style={{ background: 'rgba(239,68,68,0.06)', border: '1px solid rgba(239,68,68,0.2)', borderRadius: 10, padding: '14px 16px' }}>
        <p style={{ fontSize: 13, fontWeight: 700, color: '#FCA5A5', marginBottom: 4 }}>⚠ Authorization Required</p>
        <p style={{ fontSize: 12, color: 'var(--text2)', lineHeight: 1.6 }}>
          Only domains listed and verified here can be scanned. This prevents unauthorized scanning.
          Each domain must be verified via DNS TXT record before scanning is permitted.
        </p>
      </div>

      <div className="card">
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16 }}>
          <p className="card-title" style={{ marginBottom: 0 }}>Authorized Domains</p>
          {isAdmin && (
            <button className="btn btn-primary btn-sm" onClick={() => setAddOpen(true)}>
              <Plus size={13} /> Add Domain
            </button>
          )}
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          {domains.map(d => (
            <div key={d.id} style={{
              display: 'flex', alignItems: 'center', gap: 12,
              padding: '12px 14px',
              background: 'var(--surface2)', borderRadius: 8,
              border: `1px solid ${d.status === 'verified' ? 'rgba(34,197,94,0.2)' : 'rgba(249,115,22,0.2)'}`,
            }}>
              {d.status === 'verified'
                ? <CheckCircle size={16} style={{ color: '#22C55E', flexShrink: 0 }} />
                : <Clock size={16} style={{ color: '#F97316', flexShrink: 0 }} />}
              <div style={{ flex: 1 }}>
                <p style={{ fontSize: 13, fontFamily: 'monospace', color: 'var(--text)', fontWeight: 600 }}>{d.domain}</p>
                {d.notes && <p style={{ fontSize: 11, color: 'var(--text3)', marginTop: 2 }}>{d.notes}</p>}
              </div>
              <span style={{
                fontSize: 10, padding: '2px 8px', borderRadius: 4, fontFamily: 'monospace', fontWeight: 700,
                background: d.status === 'verified' ? 'rgba(34,197,94,0.1)' : 'rgba(249,115,22,0.1)',
                color: d.status === 'verified' ? '#86EFAC' : '#FDB87D',
                border: `1px solid ${d.status === 'verified' ? 'rgba(34,197,94,0.25)' : 'rgba(249,115,22,0.25)'}`,
              }}>{d.status.toUpperCase()}</span>
              {isAdmin && d.status === 'pending' && (
                <button className="btn btn-outline btn-sm" onClick={() => verify(d.id, d.domain)} style={{ fontSize: 11 }}>
                  Verify
                </button>
              )}
              {isAdmin && (
                <button className="btn btn-danger btn-sm" onClick={() => remove(d.id)} style={{ padding: '4px 8px' }}>
                  <Trash2 size={12} />
                </button>
              )}
            </div>
          ))}
          {!domains.length && (
            <p style={{ textAlign: 'center', color: 'var(--text3)', padding: 24, fontSize: 13 }}>
              No domains added. Add an authorized domain to start scanning.
            </p>
          )}
        </div>
      </div>

      {/* Verification token display */}
      {verifyToken && (
        <div style={{ background: 'rgba(59,130,246,0.08)', border: '1px solid rgba(59,130,246,0.25)', borderRadius: 10, padding: 16 }}>
          <p style={{ fontSize: 13, fontWeight: 700, color: '#93C5FD', marginBottom: 8 }}>DNS Verification Instructions</p>
          <p style={{ fontSize: 12, color: 'var(--text2)', marginBottom: 12 }}>
            Add this TXT record to the DNS of <strong>{verifyToken.domain}</strong>:
          </p>
          <div style={{ background: 'var(--bg)', borderRadius: 6, padding: '10px 14px', fontFamily: 'monospace', fontSize: 12, color: '#60A5FA', border: '1px solid var(--border)' }}>
            vapt-verify={verifyToken.token}
          </div>
          <p style={{ fontSize: 11, color: 'var(--text3)', marginTop: 8 }}>
            Once the record propagates, click <strong>Verify</strong> next to the domain.
          </p>
          <button className="btn btn-ghost btn-sm" style={{ marginTop: 8 }} onClick={() => setVerifyToken(null)}>Dismiss</button>
        </div>
      )}

      <Modal open={addOpen} onClose={() => setAddOpen(false)} title="Add Authorized Domain" width={460}>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
          <div>
            <label style={{ fontSize: 11, color: 'var(--text3)', display: 'block', marginBottom: 5, fontWeight: 600 }}>DOMAIN</label>
            <input className="input" placeholder="app.example.com" value={newDomain}
              onChange={e => setNewDomain(e.target.value)} />
          </div>
          <div>
            <label style={{ fontSize: 11, color: 'var(--text3)', display: 'block', marginBottom: 5, fontWeight: 600 }}>NOTES (optional)</label>
            <input className="input" placeholder="Production app, authorized by security team" value={notes}
              onChange={e => setNotes(e.target.value)} />
          </div>
          <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
            <button className="btn btn-outline btn-sm" onClick={() => setAddOpen(false)}>Cancel</button>
            <button className="btn btn-primary btn-sm" onClick={add} disabled={loading}>
              {loading ? <Spinner size={13} /> : <><Plus size={13} /> Add Domain</>}
            </button>
          </div>
        </div>
      </Modal>
    </div>
  );
}

/* ── Users Tab ───────────────────────────────────────────────── */
function UsersTab({ isAdmin }: { isAdmin: boolean }) {
  const [users, setUsers] = useState<OrgUser[]>([]);
  const [addOpen, setAddOpen] = useState(false);
  const [form, setForm] = useState({ email: '', full_name: '', password: '', role: 'viewer' });
  const [loading, setLoading] = useState(false);
  const addToast = useToastStore(s => s.add);
  const { user: me } = useAuthStore();

  const load = () => usersAPI.list().then(r => setUsers(r.data.users));
  useEffect(() => { load(); }, []);

  const createUser = async () => {
    setLoading(true);
    try {
      await usersAPI.create(form as any);
      addToast('success', `User ${form.email} created`);
      setAddOpen(false);
      setForm({ email: '', full_name: '', password: '', role: 'viewer' });
      load();
    } catch (e: any) {
      addToast('error', e.response?.data?.detail ?? 'Failed to create user');
    } finally { setLoading(false); }
  };

  const toggleActive = async (u: OrgUser) => {
    if (u.id === me?.id) return;
    await usersAPI.update(u.id, { is_active: !u.is_active });
    addToast('info', `${u.email} ${!u.is_active ? 'activated' : 'deactivated'}`);
    load();
  };

  const ROLE_COLORS: Record<string, string> = {
    admin: '#D8B4FE', analyst: '#93C5FD', viewer: '#86EFAC',
  };
  const ROLE_BG: Record<string, string> = {
    admin: 'rgba(168,85,247,0.1)', analyst: 'rgba(59,130,246,0.1)', viewer: 'rgba(34,197,94,0.08)',
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div className="card">
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16 }}>
          <p className="card-title" style={{ marginBottom: 0 }}>Team Members</p>
          {isAdmin && (
            <button className="btn btn-primary btn-sm" onClick={() => setAddOpen(true)}>
              <Plus size={13} /> Add User
            </button>
          )}
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          {users.map(u => (
            <div key={u.id} style={{
              display: 'flex', alignItems: 'center', gap: 12,
              padding: '12px 14px', background: 'var(--surface2)', borderRadius: 8,
              border: '1px solid var(--border)',
              opacity: u.is_active ? 1 : 0.5,
            }}>
              <div style={{
                width: 36, height: 36, borderRadius: '50%', flexShrink: 0,
                background: ROLE_BG[u.role] || 'var(--surface3)',
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                fontSize: 13, fontWeight: 700, color: ROLE_COLORS[u.role],
              }}>
                {u.full_name.slice(0, 2).toUpperCase()}
              </div>
              <div style={{ flex: 1 }}>
                <p style={{ fontSize: 13, fontWeight: 600, color: 'var(--text)' }}>
                  {u.full_name}
                  {u.id === me?.id && <span style={{ fontSize: 10, color: 'var(--text3)', marginLeft: 6 }}>(you)</span>}
                </p>
                <p style={{ fontSize: 11, color: 'var(--text3)' }}>{u.email}</p>
              </div>
              <span style={{
                fontSize: 10, padding: '2px 8px', borderRadius: 4, fontFamily: 'monospace', fontWeight: 700,
                background: ROLE_BG[u.role], color: ROLE_COLORS[u.role],
                border: `1px solid ${ROLE_COLORS[u.role]}40`,
                textTransform: 'uppercase',
              }}>{u.role}</span>
              {isAdmin && u.id !== me?.id && (
                <button
                  className={`btn btn-sm ${u.is_active ? 'btn-outline' : 'btn-primary'}`}
                  onClick={() => toggleActive(u)}
                  style={{ fontSize: 11 }}
                >
                  {u.is_active ? 'Deactivate' : 'Activate'}
                </button>
              )}
            </div>
          ))}
        </div>
      </div>

      <div className="card" style={{ background: 'var(--surface2)' }}>
        <p className="card-title">Role Permissions</p>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
          <thead>
            <tr>
              {['Permission', 'Admin', 'Analyst', 'Viewer'].map(h => (
                <th key={h} style={{ padding: '6px 10px', textAlign: h === 'Permission' ? 'left' : 'center', fontSize: 11, color: 'var(--text3)', borderBottom: '1px solid var(--border)' }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {[
              ['View Dashboard & Reports', '✓', '✓', '✓'],
              ['Launch & Cancel Scans',    '✓', '✓', '✗'],
              ['Send Email Reports',       '✓', '✓', '✗'],
              ['Manage Domains',           '✓', '✗', '✗'],
              ['Manage Users',             '✓', '✗', '✗'],
              ['Platform Settings',        '✓', '✗', '✗'],
            ].map(([perm, ...checks]) => (
              <tr key={perm as string} style={{ borderBottom: '1px solid var(--border)' }}>
                <td style={{ padding: '8px 10px', color: 'var(--text2)' }}>{perm}</td>
                {checks.map((c, i) => (
                  <td key={i} style={{ padding: '8px 10px', textAlign: 'center', color: c === '✓' ? '#22C55E' : '#EF4444', fontWeight: 700 }}>{c}</td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <Modal open={addOpen} onClose={() => setAddOpen(false)} title="Add Team Member" width={460}>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
          {[
            { key: 'full_name', label: 'FULL NAME',  type: 'text',     placeholder: 'Jane Smith' },
            { key: 'email',     label: 'EMAIL',       type: 'email',    placeholder: 'jane@company.com' },
            { key: 'password',  label: 'PASSWORD',    type: 'password', placeholder: 'Min 8 characters' },
          ].map(({ key, label, type, placeholder }) => (
            <div key={key}>
              <label style={{ fontSize: 11, color: 'var(--text3)', display: 'block', marginBottom: 5, fontWeight: 600 }}>{label}</label>
              <input className="input" type={type} placeholder={placeholder}
                value={(form as any)[key]} onChange={e => setForm(f => ({ ...f, [key]: e.target.value }))} />
            </div>
          ))}
          <div>
            <label style={{ fontSize: 11, color: 'var(--text3)', display: 'block', marginBottom: 5, fontWeight: 600 }}>ROLE</label>
            <select className="input" value={form.role} onChange={e => setForm(f => ({ ...f, role: e.target.value }))}>
              <option value="viewer">Viewer — Read only</option>
              <option value="analyst">Analyst — Can scan and report</option>
              <option value="admin">Admin — Full access</option>
            </select>
          </div>
          <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
            <button className="btn btn-outline btn-sm" onClick={() => setAddOpen(false)}>Cancel</button>
            <button className="btn btn-primary btn-sm" onClick={createUser} disabled={loading}>
              {loading ? <Spinner size={13} /> : 'Create User'}
            </button>
          </div>
        </div>
      </Modal>
    </div>
  );
}

/* ── Notifications Tab ───────────────────────────────────────── */
function NotificationsTab() {
  const [webhook, setWebhook] = useState('');
  const [testing, setTesting] = useState(false);
  const addToast = useToastStore(s => s.add);

  const testWebhook = async () => {
    if (!webhook) return;
    setTesting(true);
    try {
      const { data } = await alertsAPI.testWebhook(webhook);
      addToast(data.success ? 'success' : 'error', data.success ? 'Webhook delivered' : 'Webhook failed');
    } catch { addToast('error', 'Webhook test failed'); }
    finally { setTesting(false); }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div className="card">
        <p className="card-title">Email Alerts</p>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
          {[
            { label: 'Scan completion email to org admins', desc: 'Sent automatically when any scan completes' },
            { label: 'Critical vulnerability alert', desc: 'Immediate email when critical findings are detected' },
            { label: 'Scan failure notification', desc: 'Notify when a scan encounters an error' },
          ].map(({ label, desc }) => (
            <div key={label} style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '10px 14px', background: 'var(--surface2)', borderRadius: 8 }}>
              <div style={{ flex: 1 }}>
                <p style={{ fontSize: 13, color: 'var(--text)', fontWeight: 500 }}>{label}</p>
                <p style={{ fontSize: 11, color: 'var(--text3)', marginTop: 2 }}>{desc}</p>
              </div>
              <span style={{ fontSize: 10, padding: '2px 8px', borderRadius: 4, background: 'rgba(34,197,94,0.1)', color: '#86EFAC', border: '1px solid rgba(34,197,94,0.2)', fontFamily: 'monospace' }}>
                ENABLED
              </span>
            </div>
          ))}
        </div>
        <div style={{ marginTop: 12, padding: '10px 14px', background: 'rgba(59,130,246,0.06)', borderRadius: 8, fontSize: 12, color: 'var(--text3)' }}>
          Configure SMTP in the <code style={{ fontFamily: 'monospace', color: 'var(--accent2)' }}>.env</code> file:{' '}
          <code style={{ fontFamily: 'monospace', color: '#60A5FA' }}>SMTP_HOST, SMTP_USER, SMTP_PASS</code>
        </div>
      </div>

      <div className="card">
        <p className="card-title">Webhook Integration</p>
        <p style={{ fontSize: 12, color: 'var(--text3)', marginBottom: 12, lineHeight: 1.6 }}>
          Receive real-time scan events via HTTP POST to your endpoint (Slack, Teams, PagerDuty, custom).
        </p>
        <div style={{ display: 'flex', gap: 8 }}>
          <input className="input" placeholder="https://hooks.slack.com/services/..." value={webhook}
            onChange={e => setWebhook(e.target.value)} style={{ flex: 1 }} />
          <button className="btn btn-outline btn-sm" onClick={testWebhook} disabled={!webhook || testing}>
            {testing ? <Spinner size={13} /> : 'Test'}
          </button>
          <button className="btn btn-primary btn-sm" disabled={!webhook}>Save</button>
        </div>
      </div>
    </div>
  );
}

/* ── Security Tab ────────────────────────────────────────────── */
function SecurityTab() {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div className="card">
        <p className="card-title">Rate Limiting</p>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
          {[
            ['Scanner requests / minute', '120', 'Requests sent by the scanner to target per minute'],
            ['Max concurrent scans',      '3',   'Maximum simultaneous scans per organization'],
            ['Max crawl depth',           '5',   'Maximum URL depth the crawler will follow'],
            ['Max URLs per scan',         '500', 'Maximum URLs analyzed in a single scan'],
          ].map(([label, val, desc]) => (
            <div key={label as string} style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '10px 14px', background: 'var(--surface2)', borderRadius: 8 }}>
              <div style={{ flex: 1 }}>
                <p style={{ fontSize: 13, color: 'var(--text)', fontWeight: 500 }}>{label}</p>
                <p style={{ fontSize: 11, color: 'var(--text3)', marginTop: 2 }}>{desc}</p>
              </div>
              <span style={{ fontFamily: 'monospace', fontSize: 14, fontWeight: 700, color: 'var(--accent2)' }}>{val}</span>
            </div>
          ))}
        </div>
        <p style={{ fontSize: 11, color: 'var(--text3)', marginTop: 12 }}>
          Adjust in <code style={{ fontFamily: 'monospace', color: '#60A5FA' }}>.env</code> file. Changes take effect on restart.
        </p>
      </div>

      <div className="card">
        <p className="card-title">Security Hardening</p>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          {[
            ['✓', 'JWT token authentication on all API endpoints',   '#22C55E'],
            ['✓', 'Role-based access control (Admin/Analyst/Viewer)', '#22C55E'],
            ['✓', 'Whitelist-only scanning — unauthorized targets blocked', '#22C55E'],
            ['✓', 'Organization-level data isolation (multi-tenant)', '#22C55E'],
            ['✓', 'Full audit trail for all platform actions',        '#22C55E'],
            ['✓', 'Rate limiting on scanner requests',                '#22C55E'],
            ['✓', 'CORS protection configured',                       '#22C55E'],
            ['✓', 'No destructive payloads — passive detection only', '#22C55E'],
          ].map(([icon, text, color]) => (
            <div key={text as string} style={{ display: 'flex', alignItems: 'center', gap: 10, fontSize: 13, color: 'var(--text2)' }}>
              <span style={{ color: color as string, fontWeight: 700, flexShrink: 0 }}>{icon}</span>
              {text}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
