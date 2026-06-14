import React from 'react';
import { NavLink, useNavigate } from 'react-router-dom';
import {
  LayoutDashboard, Play, List, ShieldAlert, Grid3x3,
  Flame, Wrench, FileText, ScrollText, Settings,
  Sun, Moon, LogOut, Building2, ChevronLeft, ChevronRight,
  ScanSearch,
} from 'lucide-react';
import { useAuthStore, useThemeStore, useUIStore } from '../../store';
import { StatusDot } from '../shared/UI';

const NAV = [
  { group: 'Platform', items: [
    { to: '/dashboard',  icon: LayoutDashboard, label: 'Dashboard',       end: true },
    { to: '/scans/new',  icon: Play,            label: 'New Scan',        end: true },
    { to: '/scans',      icon: List,            label: 'Scan History',    end: true },
  ]},
  { group: 'Analysis', items: [
    { to: '/findings',   icon: ShieldAlert,     label: 'Vulnerabilities', end: true },
    { to: '/owasp',      icon: Grid3x3,         label: 'OWASP Top 10',    end: true },
    { to: '/heatmap',    icon: Flame,           label: 'Risk Heatmap',    end: true },
  ]},
  { group: 'Tools', items: [
    { to: '/scanners',   icon: ScanSearch,      label: 'SAST / DAST',     end: true },
    { to: '/tools',      icon: Wrench,          label: 'Security Tools',  end: true },
    { to: '/reports',    icon: FileText,        label: 'Reports',         end: true },
  ]},
  { group: 'System', items: [
    { to: '/audit',      icon: ScrollText,      label: 'Audit Log',       end: true },
    { to: '/settings',   icon: Settings,        label: 'Settings',        end: true },
  ]},
];

export default function AppShell({ children }: { children: React.ReactNode }) {
  const { user, logout } = useAuthStore();
  const { dark, toggle } = useThemeStore();
  const { sidebarOpen, setSidebarOpen, activeScanId } = useUIStore();
  const navigate = useNavigate();

  const handleLogout = () => { logout(); navigate('/login'); };

  return (
    <div style={{
      display: 'grid',
      gridTemplateColumns: sidebarOpen ? '220px 1fr' : '56px 1fr',
      gridTemplateRows: '52px 1fr',
      height: '100vh',
      background: 'var(--bg)',
    }}>
      {/* ── Topbar ── */}
      <header style={{
        gridColumn: '1/-1',
        background: 'var(--surface)',
        borderBottom: '1px solid var(--border)',
        display: 'flex', alignItems: 'center', gap: 12,
        padding: '0 16px', zIndex: 20,
      }}>
        <span style={{ fontWeight: 800, fontSize: 15, letterSpacing: '-0.5px', whiteSpace: 'nowrap' }}>
          ■ <span style={{ color: 'var(--accent2)', fontWeight: 900 }}>VAPT</span><span style={{ color: '#93C5FD', fontWeight: 900 }}>Forge</span>
        </span>
        {activeScanId && (
          <span style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 11, color: '#22C55E', marginLeft: 8 }}>
            <StatusDot status="running" /> Active scan
          </span>
        )}
        <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 8 }}>
          <div style={{ position: 'relative', display: 'inline-flex' }}
            title={dark ? 'Switch to Light Mode' : 'Switch to Dark Mode'}>
            <button
              onClick={toggle}
              style={{
                display: 'flex', alignItems: 'center', gap: 6,
                padding: '5px 10px', borderRadius: 7, cursor: 'pointer',
                background: dark ? 'rgba(255,255,255,0.06)' : 'rgba(0,0,0,0.06)',
                border: `1px solid ${dark ? 'rgba(255,255,255,0.12)' : 'rgba(0,0,0,0.12)'}`,
                color: 'var(--text2)', fontSize: 11, fontWeight: 600,
                transition: 'all 0.15s',
              }}
              onMouseEnter={e => {
                e.currentTarget.style.background = dark ? 'rgba(255,255,255,0.12)' : 'rgba(0,0,0,0.1)';
                e.currentTarget.style.color = 'var(--text)';
              }}
              onMouseLeave={e => {
                e.currentTarget.style.background = dark ? 'rgba(255,255,255,0.06)' : 'rgba(0,0,0,0.06)';
                e.currentTarget.style.color = 'var(--text2)';
              }}
            >
              {dark
                ? <><Sun size={13} style={{ color: '#FCD34D' }} /><span style={{ fontSize: 11 }}>Light</span></>
                : <><Moon size={13} style={{ color: '#818CF8' }} /><span style={{ fontSize: 11 }}>Dark</span></>
              }
            </button>
          </div>
          <div style={{
            display: 'flex', alignItems: 'center', gap: 8,
            background: 'var(--surface2)', border: '1px solid var(--border)',
            borderRadius: 8, padding: '5px 10px',
          }}>
            <Building2 size={13} style={{ color: 'var(--text3)' }} />
            <span style={{ fontSize: 12, color: 'var(--text2)' }}>{user?.full_name}</span>
            <span style={{
              fontSize: 10, padding: '1px 6px', borderRadius: 4,
              background: user?.role === 'admin' ? 'rgba(168,85,247,0.15)' : user?.role === 'analyst' ? 'rgba(59,130,246,0.15)' : 'rgba(34,197,94,0.1)',
              color: user?.role === 'admin' ? '#D8B4FE' : user?.role === 'analyst' ? '#93C5FD' : '#86EFAC',
              border: `1px solid ${user?.role === 'admin' ? 'rgba(168,85,247,0.3)' : user?.role === 'analyst' ? 'rgba(59,130,246,0.3)' : 'rgba(34,197,94,0.25)'}`,
              textTransform: 'uppercase', fontWeight: 700,
            }}>
              {user?.role}
            </span>
          </div>
          <button className="btn btn-ghost btn-sm" onClick={handleLogout} title="Logout" style={{ padding: '5px 8px' }}>
            <LogOut size={14} />
          </button>
        </div>
      </header>

      {/* ── Sidebar ── */}
      <aside style={{
        background: 'var(--surface)', borderRight: '1px solid var(--border)',
        padding: '8px 0', display: 'flex', flexDirection: 'column', overflow: 'hidden',
      }}>
        {NAV.map((group) => (
          <div key={group.group} style={{ marginBottom: 4 }}>
            {sidebarOpen && (
              <div style={{
                fontSize: 9, fontWeight: 700, color: 'var(--text3)',
                textTransform: 'uppercase', letterSpacing: '1px',
                padding: '10px 14px 4px',
              }}>
                {group.group}
              </div>
            )}
            {group.items.map(({ to, icon: Icon, label, end }) => (
              <div key={to} style={{ padding: '1px 8px' }}>
                <NavLink
                  to={to} end={end}
                  className={({ isActive }) => `nav-link ${isActive ? 'active' : ''}`}
                  style={{ justifyContent: sidebarOpen ? 'flex-start' : 'center' }}
                  title={!sidebarOpen ? label : undefined}
                >
                  <Icon size={15} style={{ flexShrink: 0 }} />
                  {sidebarOpen && <span style={{ fontSize: 13 }}>{label}</span>}
                </NavLink>
              </div>
            ))}
          </div>
        ))}

        <div style={{ marginTop: 'auto', padding: '8px' }}>
          <button
            className="btn btn-ghost btn-sm"
            onClick={() => setSidebarOpen(!sidebarOpen)}
            title={sidebarOpen ? 'Collapse Sidebar' : 'Expand Sidebar'}
            style={{
              width: '100%',
              justifyContent: sidebarOpen ? 'flex-start' : 'center',
              padding: '7px 10px',
              gap: 8,
              overflow: 'hidden',
              transition: 'all 0.2s ease',
            }}
          >
            <span style={{
              display: 'flex', alignItems: 'center', flexShrink: 0,
              transition: 'transform 0.2s ease',
            }}>
              {sidebarOpen ? <ChevronLeft size={14} /> : <ChevronRight size={14} />}
            </span>
            {sidebarOpen && (
              <span style={{
                fontSize: 11, color: 'var(--text3)', fontWeight: 500,
                whiteSpace: 'nowrap', overflow: 'hidden',
                animation: 'fadeIn 0.15s ease',
              }}>
                Collapse Sidebar
              </span>
            )}
          </button>
          {!sidebarOpen && (
            <div style={{
              fontSize: 7, color: 'var(--text3)', textAlign: 'center',
              marginTop: 3, letterSpacing: '0.4px', fontWeight: 600,
              textTransform: 'uppercase', opacity: 0.55,
              animation: 'fadeIn 0.15s ease',
              lineHeight: 1.3,
            }}>
              Expand Sidebar
            </div>
          )}
        </div>
      </aside>

      {/* ── Main ── */}
      <main style={{
        overflow: 'auto', padding: '24px',
        background: 'var(--bg)',
      }}>
        {children}
      </main>
    </div>
  );
}