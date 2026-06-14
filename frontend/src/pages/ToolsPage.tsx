import React, { useState } from 'react';
import { Wrench, CheckCircle, AlertCircle, ExternalLink, Info } from 'lucide-react';

interface Tool {
  id: string;
  name: string;
  description: string;
  mode: string;
  status: 'active' | 'available' | 'configure';
  category: string;
  capabilities: string[];
  config_key?: string;
  docs_url: string;
}

const TOOLS: Tool[] = [
  {
    id: 'internal_scanner',
    name: 'VAPTForge Internal Scanner',
    description: 'Built-in crawling and OWASP Top 10 detection engine using behavior-based analysis.',
    mode: 'ACTIVE',
    status: 'active',
    category: 'Core',
    capabilities: ['OWASP A01–A10 detection', 'Response diffing', 'Reflection analysis', 'Error pattern matching', 'JWT analysis', 'Cookie security checks'],
    docs_url: '#',
  },
  {
    id: 'header_analyzer',
    name: 'HTTP Security Headers Analyzer',
    description: 'Checks all security-relevant HTTP response headers against best practices.',
    mode: 'ACTIVE',
    status: 'active',
    category: 'Headers',
    capabilities: ['CSP validation', 'HSTS check', 'X-Frame-Options', 'X-Content-Type-Options', 'Referrer-Policy', 'Permissions-Policy'],
    docs_url: 'https://securityheaders.com/',
  },
  {
    id: 'ssl_scanner',
    name: 'SSL/TLS Scanner',
    description: 'Inspects TLS configuration, certificate validity, and weak cipher detection.',
    mode: 'ACTIVE',
    status: 'active',
    category: 'Crypto',
    capabilities: ['TLS version detection', 'Certificate expiry check', 'Protocol downgrade detection', 'HTTP→HTTPS redirect check'],
    docs_url: 'https://www.ssllabs.com/ssltest/',
  },
  {
    id: 'traffic_collector',
    name: 'Traffic & Behavior Collector',
    description: 'Records all HTTP request/response pairs during scanning for anomaly detection and evidence collection.',
    mode: 'ACTIVE',
    status: 'active',
    category: 'Analysis',
    capabilities: ['Request/response capture', 'Timing analysis', 'Anomaly flagging', 'Endpoint profiling', 'Status code distribution'],
    docs_url: '#',
  },
  {
    id: 'owasp_zap',
    name: 'OWASP ZAP',
    description: 'World\'s most widely used web app security scanner. Integrated in passive-spider mode only — no active attacks.',
    mode: 'PASSIVE ONLY',
    status: 'configure',
    category: 'External',
    capabilities: ['Passive spider', 'Alert detection', 'Ajax spider', 'Passive scan rules'],
    config_key: 'ZAP_API_URL + ZAP_API_KEY',
    docs_url: 'https://www.zaproxy.org/docs/api/',
  },
  {
    id: 'nmap',
    name: 'Nmap',
    description: 'Network discovery and service fingerprinting. Only safe, non-intrusive flags used.',
    mode: 'SAFE SCAN',
    status: 'configure',
    category: 'External',
    capabilities: ['Open port detection', 'Service version detection', 'OS fingerprinting (light)', 'Non-aggressive timing (-T2)'],
    config_key: 'NMAP_PATH',
    docs_url: 'https://nmap.org/docs.html',
  },
  {
    id: 'cve_mapper',
    name: 'CVE Mapping Engine',
    description: 'Maps detected component versions to known CVEs from the NVD database.',
    mode: 'DATABASE',
    status: 'active',
    category: 'Intelligence',
    capabilities: ['Component version matching', 'CVE reference links', 'CVSS score mapping', 'NVD integration'],
    docs_url: 'https://nvd.nist.gov/',
  },
  {
    id: 'fingerprinting',
    name: 'Technology Fingerprinting',
    description: 'Identifies web frameworks, CMS, server software, and JavaScript libraries from response signatures.',
    mode: 'PASSIVE',
    status: 'active',
    category: 'Intelligence',
    capabilities: ['Server header analysis', 'X-Powered-By detection', 'JS library version extraction', 'Framework detection'],
    docs_url: '#',
  },
];

const STATUS_CONFIG = {
  active:     { label: 'Active',     color: '#22C55E', bg: 'rgba(34,197,94,0.1)',    border: 'rgba(34,197,94,0.25)' },
  available:  { label: 'Available',  color: '#60A5FA', bg: 'rgba(59,130,246,0.1)',   border: 'rgba(59,130,246,0.25)' },
  configure:  { label: 'Configure',  color: '#FDB87D', bg: 'rgba(249,115,22,0.1)',   border: 'rgba(249,115,22,0.25)' },
};

export default function ToolsPage() {
  const [selected, setSelected] = useState<Tool | null>(null);
  const categories = [...new Set(TOOLS.map(t => t.category))];

  return (
    <div className="fade-up" style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <div>
        <h1 style={{ fontSize: 20, fontWeight: 800, color: 'var(--text)' }}>Security Tool Integrations</h1>
        <p style={{ fontSize: 12, color: 'var(--text3)', marginTop: 2 }}>
          All tools operate in safe, non-destructive mode only. No exploit payloads are used.
        </p>
      </div>

      <div style={{ background: 'rgba(34,197,94,0.06)', border: '1px solid rgba(34,197,94,0.2)', borderRadius: 10, padding: '12px 16px', display: 'flex', alignItems: 'center', gap: 10 }}>
        <CheckCircle size={16} style={{ color: '#22C55E', flexShrink: 0 }} />
        <p style={{ fontSize: 13, color: '#86EFAC' }}>
          <strong>{TOOLS.filter(t => t.status === 'active').length} tools active</strong> —{' '}
          {TOOLS.filter(t => t.status === 'configure').length} require external configuration
        </p>
      </div>

      {categories.map(cat => (
        <div key={cat}>
          <p style={{ fontSize: 11, fontWeight: 600, color: 'var(--text3)', marginBottom: 10, textTransform: 'uppercase', letterSpacing: '0.8px' }}>{cat}</p>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {TOOLS.filter(t => t.category === cat).map(tool => {
              const sc = STATUS_CONFIG[tool.status];
              return (
                <div key={tool.id}
                  onClick={() => setSelected(selected?.id === tool.id ? null : tool)}
                  style={{
                    background: 'var(--surface)', border: `1px solid ${selected?.id === tool.id ? 'rgba(59,130,246,0.4)' : 'var(--border)'}`,
                    borderRadius: 10, padding: '16px', cursor: 'pointer',
                    transition: 'border-color 0.15s',
                  }}
                  onMouseEnter={e => { if (selected?.id !== tool.id) (e.currentTarget as HTMLElement).style.borderColor = 'var(--border2)'; }}
                  onMouseLeave={e => { if (selected?.id !== tool.id) (e.currentTarget as HTMLElement).style.borderColor = 'var(--border)'; }}
                >
                  <div style={{ display: 'flex', alignItems: 'flex-start', gap: 14 }}>
                    <div style={{ width: 40, height: 40, background: 'var(--surface2)', borderRadius: 10, display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
                      <Wrench size={18} style={{ color: 'var(--accent2)' }} />
                    </div>
                    <div style={{ flex: 1 }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 4 }}>
                        <p style={{ fontSize: 14, fontWeight: 700, color: 'var(--text)' }}>{tool.name}</p>
                        <span style={{ fontSize: 10, padding: '2px 7px', borderRadius: 4, fontFamily: 'monospace', fontWeight: 700, background: sc.bg, color: sc.color, border: `1px solid ${sc.border}` }}>
                          {tool.mode}
                        </span>
                      </div>
                      <p style={{ fontSize: 12, color: 'var(--text2)', lineHeight: 1.5 }}>{tool.description}</p>
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexShrink: 0 }}>
                      <span style={{ width: 8, height: 8, borderRadius: '50%', background: sc.color, display: 'inline-block', boxShadow: `0 0 6px ${sc.color}` }} />
                      <span style={{ fontSize: 11, color: sc.color, fontFamily: 'monospace', fontWeight: 600 }}>{sc.label}</span>
                    </div>
                  </div>

                  {selected?.id === tool.id && (
                    <div style={{ marginTop: 14, paddingTop: 14, borderTop: '1px solid var(--border)' }}>
                      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
                        <div>
                          <p style={{ fontSize: 10, color: 'var(--text3)', fontWeight: 600, marginBottom: 8, textTransform: 'uppercase' }}>Capabilities</p>
                          {tool.capabilities.map(c => (
                            <div key={c} style={{ display: 'flex', alignItems: 'center', gap: 7, fontSize: 12, color: 'var(--text2)', marginBottom: 4 }}>
                              <span style={{ color: '#22C55E', fontSize: 10 }}>✓</span>{c}
                            </div>
                          ))}
                        </div>
                        {tool.config_key && (
                          <div>
                            <p style={{ fontSize: 10, color: 'var(--text3)', fontWeight: 600, marginBottom: 8, textTransform: 'uppercase' }}>Configuration</p>
                            <p style={{ fontSize: 12, color: 'var(--text2)', marginBottom: 8 }}>
                              Set these environment variables in your <code style={{ fontFamily: 'monospace', color: '#60A5FA' }}>.env</code> file:
                            </p>
                            <div style={{ background: 'var(--bg)', borderRadius: 6, padding: '8px 12px', fontFamily: 'monospace', fontSize: 11, color: '#FDB87D', border: '1px solid var(--border)' }}>
                              {tool.config_key.split(' + ').map(k => <div key={k}>{k}=your_value</div>)}
                            </div>
                          </div>
                        )}
                      </div>
                      <a href={tool.docs_url} target="_blank" rel="noreferrer"
                        style={{ display: 'inline-flex', alignItems: 'center', gap: 5, fontSize: 12, color: 'var(--accent2)', marginTop: 12 }}
                        onClick={e => e.stopPropagation()}>
                        <ExternalLink size={12} /> Documentation
                      </a>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      ))}
    </div>
  );
}
