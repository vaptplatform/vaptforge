export interface User {
  id: string; email: string; full_name: string;
  role: 'admin'|'analyst'|'viewer'; org_id: string; last_login?: string;
}
export interface AuthState { user: User|null; token: string|null; isAuthenticated: boolean; }

export type ScanStatus  = 'queued'|'running'|'completed'|'failed'|'cancelled'|'paused';
export type ScanProfile = 'full_owasp'|'quick'|'api_security'|'auth_deep'|'passive_only';
export type Severity    = 'critical'|'high'|'medium'|'low'|'info';
export type FindingStatus = 'open'|'in_review'|'accepted'|'fixed'|'false_positive';
export type DetectionMethod = 'SAST' | 'DAST';

export interface Scan {
  id: string; target_url: string; target_domain: string; profile: ScanProfile;
  status: ScanStatus; progress: number; risk_score: number|null;
  critical_count: number; high_count: number; medium_count: number;
  low_count: number; info_count: number; urls_crawled: number;
  total_requests: number; created_at: string; started_at: string|null;
  completed_at: string|null; error_message: string|null;
}
export interface CreateScanPayload {
  target_url: string; profile: ScanProfile;
  enabled_modules: Record<string,boolean>; scan_options: Record<string,unknown>;
}
export interface Finding {
  id: string; scan_id: string; owasp_category: string; owasp_name: string;
  title: string; description: string; severity: Severity; status: FindingStatus;
  affected_url: string; affected_parameter: string|null; http_method: string;
  risk_score: number; cvss_score: number|null; confidence: number;
  evidence: Record<string,unknown>; remediation: string; references: string[];
  is_false_positive: boolean; detected_at: string;

  // ── Deduplication fields (populated by backend when dedupe=true) ──
  detection_methods?: DetectionMethod[];   // e.g. ["SAST","DAST"]
  affected_urls?: string[];                // multi-URL grouping (e.g. 8× TRACE)
  duplicate_count?: number;               // how many raw findings were merged
}
export interface Domain {
  id: string; domain: string; status: 'pending'|'verified'|'revoked';
  verified_at: string|null; notes: string;
}
export interface OrgUser {
  id: string; email: string; full_name: string;
  role: 'admin'|'analyst'|'viewer'; is_active: boolean; last_login: string|null;
}
export type LogLevel = 'INFO'|'SCAN'|'WARN'|'CRIT'|'OK'|'ERROR'|'DEBUG';
export interface LogEntry {
  id: string; type: string; level: LogLevel; message: string; scan_id: string;
  url?: string; response_time_ms?: number; progress?: number; timestamp: string;
  total?: number; counts?: Record<string,number>; risk_score?: number;
  duration_seconds?: number; logs?: LogEntry[];
}
export const OWASP_MAP: Record<string,string> = {
  A01: 'Broken Access Control',
  A02: 'Cryptographic Failures',
  A03: 'Injection (SQLi / XSS / SSTI)',
  A04: 'Insecure Design',
  A05: 'Security Misconfiguration',
  A06: 'Vulnerable Components',
  A07: 'Authentication Failures',
  A08: 'Integrity Failures (SRI/Deserialization)',
  A09: 'Logging & Monitoring Failures',
  A10: 'SSRF',
};
export const SEV_ORDER: Record<Severity,number> = {
  critical:5, high:4, medium:3, low:2, info:1,
};