import axios from 'axios';
import type { Scan, CreateScanPayload, Finding } from '../types';

const api = axios.create({
  baseURL: import.meta.env.VITE_API_URL ? `${import.meta.env.VITE_API_URL}/api/v1` : '/api/v1',
  headers: { 'Content-Type': 'application/json' },
});

api.interceptors.request.use((config) => {
  const token = localStorage.getItem('vapt_token');
  if (token) config.headers.Authorization = `Bearer ${token}`;
  return config;
});
api.interceptors.response.use(
  (r) => r,
  (err) => {
    if (err.response?.status === 401) {
      localStorage.removeItem('vapt_token');
      window.location.href = '/login';
    } 
    return Promise.reject(err);
  }
);

export const authAPI = {
  login:    (email: string, password: string) =>
              api.post('/auth/login', { email, password }),
  register: (email: string, password: string, full_name: string, org_name: string) =>
              api.post('/auth/register', { email, password, full_name, org_name }),
  me:       () => api.get('/auth/me'),
  forgotPassword: (email: string) =>
              api.post('/auth/forgot-password', { email }),
  resetPassword: (token: string, new_password: string) =>
              api.post('/auth/reset-password', { token, new_password }),
};

export const scansAPI = {
  create:  (payload: CreateScanPayload) => api.post<Scan>('/scans', payload),
  list:    (page = 1, status?: string)  =>
             api.get<{ scans: Scan[] }>('/scans', { params: { page, per_page: 20, status } }),
  get:     (id: string) => api.get<Scan>(`/scans/${id}`),
  cancel:  (id: string) => api.post(`/scans/${id}/cancel`),
  delete:  (id: string) => api.delete(`/scans/${id}`),
  traffic: (id: string) => api.get(`/scans/${id}/traffic-summary`),
};

export const findingsAPI = {
  list: (params: {
    scan_id?:  string;
    severity?: string;
    owasp?:    string;
    page?:     number;
    dedupe?:   boolean;   // ← added: request server-side deduplication
  }) => api.get<{ findings: Finding[]; total: number; deduplicated: boolean }>(
         '/findings', { params }
       ),
  get:  (id: string) => api.get<Finding>(`/findings/${id}`),
  updateStatus: (id: string, status: string, reason?: string) =>
                  api.patch(`/findings/${id}/status`, { status, reason }),
};

export const reportsAPI = {
  downloadJson: (scanId: string) =>
    api.get(`/reports/${scanId}/json`, { responseType: 'blob' }),
  downloadHtml: (scanId: string) =>
    api.get(`/reports/${scanId}/html`, { responseType: 'blob' }),
  downloadPdf:  (scanId: string) =>
    api.get(`/reports/${scanId}/pdf`,  { responseType: 'blob' }),
  regenerate: (scanId: string, recipients: string[], sendEmail: boolean, includePdf = true) =>
    api.post(`/reports/${scanId}/regenerate`, {
      send_email: sendEmail, recipients, include_pdf: includePdf,
    }),
};

export const alertsAPI = {
  sendReport: (scanId: string, recipients: string[], message?: string, includePdf = true) =>
    api.post('/alerts/send-report', { scan_id: scanId, recipients, message, include_pdf: includePdf }),
  sendAlert: (scanId: string, recipients: string[], message?: string, findingId?: string) =>
    api.post('/alerts/send-alert', { scan_id: scanId, recipients, message, finding_id: findingId }),
  testWebhook:   (url: string) => api.post('/alerts/test-webhook', { webhook_url: url }),
  notifications: (scanId: string) => api.get(`/alerts/scan/${scanId}/notification-status`),
};

export const domainsAPI = {
  list:   ()                          => api.get<{ domains: any[] }>('/domains'),
  add:    (domain: string, notes = '') => api.post('/domains', { domain, notes }),
  verify: (id: string)                => api.post(`/domains/${id}/verify`),
  remove: (id: string)                => api.delete(`/domains/${id}`),
};

export const usersAPI = {
  list:   ()                            => api.get<{ users: any[] }>('/users'),
  create: (data: any)                   => api.post('/users', data),
  update: (id: string, data: Partial<any>) => api.patch(`/users/${id}`, data),
};

export const auditAPI = {
  list: (page = 1, action?: string) =>
    api.get('/audit', { params: { per_page: 200, page, action } }),
};

export function downloadBlob(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const a   = document.createElement('a');
  a.href = url; a.download = filename;
  document.body.appendChild(a); a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

export default api;

export const scannersAPI = {
  sastScanCode: (code: string, filename: string) =>
    api.post('/scanners/sast/code', { code, filename }),
  dastScan: (target_url: string, timeout = 60, max_urls = 30) =>
    api.post('/scanners/dast/scan', { target_url, timeout, max_urls }),
  sastRules: () => api.get('/scanners/sast/rules'),
}; 