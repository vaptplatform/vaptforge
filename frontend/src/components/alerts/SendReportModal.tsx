import React, { useState, useEffect, useRef, useCallback } from 'react';
import { Mail, X, Plus, Send, Loader2, CheckCircle2 } from 'lucide-react';
import { Modal } from '../shared/UI';
import { alertsAPI } from '../../services/api';
import { useToastStore } from '../../store';

interface Props {
  open: boolean;
  onClose: () => void;
  scanId: string;
  targetUrl: string;
}

export default function SendReportModal({ open, onClose, scanId, targetUrl }: Props) {
  const addToast = useToastStore((s) => s.add);
  const [emails, setEmails]     = useState<string[]>(['']);
  const [message, setMessage]   = useState('');
  const [includePdf, setIncPdf] = useState(true);
  const [loading, setLoading]   = useState(false);
  const [sent, setSent]         = useState(false);
  const mountedRef = useRef(true);

  // ── Full state reset on every open/close cycle ──
  // This prevents stale "Sending…" when modal is closed mid-flight and reopened.
  useEffect(() => {
    mountedRef.current = true;
    if (open) {
      setEmails(['']);
      setMessage('');
      setIncPdf(true);
      setLoading(false);  // ← must reset here, not just on close
      setSent(false);
    }
    return () => { mountedRef.current = false; };
  }, [open]);

  const handleClose = useCallback(() => {
    // Sync reset before notifying parent — prevents flash of stale state on reopen
    setLoading(false);
    setSent(false);
    setEmails(['']);
    setMessage('');
    onClose();
  }, [onClose]);

  const addEmail   = () => setEmails((e) => [...e, '']);
  const rmEmail    = (i: number) => setEmails((e) => e.filter((_, idx) => idx !== i));
  const setEmail   = (i: number, v: string) => setEmails((e) => e.map((x, idx) => idx === i ? v : x));

  const send = async () => {
    const valid = emails.filter((e) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e));
    if (!valid.length) { addToast('error', 'Enter at least one valid email'); return; }
    setLoading(true);
    try {
      const result = await alertsAPI.sendReport(scanId, valid, message, includePdf);
      if (!mountedRef.current) return;
      if (result.data.success) {
        setSent(true);
        addToast('success', `Report emailed successfully to ${valid.length} recipient${valid.length > 1 ? 's' : ''}`);
        setTimeout(() => { if (mountedRef.current) handleClose(); }, 2200);
      } else {
        addToast('error', result.data.message ?? 'Send failed');
      }
    } catch (err: any) {
      if (!mountedRef.current) return;
      addToast('error', err.response?.data?.detail ?? 'Failed to send email');
    } finally {
      // Always reset loading — even after success — so reopen is clean
      if (mountedRef.current) setLoading(false);
    }
  };

  return (
    <Modal open={open} onClose={handleClose} title="Send Security Report" width={520}>
      {sent ? (
        <div style={{ textAlign: 'center', padding: '24px 0' }}>
          <CheckCircle2 size={48} style={{ color: '#22C55E', margin: '0 auto 14px' }} />
          <p style={{ color: '#86EFAC', fontWeight: 700, fontSize: 16, marginBottom: 6 }}>Report Emailed Successfully!</p>
          <p style={{ color: 'var(--text3)', fontSize: 12 }}>Closing automatically…</p>
          <button className="btn btn-outline btn-sm" style={{ marginTop: 18 }} onClick={handleClose}>Close Now</button>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          {/* Target info */}
          <div style={{ background: 'var(--surface2)', border: '1px solid var(--border)', borderRadius: 8, padding: '10px 14px' }}>
            <p style={{ fontSize: 10, color: 'var(--text3)', marginBottom: 2 }}>SCAN TARGET</p>
            <p style={{ fontSize: 13, color: '#60A5FA', fontFamily: 'monospace', wordBreak: 'break-all' }}>{targetUrl}</p>
          </div>

          {/* Recipients */}
          <div>
            <label style={{ fontSize: 11, color: 'var(--text3)', display: 'block', marginBottom: 8, fontWeight: 600 }}>
              RECIPIENTS
            </label>
            {emails.map((email, i) => (
              <div key={i} style={{ display: 'flex', gap: 6, marginBottom: 6 }}>
                <input
                  className="input"
                  type="email"
                  placeholder="security@company.com"
                  value={email}
                  onChange={(e) => setEmail(i, e.target.value)}
                />
                {emails.length > 1 && (
                  <button type="button" onClick={() => rmEmail(i)} className="btn btn-ghost" style={{ padding: '6px 10px', color: '#FCA5A5' }}>
                    <X size={14} />
                  </button>
                )}
              </div>
            ))}
            {emails.length < 10 && (
              <button type="button" onClick={addEmail} className="btn btn-ghost btn-sm" style={{ marginTop: 2 }}>
                <Plus size={13} /> Add recipient
              </button>
            )}
          </div>

          {/* Message */}
          <div>
            <label style={{ fontSize: 11, color: 'var(--text3)', display: 'block', marginBottom: 5, fontWeight: 600 }}>
              MESSAGE <span style={{ fontWeight: 400, opacity: 0.6 }}>(optional)</span>
            </label>
            <textarea
              className="input"
              rows={3}
              placeholder="Please find the VAPT security assessment report attached…"
              value={message}
              onChange={(e) => setMessage(e.target.value)}
              style={{ resize: 'vertical', lineHeight: 1.5 }}
            />
          </div>

          {/* Options */}
          <label style={{ display: 'flex', alignItems: 'center', gap: 10, cursor: 'pointer' }}>
            <input type="checkbox" checked={includePdf} onChange={(e) => setIncPdf(e.target.checked)}
              style={{ accentColor: 'var(--accent)', width: 14, height: 14 }} />
            <span style={{ fontSize: 13, color: 'var(--text2)' }}>Attach PDF report</span>
          </label>

          {/* Actions */}
          <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end', paddingTop: 4 }}>
            <button type="button" className="btn btn-outline btn-sm" onClick={handleClose} disabled={loading}>Cancel</button>
            <button type="button" className="btn btn-primary btn-sm" onClick={send} disabled={loading}>
              {loading
                ? <><Loader2 size={13} className="animate-spin"/> Sending…</>
                : <><Send size={13}/> Send Report</>}
            </button>
          </div>
        </div>
      )}
    </Modal>
  );
}
