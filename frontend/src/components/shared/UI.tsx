import React, { useEffect, useRef } from 'react';
import { X, CheckCircle, AlertTriangle, Info, XCircle } from 'lucide-react';
import { useToastStore } from '../../store';
import type { Severity } from '../../types';

// ── Toast notifications ───────────────────────────────────────
export function ToastContainer() {
  const { toasts, remove } = useToastStore();
  if (!toasts.length) return null;
  return (
    <div className="fixed top-5 right-5 z-50 flex flex-col gap-2">
      {toasts.map((t) => (
        <div
          key={t.id}
          className="flex items-center gap-3 px-4 py-3 rounded-xl shadow-2xl text-sm font-medium animate-fade-up max-w-sm"
          style={{
            background: 'var(--surface)',
            border: `1px solid ${t.type === 'success' ? 'rgba(34,197,94,0.35)' : t.type === 'error' ? 'rgba(239,68,68,0.35)' : t.type === 'warn' ? 'rgba(249,115,22,0.35)' : 'rgba(59,130,246,0.35)'}`,
            color: t.type === 'success' ? '#86EFAC' : t.type === 'error' ? '#FCA5A5' : t.type === 'warn' ? '#FDB87D' : '#93C5FD',
          }}
        >
          {t.type === 'success' && <CheckCircle size={15} />}
          {t.type === 'error'   && <XCircle size={15} />}
          {t.type === 'warn'    && <AlertTriangle size={15} />}
          {t.type === 'info'    && <Info size={15} />}
          <span style={{ color: 'var(--text)' }}>{t.message}</span>
          <button onClick={() => remove(t.id)} style={{ color: 'var(--text3)', marginLeft: 'auto' }}>
            <X size={13} />
          </button>
        </div>
      ))}
    </div>
  );
}

// ── Severity badge ────────────────────────────────────────────
export function SevBadge({ sev }: { sev: string }) {
  const cls = `badge-${sev.toLowerCase()}`;
  return (
    <span className={`${cls} px-2 py-0.5 rounded text-xs font-bold font-mono`}>
      {sev.toUpperCase()}
    </span>
  );
}

// ── Risk score pill ───────────────────────────────────────────
export function RiskScore({ score }: { score: number | null | undefined }) {
  if (score == null || !isFinite(Number(score))) return <span style={{ color: 'var(--text3)' }}>—</span>;
  const n = Number(score);
  const color = n >= 7 ? '#EF4444' : n >= 4 ? '#F97316' : '#EAB308';
  return (
    <span style={{ fontFamily:'monospace', fontWeight:700, fontSize:13, color }}>{n.toFixed(1)}</span>
  );
}

// ── Spinner ───────────────────────────────────────────────────
export function Spinner({ size = 18 }: { size?: number }) {
  return (
    <svg
      width={size} height={size} viewBox="0 0 24 24"
      fill="none" stroke="currentColor" strokeWidth="2.5"
      strokeLinecap="round" strokeLinejoin="round"
      style={{ animation: 'spin 0.8s linear infinite' }}
    >
      <style>{'@keyframes spin{to{transform:rotate(360deg)}}'}</style>
      <path d="M21 12a9 9 0 1 1-6.219-8.56" />
    </svg>
  );
}

// ── Modal ─────────────────────────────────────────────────────
interface ModalProps {
  open: boolean;
  onClose: () => void;
  title: string;
  children: React.ReactNode;
  width?: number;
}
export function Modal({ open, onClose, title, children, width = 520 }: ModalProps) {
  const overlayRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const handler = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); };
    if (open) document.addEventListener('keydown', handler);
    return () => document.removeEventListener('keydown', handler);
  }, [open, onClose]);
  if (!open) return null;
  return (
    <div
      ref={overlayRef}
      className="fixed inset-0 z-40 flex items-center justify-center p-4"
      style={{ background: 'rgba(0,0,0,0.7)', backdropFilter: 'blur(4px)' }}
      onClick={(e) => { if (e.target === overlayRef.current) onClose(); }}
    >
      <div
        className="fade-up w-full rounded-xl shadow-2xl"
        style={{ background: 'var(--surface)', border: '1px solid var(--border2)', maxWidth: width }}
      >
        <div className="flex items-center justify-between px-5 py-4" style={{ borderBottom: '1px solid var(--border)' }}>
          <h2 className="font-semibold text-sm" style={{ color: 'var(--text)' }}>{title}</h2>
          <button onClick={onClose} className="btn btn-ghost btn-sm p-1 rounded-lg"><X size={16} /></button>
        </div>
        <div className="p-5">{children}</div>
      </div>
    </div>
  );
}

// ── Empty state ───────────────────────────────────────────────
export function EmptyState({ icon, title, desc, action }: {
  icon: React.ReactNode; title: string; desc?: string; action?: React.ReactNode;
}) {
  return (
    <div className="flex flex-col items-center justify-center py-16 gap-3">
      <div style={{ color: 'var(--text3)', opacity: 0.5 }}>{icon}</div>
      <p className="font-semibold" style={{ color: 'var(--text2)' }}>{title}</p>
      {desc && <p className="text-xs text-center max-w-xs" style={{ color: 'var(--text3)' }}>{desc}</p>}
      {action}
    </div>
  );
}

// ── Status dot ────────────────────────────────────────────────
export function StatusDot({ status }: { status: string }) {
  const color =
    status === 'running' ? '#22C55E' :
    status === 'queued'  ? '#F97316' :
    status === 'failed'  ? '#EF4444' :
    status === 'completed' ? '#3B82F6' : '#64748B';
  return (
    <span
      className={status === 'running' ? 'pulse' : ''}
      style={{ display: 'inline-block', width: 8, height: 8, borderRadius: '50%', background: color, boxShadow: `0 0 5px ${color}` }}
    />
  );
}

// ── Section card wrapper ──────────────────────────────────────
export function Section({ title, children, action }: {
  title: string; children: React.ReactNode; action?: React.ReactNode;
}) {
  return (
    <div className="card">
      <div className="flex items-center justify-between mb-4">
        <span className="card-title" style={{ marginBottom: 0 }}>{title}</span>
        {action}
      </div>
      {children}
    </div>
  );
}

// ── Stat card ─────────────────────────────────────────────────
export function StatCard({ label, value, color, sub }: {
  label: string; value: React.ReactNode; color: string; sub?: string;
}) {
  return (
    <div className="card-sm">
      <p className="text-xs mb-1" style={{ color: 'var(--text3)', textTransform: 'uppercase', letterSpacing: '0.5px' }}>{label}</p>
      <p className="text-3xl font-bold leading-none" style={{ color }}>{value}</p>
      {sub && <p className="text-xs mt-1" style={{ color: 'var(--text3)' }}>{sub}</p>}
    </div>
  );
}

// ── Confirm dialog ────────────────────────────────────────────
export function ConfirmDialog({ open, onClose, onConfirm, title, message }: {
  open: boolean; onClose: () => void; onConfirm: () => void; title: string; message: string;
}) {
  return (
    <Modal open={open} onClose={onClose} title={title} width={420}>
      <p className="text-sm mb-5" style={{ color: 'var(--text2)', lineHeight: 1.6 }}>{message}</p>
      <div className="flex justify-end gap-2">
        <button className="btn btn-outline btn-sm" onClick={onClose}>Cancel</button>
        <button className="btn btn-danger btn-sm" onClick={() => { onConfirm(); onClose(); }}>Confirm</button>
      </div>
    </Modal>
  );
}
