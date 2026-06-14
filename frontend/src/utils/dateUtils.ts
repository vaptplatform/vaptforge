/**
 * VAPTForge Date Utilities - single source of truth for all date formatting
 * Fixes: timezone mismatch, null crashes, relative time accuracy
 */
import { format, formatDistanceToNow, isValid, parseISO } from 'date-fns';

export function safeParse(value: string | Date | null | undefined): Date | null {
  if (!value) return null;
  if (value instanceof Date) return isValid(value) ? value : null;
  const str = String(value);
  if (!str) return null;
  // Append Z if no timezone info — treats backend UTC timestamps correctly
  const normalized = str.includes('Z') || str.includes('+') || str.includes('-', 10)
    ? str
    : str + 'Z';
  const parsed = parseISO(normalized);
  if (isValid(parsed)) return parsed;
  const native = new Date(str);
  return isValid(native) ? native : null;
}

/** "04 May 2026, 12:45 PM" */
export function formatExact(value: string | Date | null | undefined): string {
  const d = safeParse(value);
  if (!d) return '—';
  try { return format(d, 'dd MMM yyyy, hh:mm a'); } catch { return '—'; }
}

/** "2 minutes ago" */
export function formatRelative(value: string | Date | null | undefined): string {
  const d = safeParse(value);
  if (!d) return '';
  try { return formatDistanceToNow(d, { addSuffix: true }); } catch { return ''; }
}

/** "47m 23s" */
export function formatDuration(
  start: string | Date | null | undefined,
  end:   string | Date | null | undefined
): string {
  const s = safeParse(start);
  const e = safeParse(end);
  if (!s || !e) return '—';
  const secs = Math.round((e.getTime() - s.getTime()) / 1000);
  if (secs < 0) return '—';
  const m = Math.floor(secs / 60);
  return m === 0 ? `${secs}s` : `${m}m ${secs % 60}s`;
}

/** Both: { exact: "04 May 2026, 12:45 PM", relative: "2 minutes ago" } */
export function formatBoth(value: string | Date | null | undefined) {
  return { exact: formatExact(value), relative: formatRelative(value) };
}
