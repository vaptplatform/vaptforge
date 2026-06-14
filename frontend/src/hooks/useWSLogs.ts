import { useEffect, useRef, useState, useCallback } from 'react';
import type { LogEntry } from '../types';

interface UseWSLogsOptions {
  scanId: string | null;
  enabled?: boolean;
}

export function useWSLogs({ scanId, enabled = true }: UseWSLogsOptions) {
  const [logs, setLogs]           = useState<LogEntry[]>([]);
  const [progress, setProgress]   = useState(0);
  const [connected, setConnected] = useState(false);
  const [scanComplete, setScanComplete] = useState(false);
  const wsRef    = useRef<WebSocket | null>(null);
  const pingRef  = useRef<ReturnType<typeof setInterval> | null>(null);
  const retryRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const mountedRef = useRef(true);

  const connect = useCallback(() => {
    if (!scanId || !enabled || !mountedRef.current) return;

    // Clean up previous connection
    if (wsRef.current) {
      wsRef.current.onclose = null;
      wsRef.current.onerror = null;
      wsRef.current.onmessage = null;
      if (wsRef.current.readyState <= WebSocket.OPEN) {
        wsRef.current.close();
      }
    }

    const token = localStorage.getItem('vapt_token') ?? '';
    const proto = window.location.protocol === 'https:' ? 'wss' : 'ws';
    const host  = window.location.host;
    const url   = `${proto}://${host}/api/v1/ws/scan/${scanId}/logs?token=${encodeURIComponent(token)}`;

    let ws: WebSocket;
    try {
      ws = new WebSocket(url);
    } catch (e) {
      console.warn('WS connection failed:', e);
      return;
    }
    wsRef.current = ws;

    ws.onopen = () => {
      if (!mountedRef.current) return;
      setConnected(true);
      // Keepalive ping every 25s
      pingRef.current = setInterval(() => {
        if (ws.readyState === WebSocket.OPEN) {
          ws.send('ping');
        }
      }, 25000);
    };

    ws.onmessage = (e) => {
      if (!mountedRef.current) return;
      try {
        const msg: LogEntry = JSON.parse(e.data);

        if (msg.type === 'pong') return;

        if (msg.type === 'history') {
          setLogs(msg.logs ?? []);
          return;
        }

        if (msg.type === 'progress_update' && msg.progress != null) {
          setProgress(Number(msg.progress) || 0);
          return;
        }

        if (msg.type === 'scan_complete') {
          setScanComplete(true);
          setProgress(100);
        }

        if (msg.type === 'log' || msg.type === 'scan_complete') {
          if (msg.progress != null) {
            setProgress(Number(msg.progress) || 0);
          }
          setLogs((prev) => {
            const next = [...prev, msg];
            return next.slice(-500);
          });
        }
      } catch {
        // Ignore parse errors
      }
    };

    ws.onclose = () => {
      if (!mountedRef.current) return;
      setConnected(false);
      if (pingRef.current) { clearInterval(pingRef.current); pingRef.current = null; }
      // Auto-reconnect after 3s if not complete
      if (!scanComplete) {
        retryRef.current = setTimeout(() => {
          if (mountedRef.current) connect();
        }, 3000);
      }
    };

    ws.onerror = () => {
      if (!mountedRef.current) return;
      setConnected(false);
    };
  }, [scanId, enabled]); // eslint-disable-line

  useEffect(() => {
    mountedRef.current = true;
    connect();
    return () => {
      mountedRef.current = false;
      if (retryRef.current) clearTimeout(retryRef.current);
      if (pingRef.current)  clearInterval(pingRef.current);
      if (wsRef.current) {
        wsRef.current.onclose   = null;
        wsRef.current.onerror   = null;
        wsRef.current.onmessage = null;
        wsRef.current.close();
      }
    };
  }, [connect]);

  return {
    logs,
    progress,
    connected,
    scanComplete,
    clearLogs: () => setLogs([]),
  };
}
