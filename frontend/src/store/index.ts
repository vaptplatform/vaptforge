import { create } from 'zustand';
import { persist } from 'zustand/middleware';
import type { User } from '../types';

// ── Auth store ────────────────────────────────────────────────
interface AuthStore {
  user: User | null;
  token: string | null;
  setAuth: (user: User, token: string) => void;
  logout: () => void;
}

export const useAuthStore = create<AuthStore>()(
  persist(
    (set) => ({
      user: null,
      token: null,
      setAuth: (user, token) => {
        localStorage.setItem('vapt_token', token);
        set({ user, token });
      },
      logout: () => {
        localStorage.removeItem('vapt_token');
        set({ user: null, token: null });
      },
    }),
    { name: 'vapt-auth', partialize: (s) => ({ user: s.user, token: s.token }) }
  )
);

// ── Theme store ───────────────────────────────────────────────
interface ThemeStore {
  dark: boolean;
  toggle: () => void;
}

export const useThemeStore = create<ThemeStore>()(
  persist(
    (set, get) => ({
      dark: true,
      toggle: () => {
        const next = !get().dark;
        document.documentElement.classList.toggle('light', !next);
        set({ dark: next });
      },
    }),
    { name: 'vapt-theme' }
  )
);

// ── UI store (sidebar, active scan) ───────────────────────────
interface UIStore {
  sidebarOpen: boolean;
  activeScanId: string | null;
  setSidebarOpen: (v: boolean) => void;
  setActiveScan: (id: string | null) => void;
}

export const useUIStore = create<UIStore>((set) => ({
  sidebarOpen: true,
  activeScanId: null,
  setSidebarOpen: (v) => set({ sidebarOpen: v }),
  setActiveScan: (id) => set({ activeScanId: id }),
}));

// ── Notification toast store ──────────────────────────────────
export type ToastType = 'success' | 'error' | 'warn' | 'info';
interface Toast { id: string; type: ToastType; message: string; }
interface ToastStore {
  toasts: Toast[];
  add: (type: ToastType, message: string) => void;
  remove: (id: string) => void;
}

export const useToastStore = create<ToastStore>((set) => ({
  toasts: [],
  add: (type, message) => {
    const id = Math.random().toString(36).slice(2);
    set((s) => ({ toasts: [...s.toasts, { id, type, message }] }));
    setTimeout(() => set((s) => ({ toasts: s.toasts.filter((t) => t.id !== id) })), 4000);
  },
  remove: (id) => set((s) => ({ toasts: s.toasts.filter((t) => t.id !== id) })),
}));
