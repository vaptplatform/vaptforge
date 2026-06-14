import React, { useEffect } from 'react';
import { BrowserRouter, Routes, Route, Navigate, useLocation } from 'react-router-dom';
import { useAuthStore, useThemeStore } from './store';
import AppShell from './components/shared/AppShell';
import { ToastContainer } from './components/shared/UI';

import { LoginPage, RegisterPage, ForgotPasswordPage, ResetPasswordPage } from './pages/AuthPages';
import DashboardPage   from './pages/DashboardPage';
import NewScanPage     from './pages/NewScanPage';
import ScanHistoryPage from './pages/ScanHistoryPage';
import ScanDetailPage  from './pages/ScanDetailPage';
import { FindingsPage } from './pages/FindingsPage';
import OWASPPage       from './pages/OWASPPage';
import HeatmapPage     from './pages/HeatmapPage';
import ToolsPage       from './pages/ToolsPage';
import ReportsPage     from './pages/ReportsPage';
import AuditPage       from './pages/AuditPage';
import SettingsPage    from './pages/SettingsPage';
import ScannerPage     from './pages/ScannerPage';

function ThemeBootstrap() {
  const { dark } = useThemeStore();
  useEffect(() => {
    document.documentElement.classList.toggle('light', !dark);
  }, [dark]);
  return null;
}

function RequireAuth({ children }: { children: React.ReactNode }) {
  const { token } = useAuthStore();
  const location  = useLocation();
  if (!token) return <Navigate to="/login" state={{ from: location }} replace />;
  return <>{children}</>;
}

function Protected({ children }: { children: React.ReactNode }) {
  return (
    <RequireAuth>
      <AppShell>{children}</AppShell>
    </RequireAuth>
  );
}

export default function App() {
  return (
    <BrowserRouter>
      <ThemeBootstrap />
      <ToastContainer />
      <Routes>
        {/* Public */}
        <Route path="/login"           element={<LoginPage />} />
        <Route path="/register"        element={<RegisterPage />} />
        <Route path="/forgot-password"  element={<ForgotPasswordPage />} />
        <Route path="/reset-password"   element={<ResetPasswordPage />} />

        {/* Protected */}
        <Route path="/dashboard" element={<Protected><DashboardPage /></Protected>} />
        <Route path="/scans/new" element={<Protected><NewScanPage /></Protected>} />
        <Route path="/scans/:id" element={<Protected><ScanDetailPage /></Protected>} />
        <Route path="/scans"     element={<Protected><ScanHistoryPage /></Protected>} />
        <Route path="/findings"  element={<Protected><FindingsPage /></Protected>} />
        <Route path="/owasp"     element={<Protected><OWASPPage /></Protected>} />
        <Route path="/heatmap"   element={<Protected><HeatmapPage /></Protected>} />
        <Route path="/tools"     element={<Protected><ToolsPage /></Protected>} />
        <Route path="/reports"   element={<Protected><ReportsPage /></Protected>} />
        <Route path="/audit"     element={<Protected><AuditPage /></Protected>} />
        <Route path="/settings"  element={<Protected><SettingsPage /></Protected>} />
        <Route path="/scanners"  element={<Protected><ScannerPage /></Protected>} />

        <Route path="/" element={<Navigate to="/dashboard" replace />} />
        <Route path="*" element={<Navigate to="/dashboard" replace />} />
      </Routes>
    </BrowserRouter>
  );
}
