import React, { useState, useEffect } from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { Sidebar } from './components/Sidebar';
import { Topbar } from './components/Topbar';
import { CommandPalette } from './components/CommandPalette';
import { Dashboard } from './pages/Dashboard';
import { Scanner } from './pages/Scanner';
import { FindingsList } from './pages/FindingsList';
import { FindingDetail } from './pages/FindingDetail';
import { AttackGraphPage } from './pages/AttackGraphPage';
import { RemediationPage } from './pages/RemediationPage';
import { ReportsPage } from './pages/ReportsPage';
import { ScanHistoryPage } from './pages/ScanHistoryPage';
import { ClusterPage } from './pages/ClusterPage';
import { CompliancePage } from './pages/CompliancePage';
import { SettingsPage } from './pages/SettingsPage';
import { INITIAL_DEMO_SCAN } from './services/demo-data';
import { Scan } from './types/rbac';

export default function App() {
  const [currentScan, setCurrentScan] = useState<Scan>(() => {
    return JSON.parse(JSON.stringify(INITIAL_DEMO_SCAN));
  });

  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [commandPaletteOpen, setCommandPaletteOpen] = useState(false);

  // Global Ctrl+K / Cmd+K listener
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        setCommandPaletteOpen((prev) => !prev);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  const handleScanComplete = (newScan: Scan) => {
    setCurrentScan(newScan);
  };

  const handleRescanComplete = (updatedScan: Scan) => {
    setCurrentScan(updatedScan);
  };

  return (
    <BrowserRouter>
      <div className="flex min-h-screen bg-[#070B14] text-[#F8FAFC]">
        {/* Navigation Sidebar */}
        <Sidebar
          isOpen={sidebarOpen}
          onClose={() => setSidebarOpen(false)}
        />

        {/* Main Application Area */}
        <div className="flex flex-1 flex-col overflow-hidden bg-grid-cyber bg-radial-glow">
          {/* Topbar */}
          <Topbar
            onToggleSidebar={() => setSidebarOpen((prev) => !prev)}
            onOpenCommandPalette={() => setCommandPaletteOpen(true)}
            clusterName={currentScan.cluster}
            k8sVersion={currentScan.k8sVersion}
            lastScanTime={currentScan.timestamp}
          />

          {/* Page View Container */}
          <main className="flex-1 overflow-y-auto p-4 lg:p-8">
            <div className="mx-auto max-w-7xl">
              <Routes>
                <Route path="/" element={<Dashboard currentScan={currentScan} />} />
                <Route path="/dashboard" element={<Dashboard currentScan={currentScan} />} />
                <Route
                  path="/scanner"
                  element={
                    <Scanner
                      currentScan={currentScan}
                      onScanComplete={handleScanComplete}
                    />
                  }
                />
                <Route path="/findings" element={<FindingsList currentScan={currentScan} />} />
                <Route
                  path="/findings/:id"
                  element={<FindingDetail currentScan={currentScan} />}
                />
                <Route
                  path="/attack-graph"
                  element={<AttackGraphPage currentScan={currentScan} />}
                />
                <Route
                  path="/remediation"
                  element={
                    <RemediationPage
                      currentScan={currentScan}
                      onRescanComplete={handleRescanComplete}
                    />
                  }
                />
                <Route path="/reports" element={<ReportsPage currentScan={currentScan} />} />
                <Route path="/history" element={<ScanHistoryPage />} />
                <Route path="/cluster" element={<ClusterPage currentScan={currentScan} />} />
                <Route path="/compliance" element={<CompliancePage />} />
                <Route path="/settings" element={<SettingsPage />} />
                <Route path="*" element={<Navigate to="/dashboard" replace />} />
              </Routes>
            </div>
          </main>
        </div>

        {/* Global Command Palette */}
        <CommandPalette
          isOpen={commandPaletteOpen}
          onClose={() => setCommandPaletteOpen(false)}
        />
      </div>
    </BrowserRouter>
  );
}
