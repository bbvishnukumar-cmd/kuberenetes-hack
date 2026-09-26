import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Search,
  LayoutDashboard,
  SearchCode,
  AlertTriangle,
  GitFork,
  Wrench,
  FileText,
  History,
  Award,
  Settings,
  ShieldAlert,
  X,
  ArrowRight,
  Download,
} from 'lucide-react';

interface CommandPaletteProps {
  isOpen: boolean;
  onClose: () => void;
  onExportReport?: () => void;
}

export const CommandPalette: React.FC<CommandPaletteProps> = ({
  isOpen,
  onClose,
  onExportReport,
}) => {
  const navigate = useNavigate();
  const [query, setQuery] = useState('');
  const [selectedIndex, setSelectedIndex] = useState(0);

  const commands = [
    { id: 'dashboard', label: 'Go to Dashboard', icon: LayoutDashboard, path: '/dashboard', category: 'Navigation' },
    { id: 'scanner', label: 'Open Security Scanner', icon: SearchCode, path: '/scanner', category: 'Navigation' },
    { id: 'findings', label: 'View Security Findings', icon: AlertTriangle, path: '/findings', category: 'Navigation' },
    { id: 'attack-graph', label: 'Open Attack Graph', icon: GitFork, path: '/attack-graph', category: 'Navigation' },
    { id: 'remediation', label: 'Open AI Remediation', icon: Wrench, path: '/remediation', category: 'Navigation' },
    { id: 'reports', label: 'View Reports & PDF Export', icon: FileText, path: '/reports', category: 'Navigation' },
    { id: 'history', label: 'View Scan History', icon: History, path: '/history', category: 'Navigation' },
    { id: 'benchmark', label: 'View Security Benchmark & Threat Events', icon: ShieldAlert, path: '/history?tab=benchmark', category: 'Navigation' },
    { id: 'compliance', label: 'View CIS & MITRE Compliance', icon: Award, path: '/compliance', category: 'Navigation' },
    { id: 'settings', label: 'Open Settings', icon: Settings, path: '/settings', category: 'Navigation' },
    {
      id: 'scan-now',
      label: 'Scan New Kubernetes YAML',
      icon: SearchCode,
      action: () => navigate('/scanner'),
      category: 'Actions',
    },
    {
      id: 'export-report',
      label: 'Export Security Report',
      icon: Download,
      action: () => {
        if (onExportReport) onExportReport();
        else navigate('/reports');
      },
      category: 'Actions',
    },
  ];

  const filtered = commands.filter((c) =>
    c.label.toLowerCase().includes(query.toLowerCase()) ||
    c.category.toLowerCase().includes(query.toLowerCase())
  );

  useEffect(() => {
    setSelectedIndex(0);
  }, [query]);

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        if (isOpen) onClose();
        else {
          // handled in parent or global
        }
      }

      if (!isOpen) return;

      if (e.key === 'Escape') {
        onClose();
      } else if (e.key === 'ArrowDown') {
        e.preventDefault();
        setSelectedIndex((prev) => (prev + 1) % (filtered.length || 1));
      } else if (e.key === 'ArrowUp') {
        e.preventDefault();
        setSelectedIndex((prev) => (prev - 1 + filtered.length) % (filtered.length || 1));
      } else if (e.key === 'Enter') {
        e.preventDefault();
        if (filtered[selectedIndex]) {
          executeCommand(filtered[selectedIndex]);
        }
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, filtered, selectedIndex]);

  const executeCommand = (cmd: (typeof commands)[0]) => {
    onClose();
    if (cmd.action) {
      cmd.action();
    } else if (cmd.path) {
      navigate(cmd.path);
    }
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center pt-20 px-4 bg-black/75 backdrop-blur-xs">
      <div className="w-full max-w-xl overflow-hidden rounded-xl border border-[#263244] bg-[#0D1320] shadow-2xl">
        {/* Search Input */}
        <div className="flex items-center gap-3 border-b border-[#263244] px-4 py-3 bg-[#070B14]">
          <Search className="h-5 w-5 text-[#00D4FF]" />
          <input
            type="text"
            autoFocus
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Type a command or search (e.g. Scanner, Findings, Attack Graph)..."
            className="flex-1 bg-transparent text-sm text-[#F8FAFC] placeholder-[#64748B] outline-none"
          />
          <button
            onClick={onClose}
            className="rounded p-1 text-[#94A3B8] hover:bg-[#263244] hover:text-[#F8FAFC]"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        {/* Command List */}
        <div className="max-h-80 overflow-y-auto p-2">
          {filtered.length === 0 ? (
            <div className="p-4 text-center text-sm text-[#94A3B8]">
              No commands matching &ldquo;{query}&rdquo;
            </div>
          ) : (
            filtered.map((cmd, idx) => (
              <button
                key={cmd.id}
                onClick={() => executeCommand(cmd)}
                onMouseEnter={() => setSelectedIndex(idx)}
                className={`flex w-full items-center justify-between rounded-lg px-3 py-2.5 text-sm transition-colors ${
                  idx === selectedIndex
                    ? 'border border-[#00D4FF]/30 bg-[#00D4FF]/10 text-[#00D4FF]'
                    : 'text-[#94A3B8] hover:bg-[#111827] hover:text-[#F8FAFC]'
                }`}
              >
                <div className="flex items-center gap-3">
                  <cmd.icon className="h-4 w-4" />
                  <span className="font-medium">{cmd.label}</span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-[10px] uppercase tracking-wider text-[#64748B]">
                    {cmd.category}
                  </span>
                  <ArrowRight className="h-3 w-3 opacity-60" />
                </div>
              </button>
            ))
          )}
        </div>

        {/* Footer shortcuts */}
        <div className="flex items-center justify-between border-t border-[#263244] bg-[#070B14] px-4 py-2 text-[11px] text-[#64748B]">
          <div className="flex items-center gap-3">
            <span>
              <kbd className="rounded border border-[#263244] bg-[#111827] px-1 py-0.5">↑↓</kbd> Navigate
            </span>
            <span>
              <kbd className="rounded border border-[#263244] bg-[#111827] px-1 py-0.5">Enter</kbd> Select
            </span>
            <span>
              <kbd className="rounded border border-[#263244] bg-[#111827] px-1 py-0.5">Esc</kbd> Close
            </span>
          </div>
          <span className="font-mono text-[10px] text-[#00D4FF]">RBAC GUARDIAN v1.0</span>
        </div>
      </div>
    </div>
  );
};
