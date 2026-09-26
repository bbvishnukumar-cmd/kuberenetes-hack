import React from 'react';
import { NavLink } from 'react-router-dom';
import {
  ShieldAlert,
  LayoutDashboard,
  SearchCode,
  AlertTriangle,
  GitFork,
  Wrench,
  FileText,
  History,
  Server,
  Award,
  Settings,
  ShieldCheck,
} from 'lucide-react';

interface SidebarProps {
  isOpen: boolean;
  onClose?: () => void;
}

export const Sidebar: React.FC<SidebarProps> = ({ isOpen, onClose }) => {
  const mainNav = [
    { name: 'Overview', to: '/dashboard', icon: LayoutDashboard },
    { name: 'Security Scanner', to: '/scanner', icon: SearchCode },
    { name: 'Findings', to: '/findings', icon: AlertTriangle },
    { name: 'Attack Graph', to: '/attack-graph', icon: GitFork },
    { name: 'Remediation', to: '/remediation', icon: Wrench },
    { name: 'Reports', to: '/reports', icon: FileText },
    { name: 'Scan History', to: '/history', icon: History },
  ];

  const secondaryNav = [
    { name: 'Cluster', to: '/cluster', icon: Server },
    { name: 'Compliance', to: '/compliance', icon: Award },
    { name: 'Security Benchmark', to: '/history?tab=benchmark', icon: ShieldCheck },
    { name: 'Settings', to: '/settings', icon: Settings },
  ];

  return (
    <>
      {/* Mobile Backdrop */}
      {isOpen && (
        <div
          className="fixed inset-0 z-40 bg-black/70 backdrop-blur-xs lg:hidden"
          onClick={onClose}
        />
      )}

      <aside
        className={`fixed top-0 bottom-0 left-0 z-50 flex w-64 flex-col border-r border-[#263244] bg-[#070B14] transition-transform duration-200 lg:static lg:translate-x-0 ${
          isOpen ? 'translate-x-0' : '-translate-x-full'
        }`}
      >
        {/* Branding */}
        <div className="flex items-center gap-3 border-b border-[#263244] px-5 py-5">
          <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-[#00D4FF]/10 text-[#00D4FF] border border-[#00D4FF]/30 shadow-[0_0_15px_rgba(0,212,255,0.25)]">
            <ShieldAlert className="h-6 w-6" />
          </div>
          <div>
            <div className="flex items-center gap-1.5 font-bold tracking-wider text-[#F8FAFC]">
              <span>RBAC</span>
              <span className="text-[#00D4FF]">GUARDIAN</span>
            </div>
            <p className="text-[11px] font-medium uppercase tracking-widest text-[#94A3B8]">
              Kubernetes Security
            </p>
          </div>
        </div>

        {/* Navigation list */}
        <div className="flex flex-1 flex-col justify-between overflow-y-auto px-3 py-4">
          <div className="space-y-6">
            <div>
              <div className="px-3 pb-2 text-[10px] font-semibold uppercase tracking-wider text-[#64748B]">
                Core Modules
              </div>
              <nav className="space-y-1">
                {mainNav.map((item) => (
                  <NavLink
                    key={item.name}
                    to={item.to}
                    onClick={onClose}
                    className={({ isActive }) =>
                      `flex items-center gap-3 rounded-md px-3 py-2.5 text-sm font-medium transition-all ${
                        isActive
                          ? 'border border-[#00D4FF]/30 bg-[#00D4FF]/10 text-[#00D4FF] shadow-[0_0_12px_rgba(0,212,255,0.15)]'
                          : 'text-[#94A3B8] hover:border hover:border-[#263244] hover:bg-[#0D1320] hover:text-[#F8FAFC]'
                      }`
                    }
                  >
                    <item.icon className="h-4 w-4 shrink-0" />
                    <span>{item.name}</span>
                  </NavLink>
                ))}
              </nav>
            </div>

            <div className="border-t border-[#263244] pt-4">
              <div className="px-3 pb-2 text-[10px] font-semibold uppercase tracking-wider text-[#64748B]">
                Governance
              </div>
              <nav className="space-y-1">
                {secondaryNav.map((item) => (
                  <NavLink
                    key={item.name}
                    to={item.to}
                    onClick={onClose}
                    className={({ isActive }) =>
                      `flex items-center gap-3 rounded-md px-3 py-2 text-sm font-medium transition-all ${
                        isActive
                          ? 'border border-[#00D4FF]/30 bg-[#00D4FF]/10 text-[#00D4FF]'
                          : 'text-[#94A3B8] hover:border hover:border-[#263244] hover:bg-[#0D1320] hover:text-[#F8FAFC]'
                      }`
                    }
                  >
                    <item.icon className="h-4 w-4 shrink-0" />
                    <span>{item.name}</span>
                  </NavLink>
                ))}
              </nav>
            </div>
          </div>

          {/* Bottom System Status */}
          <div className="rounded-lg border border-[#263244] bg-[#0D1320] p-3">
            <div className="flex items-center justify-between text-xs text-[#94A3B8]">
              <span className="font-medium text-[#F8FAFC]">System Status</span>
              <span className="flex items-center gap-1.5 text-[11px] text-[#22C55E]">
                <span className="relative flex h-2 w-2">
                  <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-[#22C55E] opacity-75"></span>
                  <span className="relative inline-flex h-2 w-2 rounded-full bg-[#22C55E]"></span>
                </span>
                Online
              </span>
            </div>
            <div className="mt-2 text-[11px] text-[#64748B] flex items-center gap-1">
              <ShieldCheck className="h-3.5 w-3.5 text-[#00D4FF]" />
              <span>RBAC Engine v2.4.1</span>
            </div>
          </div>
        </div>
      </aside>
    </>
  );
};
