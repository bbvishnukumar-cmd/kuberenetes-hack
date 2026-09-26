import React from 'react';
import { Menu, Search, Bell, Server, Clock, PlusCircle } from 'lucide-react';
import { useNavigate } from 'react-router-dom';

interface TopbarProps {
  onToggleSidebar: () => void;
  onOpenCommandPalette: () => void;
  clusterName?: string;
  k8sVersion?: string;
  lastScanTime?: string;
}

export const Topbar: React.FC<TopbarProps> = ({
  onToggleSidebar,
  onOpenCommandPalette,
  clusterName = 'production-demo',
  k8sVersion = 'v1.30.2',
  lastScanTime = 'Today, 09:42 PM',
}) => {
  const navigate = useNavigate();

  return (
    <header className="sticky top-0 z-30 flex h-16 w-full items-center justify-between border-b border-[#263244] bg-[#070B14]/90 px-4 backdrop-blur-md lg:px-6">
      <div className="flex items-center gap-4">
        {/* Mobile menu trigger */}
        <button
          onClick={onToggleSidebar}
          aria-label="Toggle Navigation"
          className="rounded-md border border-[#263244] p-2 text-[#94A3B8] hover:border-[#00D4FF]/40 hover:text-[#F8FAFC] lg:hidden"
        >
          <Menu className="h-5 w-5" />
        </button>

        {/* Cluster information pills */}
        <div className="flex flex-wrap items-center gap-2">
          <div className="flex items-center gap-2 rounded-md border border-[#263244] bg-[#0D1320] px-2.5 py-1 text-xs">
            <Server className="h-3.5 w-3.5 text-[#00D4FF]" />
            <span className="text-[#94A3B8]">Cluster:</span>
            <span className="font-semibold text-[#F8FAFC]">{clusterName}</span>
          </div>

          <div className="hidden sm:flex items-center gap-1.5 rounded-md border border-[#263244] bg-[#0D1320] px-2.5 py-1 text-xs font-mono text-[#94A3B8]">
            <span className="text-[#64748B]">K8s</span>
            <span className="text-[#00D4FF] font-medium">{k8sVersion}</span>
          </div>

          <div className="hidden md:flex items-center gap-1.5 rounded-md border border-[#263244] bg-[#0D1320] px-2.5 py-1 text-xs text-[#94A3B8]">
            <Clock className="h-3 w-3 text-[#94A3B8]" />
            <span>Last Scan:</span>
            <span className="font-medium text-[#F8FAFC]">{lastScanTime}</span>
          </div>
        </div>
      </div>

      {/* Right Actions */}
      <div className="flex items-center gap-3">
        {/* Command palette search bar */}
        <button
          onClick={onOpenCommandPalette}
          className="flex items-center gap-3 rounded-md border border-[#263244] bg-[#0D1320] px-3 py-1.5 text-xs text-[#94A3B8] transition-colors hover:border-[#00D4FF]/50 hover:text-[#F8FAFC]"
        >
          <Search className="h-3.5 w-3.5 text-[#00D4FF]" />
          <span className="hidden sm:inline">Search rules, findings...</span>
          <kbd className="hidden rounded bg-[#111827] px-1.5 py-0.5 text-[10px] font-mono text-[#64748B] sm:inline border border-[#263244]">
            Ctrl K
          </kbd>
        </button>

        {/* Quick New Scan button */}
        <button
          onClick={() => navigate('/scanner')}
          className="flex items-center gap-1.5 rounded-md bg-[#00D4FF] px-3 py-1.5 text-xs font-semibold text-[#070B14] transition-all hover:bg-[#00D4FF]/90 hover:shadow-[0_0_15px_rgba(0,212,255,0.4)]"
        >
          <PlusCircle className="h-3.5 w-3.5" />
          <span className="hidden sm:inline">New Security Scan</span>
          <span className="sm:hidden">Scan</span>
        </button>

        {/* Notifications */}
        <div className="relative">
          <button
            aria-label="View notifications"
            className="relative rounded-md border border-[#263244] bg-[#0D1320] p-2 text-[#94A3B8] hover:border-[#00D4FF]/40 hover:text-[#F8FAFC]"
          >
            <Bell className="h-4 w-4" />
            <span className="absolute top-1.5 right-1.5 h-2 w-2 rounded-full bg-[#EF4444] animate-pulse"></span>
          </button>
        </div>

        {/* User profile */}
        <div className="flex items-center gap-2 border-l border-[#263244] pl-3">
          <div className="flex h-8 w-8 items-center justify-center rounded-full bg-gradient-to-tr from-[#7C3AED] to-[#00D4FF] text-xs font-bold text-white shadow-xs">
            SOC
          </div>
          <div className="hidden lg:block text-left text-xs">
            <div className="font-semibold text-[#F8FAFC]">Security Officer</div>
            <div className="text-[10px] text-[#64748B]">Cluster Admin</div>
          </div>
        </div>
      </div>
    </header>
  );
};
