import React from 'react';
import { Scan } from '../types/rbac';
import { FindingTable } from '../components/FindingTable';
import { AlertTriangle, ShieldCheck } from 'lucide-react';

interface FindingsListProps {
  currentScan: Scan;
}

export const FindingsList: React.FC<FindingsListProps> = ({ currentScan }) => {
  return (
    <div className="space-y-6">
      {/* Page Title */}
      <div className="border-b border-[#263244] pb-4">
        <h1 className="text-xl font-bold tracking-tight text-[#F8FAFC] sm:text-2xl flex items-center gap-2">
          <AlertTriangle className="h-6 w-6 text-[#EF4444]" />
          <span>RBAC Security Findings</span>
        </h1>
        <p className="mt-1 text-xs text-[#94A3B8]">
          Comprehensive misconfiguration inventory detected across cluster{' '}
          <span className="text-[#00D4FF] font-semibold">{currentScan.cluster}</span>.
        </p>
      </div>

      {/* Main Finding Table with Full Filters */}
      <FindingTable
        findings={currentScan.findings}
        title="All Detected Misconfigurations"
        showFilters={true}
      />
    </div>
  );
};
