import React from 'react';
import { Scan } from '../types/rbac';
import { Server, Shield, Globe, Users, Key, FileCode } from 'lucide-react';

interface ClusterPageProps {
  currentScan: Scan;
}

export const ClusterPage: React.FC<ClusterPageProps> = ({ currentScan }) => {
  const namespaces = [
    { name: 'payments', workloads: 2, status: 'Critical Risk', riskColor: 'text-[#EF4444] bg-[#EF4444]/10' },
    { name: 'development', workloads: 1, status: 'High Warning', riskColor: 'text-[#F59E0B] bg-[#F59E0B]/10' },
    { name: 'monitoring', workloads: 1, status: 'High Warning', riskColor: 'text-[#F59E0B] bg-[#F59E0B]/10' },
    { name: 'default', workloads: 1, status: 'Medium Warning', riskColor: 'text-[#38BDF8] bg-[#38BDF8]/10' },
  ];

  const serviceAccounts = [
    { name: 'payment-sa', namespace: 'payments', binding: 'payment-admin', role: 'cluster-admin', risk: 'CRITICAL' },
    { name: 'developer-sa', namespace: 'development', binding: 'dev-binding', role: 'dev-role (*)', risk: 'HIGH' },
    { name: 'monitoring-sa', namespace: 'default', binding: 'debugger-binding', role: 'pod-debugger-role', risk: 'HIGH' },
    { name: 'backup-sa', namespace: 'payments', binding: 'secret-reader-binding', role: 'secret-reader', risk: 'HIGH' },
    { name: 'default', namespace: 'default', binding: 'None (Unassigned)', role: 'Default Workload Identity', risk: 'MEDIUM' },
  ];

  return (
    <div className="space-y-6">
      <div className="border-b border-[#263244] pb-4">
        <h1 className="text-xl font-bold tracking-tight text-[#F8FAFC] sm:text-2xl flex items-center gap-2">
          <Server className="h-6 w-6 text-[#00D4FF]" />
          <span>Cluster Architecture & Identity Inventory</span>
        </h1>
        <p className="mt-1 text-xs text-[#94A3B8]">
          Topology, namespace segmentation, and service account authority mappings for{' '}
          <span className="font-semibold text-[#00D4FF]">{currentScan.cluster}</span>.
        </p>
      </div>

      {/* Cluster Overview Cards */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <div className="rounded-xl border border-[#263244] bg-[#0D1320] p-4 text-xs space-y-1">
          <span className="text-[#64748B] uppercase font-semibold text-[10px]">Cluster Identity</span>
          <p className="text-base font-bold text-[#F8FAFC]">{currentScan.cluster}</p>
          <span className="text-[#00D4FF] font-mono">Control Plane v1.30.2</span>
        </div>

        <div className="rounded-xl border border-[#263244] bg-[#0D1320] p-4 text-xs space-y-1">
          <span className="text-[#64748B] uppercase font-semibold text-[10px]">Active Namespaces</span>
          <p className="text-base font-bold text-[#F8FAFC]">{namespaces.length} Isolated Tenants</p>
          <span className="text-[#22C55E]">Multi-tenant Partitioned</span>
        </div>

        <div className="rounded-xl border border-[#263244] bg-[#0D1320] p-4 text-xs space-y-1">
          <span className="text-[#64748B] uppercase font-semibold text-[10px]">ServiceAccounts</span>
          <p className="text-base font-bold text-[#F8FAFC]">{serviceAccounts.length} Registered Identities</p>
          <span className="text-[#EF4444] font-medium">1 Superuser Binding</span>
        </div>

        <div className="rounded-xl border border-[#263244] bg-[#0D1320] p-4 text-xs space-y-1">
          <span className="text-[#64748B] uppercase font-semibold text-[10px]">RBAC Security Posture</span>
          <p className="text-base font-bold text-[#F8FAFC]">{currentScan.score} / 100</p>
          <span className="text-[#F59E0B]">Action Recommended</span>
        </div>
      </div>

      {/* Namespaces Grid */}
      <div className="rounded-xl border border-[#263244] bg-[#0D1320] p-5 space-y-4">
        <h3 className="text-xs font-bold uppercase tracking-wider text-[#F8FAFC] flex items-center gap-2 border-b border-[#263244] pb-2">
          <Globe className="h-4 w-4 text-[#00D4FF]" />
          <span>Namespace Boundaries</span>
        </h3>

        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
          {namespaces.map((ns) => (
            <div
              key={ns.name}
              className="rounded-lg border border-[#263244] bg-[#111827] p-3 text-xs space-y-2"
            >
              <div className="flex items-center justify-between">
                <span className="font-mono font-bold text-[#00D4FF]">{ns.name}</span>
                <span className={`rounded px-1.5 py-0.5 text-[9px] font-bold ${ns.riskColor}`}>
                  {ns.status}
                </span>
              </div>
              <p className="text-[#94A3B8]">{ns.workloads} Active Manifest Workloads</p>
            </div>
          ))}
        </div>
      </div>

      {/* ServiceAccount Inventory Table */}
      <div className="overflow-hidden rounded-xl border border-[#263244] bg-[#0D1320]">
        <div className="border-b border-[#263244] p-4">
          <h3 className="text-xs font-bold uppercase tracking-wider text-[#F8FAFC] flex items-center gap-2">
            <Users className="h-4 w-4 text-[#7C3AED]" />
            <span>ServiceAccount Identity Privilege Mapping</span>
          </h3>
        </div>

        <table className="w-full text-left text-xs">
          <thead className="border-b border-[#263244] bg-[#070B14] uppercase text-[#64748B] font-semibold tracking-wider">
            <tr>
              <th className="px-4 py-3">ServiceAccount</th>
              <th className="px-4 py-3">Namespace</th>
              <th className="px-4 py-3">Binding</th>
              <th className="px-4 py-3">Referenced Role</th>
              <th className="px-4 py-3">Privilege Risk</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[#263244]">
            {serviceAccounts.map((sa) => (
              <tr key={sa.name} className="hover:bg-[#111827]">
                <td className="px-4 py-3 font-mono font-bold text-[#F8FAFC]">
                  {sa.name}
                </td>
                <td className="px-4 py-3 font-mono text-[#38BDF8]">
                  {sa.namespace}
                </td>
                <td className="px-4 py-3 font-mono text-[#94A3B8]">
                  {sa.binding}
                </td>
                <td className="px-4 py-3 font-mono font-medium text-[#F8FAFC]">
                  {sa.role}
                </td>
                <td className="px-4 py-3">
                  <span
                    className={`rounded px-2 py-0.5 text-[10px] font-bold ${
                      sa.risk === 'CRITICAL'
                        ? 'bg-[#EF4444]/20 text-[#EF4444]'
                        : sa.risk === 'HIGH'
                        ? 'bg-[#F59E0B]/20 text-[#F59E0B]'
                        : 'bg-[#38BDF8]/20 text-[#38BDF8]'
                    }`}
                  >
                    {sa.risk}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};
