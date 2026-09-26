import React from 'react';
import { ResourceCounts } from '../types/rbac';
import { Box, Layers, UserCheck, Key, Shield, FileCode, Lock, Globe } from 'lucide-react';

interface ResourceSummaryProps {
  counts: ResourceCounts;
}

export const ResourceSummary: React.FC<ResourceSummaryProps> = ({ counts }) => {
  const items = [
    { label: 'Pods', count: counts.pods, icon: Box, color: 'text-[#38BDF8]' },
    { label: 'Deployments', count: counts.deployments, icon: Layers, color: 'text-[#00D4FF]' },
    { label: 'ServiceAccounts', count: counts.serviceAccounts, icon: UserCheck, color: 'text-[#7C3AED]' },
    { label: 'Roles', count: counts.roles, icon: Key, color: 'text-[#F59E0B]' },
    { label: 'ClusterRoles', count: counts.clusterRoles, icon: Shield, color: 'text-[#EF4444]' },
    { label: 'RoleBindings', count: counts.roleBindings, icon: FileCode, color: 'text-[#F59E0B]' },
    { label: 'ClusterRoleBindings', count: counts.clusterRoleBindings, icon: Shield, color: 'text-[#EF4444]' },
    { label: 'Secrets', count: counts.secrets, icon: Lock, color: 'text-[#EC4899]' },
    { label: 'Namespaces', count: counts.namespaces, icon: Globe, color: 'text-[#22C55E]' },
  ];

  return (
    <div className="rounded-lg border border-[#263244] bg-[#0D1320] p-4">
      <div className="flex items-center justify-between border-b border-[#263244] pb-2.5 mb-3">
        <h3 className="text-xs font-bold uppercase tracking-wider text-[#F8FAFC]">
          Parsed Kubernetes Resources ({counts.total} objects)
        </h3>
        <span className="text-[11px] font-mono text-[#00D4FF]">Live Normalized Index</span>
      </div>

      <div className="grid grid-cols-3 gap-2.5 sm:grid-cols-4 md:grid-cols-5 lg:grid-cols-9">
        {items.map((item) => (
          <div
            key={item.label}
            className="flex flex-col items-center justify-center rounded-md border border-[#263244] bg-[#111827] p-2 text-center"
          >
            <item.icon className={`h-4 w-4 ${item.color} mb-1`} />
            <span className="text-[10px] text-[#94A3B8] truncate w-full">{item.label}</span>
            <span className="text-sm font-bold text-[#F8FAFC]">{item.count}</span>
          </div>
        ))}
      </div>
    </div>
  );
};
