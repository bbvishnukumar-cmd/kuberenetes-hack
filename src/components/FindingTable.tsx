import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Finding, Severity } from '../types/rbac';
import { FindingBadge } from './SeverityCard';
import { Search, ChevronRight, CheckCircle2, AlertOctagon, Filter } from 'lucide-react';

interface FindingTableProps {
  findings: Finding[];
  title?: string;
  limit?: number;
  showFilters?: boolean;
}

export const FindingTable: React.FC<FindingTableProps> = ({
  findings,
  title = 'Recent Findings',
  limit,
  showFilters = true,
}) => {
  const navigate = useNavigate();
  const [selectedFilter, setSelectedFilter] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState('');

  const filtered = findings.filter((f) => {
    // Severity filter
    if (selectedFilter !== 'ALL') {
      if (selectedFilter === 'RESOLVED') {
        if (f.status !== 'Resolved') return false;
      } else if (f.severity !== selectedFilter) {
        return false;
      }
    }

    // Text search
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      const match =
        f.ruleId.toLowerCase().includes(q) ||
        f.title.toLowerCase().includes(q) ||
        f.resourceName.toLowerCase().includes(q) ||
        f.namespace.toLowerCase().includes(q);
      if (!match) return false;
    }

    return true;
  });

  const displayList = limit ? filtered.slice(0, limit) : filtered;

  return (
    <div className="rounded-xl border border-[#263244] bg-[#0D1320] overflow-hidden">
      {/* Header bar */}
      <div className="flex flex-col gap-3 border-b border-[#263244] p-4 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex items-center gap-2">
          <AlertOctagon className="h-5 w-5 text-[#00D4FF]" />
          <div>
            <h3 className="font-bold text-sm text-[#F8FAFC]">{title}</h3>
            <p className="text-xs text-[#94A3B8]">
              {filtered.length} security misconfiguration(s) flagged
            </p>
          </div>
        </div>

        {/* Search & Filter pills */}
        <div className="flex flex-wrap items-center gap-2">
          <div className="relative">
            <Search className="absolute left-2.5 top-2.5 h-3.5 w-3.5 text-[#64748B]" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Filter findings..."
              className="h-8 rounded-md border border-[#263244] bg-[#111827] pl-8 pr-3 text-xs text-[#F8FAFC] placeholder-[#64748B] outline-none focus:border-[#00D4FF]"
            />
          </div>

          {showFilters && (
            <div className="flex items-center rounded-md border border-[#263244] bg-[#111827] p-0.5 text-xs">
              {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'RESOLVED'].map((lvl) => (
                <button
                  key={lvl}
                  onClick={() => setSelectedFilter(lvl)}
                  className={`rounded px-2.5 py-1 text-[11px] font-medium transition-colors ${
                    selectedFilter === lvl
                      ? 'bg-[#00D4FF]/20 text-[#00D4FF]'
                      : 'text-[#94A3B8] hover:text-[#F8FAFC]'
                  }`}
                >
                  {lvl}
                </button>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Table */}
      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs">
          <thead className="border-b border-[#263244] bg-[#070B14] uppercase text-[#64748B] font-semibold tracking-wider">
            <tr>
              <th className="px-4 py-3">Severity</th>
              <th className="px-4 py-3">Rule ID</th>
              <th className="px-4 py-3">Finding</th>
              <th className="px-4 py-3">Resource</th>
              <th className="px-4 py-3">Namespace</th>
              <th className="px-4 py-3">Status</th>
              <th className="px-4 py-3">Detected</th>
              <th className="px-4 py-3 text-right">Action</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[#263244]">
            {displayList.length === 0 ? (
              <tr>
                <td colSpan={8} className="p-8 text-center text-[#94A3B8]">
                  <p className="font-medium text-sm">No security issues detected matching criteria.</p>
                  <p className="text-xs text-[#64748B] mt-1">
                    Configuration passed all enabled RBAC Guardian checks.
                  </p>
                </td>
              </tr>
            ) : (
              displayList.map((finding) => (
                <tr
                  key={finding.id}
                  onClick={() => navigate(`/findings/${finding.id}`)}
                  className="group cursor-pointer hover:bg-[#111827] transition-colors"
                >
                  <td className="px-4 py-3 whitespace-nowrap">
                    <FindingBadge severity={finding.severity} />
                  </td>
                  <td className="px-4 py-3 whitespace-nowrap font-mono font-bold text-[#00D4FF]">
                    {finding.ruleId}
                  </td>
                  <td className="px-4 py-3 font-medium text-[#F8FAFC] max-w-xs truncate group-hover:text-[#00D4FF] transition-colors">
                    {finding.title}
                  </td>
                  <td className="px-4 py-3 whitespace-nowrap font-mono text-[#94A3B8]">
                    <span className="text-[#64748B]">{finding.resourceKind}/</span>
                    <span className="text-[#F8FAFC]">{finding.resourceName}</span>
                  </td>
                  <td className="px-4 py-3 whitespace-nowrap font-mono text-[#38BDF8]">
                    {finding.namespace}
                  </td>
                  <td className="px-4 py-3 whitespace-nowrap">
                    {finding.status === 'Resolved' ? (
                      <span className="inline-flex items-center gap-1 text-[11px] font-bold text-[#22C55E]">
                        <CheckCircle2 className="h-3.5 w-3.5" />
                        Resolved
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1 text-[11px] font-bold text-[#EF4444]">
                        <span className="h-1.5 w-1.5 rounded-full bg-[#EF4444] animate-pulse"></span>
                        Open
                      </span>
                    )}
                  </td>
                  <td className="px-4 py-3 whitespace-nowrap text-[#64748B]">
                    {new Date(finding.createdAt).toLocaleDateString('en-US', {
                      month: 'short',
                      day: 'numeric',
                    })}
                  </td>
                  <td className="px-4 py-3 whitespace-nowrap text-right text-[#64748B] group-hover:text-[#00D4FF]">
                    <ChevronRight className="h-4 w-4 inline-block transform group-hover:translate-x-0.5 transition-transform" />
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};
