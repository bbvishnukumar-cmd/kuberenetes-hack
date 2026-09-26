import React from 'react';
import { Clock3, GitPullRequest, ShieldCheck } from 'lucide-react';
import type { DeploymentApproval } from '../types/deployment-approval';

const STATUS: Record<DeploymentApproval['approvalStatus'], { label: string; color: string }> = {
  unavailable: { label: 'No linked pull request', color: 'text-[#94A3B8]' },
  pending: { label: '🟡 Waiting for TL Approval', color: 'text-[#F59E0B]' },
  approved: { label: '🟢 Approved', color: 'text-[#22C55E]' },
  rejected: { label: '🔴 Rejected', color: 'text-[#EF4444]' },
  'security-blocked': { label: '⚫ Blocked by Security Gate', color: 'text-[#94A3B8]' },
  deploying: { label: '🔵 Deployment Running', color: 'text-[#38BDF8]' },
  completed: { label: '✅ Deployment Completed', color: 'text-[#22C55E]' },
};

export const DeploymentApprovalCard: React.FC<{ approval?: DeploymentApproval }> = ({ approval }) => {
  const state = approval ?? { approvalStatus: 'unavailable', securityGate: 'UNAVAILABLE' as const };
  const status = STATUS[state.approvalStatus];
  const details = [
    ['PR', state.pullRequestNumber ? `#${state.pullRequestNumber}${state.pullRequestTitle ? ` · ${state.pullRequestTitle}` : ''}` : 'Not linked'],
    ['Developer', state.developer ?? 'Unavailable'],
    ['Security Score', state.securityScore === undefined ? 'Unavailable' : `${state.securityScore}/100`],
    ['Rule Risk', state.ruleRisk ?? 'Unavailable'],
    ['ML Risk', state.mlRisk ?? 'Unavailable'],
    ['Security Gate', state.securityGate ?? 'UNAVAILABLE'],
    ['TL Approval', state.approvedBy ? `${state.approvedBy}${state.approvedAt ? ` · ${state.approvedAt}` : ''}` : state.approvalStatus === 'pending' ? 'Pending' : 'Unavailable'],
    ['Reminder Status', state.reminderCount === undefined ? 'Not active' : `Reminder #${state.reminderCount}`],
  ];

  return (
    <section className="rounded-xl border border-[#263244] bg-[#0D1320] p-4 shadow-xl">
      <div className="flex flex-col gap-3 border-b border-[#263244] pb-3 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h2 className="flex items-center gap-2 text-sm font-bold text-[#F8FAFC]">
            <ShieldCheck className="h-4 w-4 text-[#00D4FF]" /> Deployment Approval
          </h2>
          <p className="mt-1 text-xs text-[#94A3B8]">Read-only status from the protected GitHub deployment workflow.</p>
        </div>
        <span className={`text-xs font-bold ${status.color}`}>{status.label}</span>
      </div>
      <div className="mt-4 grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
        {details.map(([label, value]) => (
          <div key={label} className="rounded-lg border border-[#263244] bg-[#111827] p-3">
            <p className="text-[10px] font-semibold uppercase tracking-wider text-[#64748B]">{label}</p>
            <p className="mt-1 truncate text-xs font-semibold text-[#F8FAFC]">{value}</p>
          </div>
        ))}
      </div>
      {state.approvalStatus === 'pending' && <p className="mt-3 flex items-center gap-1.5 text-xs text-[#F59E0B]"><Clock3 className="h-3.5 w-3.5" /> GitHub Environment required reviewers control approval; this dashboard cannot approve or deploy.</p>}
      {state.pullRequestNumber && <p className="mt-2 flex items-center gap-1.5 text-xs text-[#94A3B8]"><GitPullRequest className="h-3.5 w-3.5" /> Deployment status is mirrored from GitHub Actions.</p>}
    </section>
  );
};
