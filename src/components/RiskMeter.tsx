import React from 'react';
import { BlastRadius } from '../types/rbac';
import { Flame, Shield, Target, Zap } from 'lucide-react';

interface RiskMeterProps {
  blastRadius: BlastRadius;
}

export const RiskMeter: React.FC<RiskMeterProps> = ({ blastRadius }) => {
  const metrics = [
    {
      label: 'Resource Sensitivity',
      value: blastRadius.resourceSensitivity,
      icon: Target,
      desc: 'Criticality of exposed assets (Secrets, Control Plane, Nodes)',
    },
    {
      label: 'Permission Scope',
      value: blastRadius.permissionScope,
      icon: Zap,
      desc: 'Breadth of granted verbs and resources (Wildcards, Superuser)',
    },
    {
      label: 'Namespace Criticality',
      value: blastRadius.namespaceCriticality,
      icon: Shield,
      desc: 'Impact on production, system namespaces, or cluster-wide scope',
    },
    {
      label: 'Privilege Escalation Potential',
      value: blastRadius.privilegeEscalation,
      icon: Flame,
      desc: 'Likelihood of escalating from workload shell to root admin',
    },
  ];

  const getMeterColor = (val: number) => {
    if (val >= 80) return 'bg-[#EF4444] shadow-[0_0_8px_rgba(239,68,68,0.5)]';
    if (val >= 60) return 'bg-[#F59E0B] shadow-[0_0_8px_rgba(245,158,11,0.5)]';
    if (val >= 40) return 'bg-[#38BDF8]';
    return 'bg-[#22C55E]';
  };

  return (
    <div className="space-y-4 rounded-lg border border-[#263244] bg-[#0D1320] p-4">
      <div className="flex items-center justify-between border-b border-[#263244] pb-3">
        <div className="flex items-center gap-2">
          <Flame className="h-5 w-5 text-[#EF4444]" />
          <div>
            <h4 className="text-sm font-bold text-[#F8FAFC]">Blast Radius & Impact Analysis</h4>
            <p className="text-xs text-[#94A3B8]">Multidimensional risk measurement</p>
          </div>
        </div>
        <div className="text-right">
          <span className="text-xs font-semibold text-[#94A3B8]">Overall Impact:</span>
          <span className="ml-2 font-mono text-base font-black text-[#EF4444]">
            {blastRadius.overallScore}%
          </span>
        </div>
      </div>

      <div className="space-y-3">
        {metrics.map((m) => (
          <div key={m.label} className="space-y-1">
            <div className="flex items-center justify-between text-xs">
              <span className="flex items-center gap-1.5 font-medium text-[#F8FAFC]">
                <m.icon className="h-3.5 w-3.5 text-[#00D4FF]" />
                {m.label}
              </span>
              <span className="font-mono font-bold text-[#94A3B8]">{m.value}%</span>
            </div>
            {/* Progress bar */}
            <div className="h-2 w-full overflow-hidden rounded-full bg-[#111827]">
              <div
                className={`h-full rounded-full transition-all duration-500 ${getMeterColor(m.value)}`}
                style={{ width: `${m.value}%` }}
              />
            </div>
            <p className="text-[11px] text-[#64748B]">{m.desc}</p>
          </div>
        ))}
      </div>
    </div>
  );
};
