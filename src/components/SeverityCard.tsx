import React from 'react';
import { ShieldAlert, AlertTriangle, AlertCircle, Info, CheckCircle2 } from 'lucide-react';
import { Severity } from '../types/rbac';

interface SeverityCardProps {
  severity: Severity;
  count: number;
  label?: string;
  onClick?: () => void;
  active?: boolean;
}

export const SeverityCard: React.FC<SeverityCardProps> = ({
  severity,
  count,
  label,
  onClick,
  active = false,
}) => {
  const configs = {
    CRITICAL: {
      title: label || 'Critical',
      icon: ShieldAlert,
      textColor: 'text-[#EF4444]',
      bgColor: 'bg-[#EF4444]/10',
      borderColor: 'border-[#EF4444]/30',
      activeRing: 'ring-2 ring-[#EF4444]',
    },
    HIGH: {
      title: label || 'High',
      icon: AlertTriangle,
      textColor: 'text-[#F59E0B]',
      bgColor: 'bg-[#F59E0B]/10',
      borderColor: 'border-[#F59E0B]/30',
      activeRing: 'ring-2 ring-[#F59E0B]',
    },
    MEDIUM: {
      title: label || 'Medium',
      icon: AlertCircle,
      textColor: 'text-[#38BDF8]',
      bgColor: 'bg-[#38BDF8]/10',
      borderColor: 'border-[#38BDF8]/30',
      activeRing: 'ring-2 ring-[#38BDF8]',
    },
    LOW: {
      title: label || 'Low',
      icon: Info,
      textColor: 'text-[#94A3B8]',
      bgColor: 'bg-[#94A3B8]/10',
      borderColor: 'border-[#94A3B8]/30',
      activeRing: 'ring-2 ring-[#94A3B8]',
    },
    PASSED: {
      title: label || 'Passed',
      icon: CheckCircle2,
      textColor: 'text-[#22C55E]',
      bgColor: 'bg-[#22C55E]/10',
      borderColor: 'border-[#22C55E]/30',
      activeRing: 'ring-2 ring-[#22C55E]',
    },
  };

  const config = configs[severity];
  const IconComponent = config.icon;

  return (
    <button
      onClick={onClick}
      className={`flex flex-1 min-w-[130px] flex-col rounded-lg border bg-[#111827] p-3 text-left transition-all hover:border-[#00D4FF]/40 ${
        config.borderColor
      } ${active ? config.activeRing : ''}`}
    >
      <div className="flex items-center justify-between">
        <span className="text-xs font-semibold uppercase tracking-wider text-[#94A3B8]">
          {config.title}
        </span>
        <div className={`rounded-md p-1.5 ${config.bgColor} ${config.textColor}`}>
          <IconComponent className="h-4 w-4" />
        </div>
      </div>
      <div className="mt-2 flex items-baseline gap-2">
        <span className={`text-2xl font-black ${config.textColor}`}>
          {count}
        </span>
      </div>
    </button>
  );
};

export const FindingBadge: React.FC<{ severity: Severity; text?: string }> = ({
  severity,
  text,
}) => {
  const styles: Record<Severity, string> = {
    CRITICAL: 'text-[#EF4444] bg-[#EF4444]/10 border-[#EF4444]/30',
    HIGH: 'text-[#F59E0B] bg-[#F59E0B]/10 border-[#F59E0B]/30',
    MEDIUM: 'text-[#38BDF8] bg-[#38BDF8]/10 border-[#38BDF8]/30',
    LOW: 'text-[#94A3B8] bg-[#94A3B8]/10 border-[#94A3B8]/30',
    PASSED: 'text-[#22C55E] bg-[#22C55E]/10 border-[#22C55E]/30',
  };

  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded border px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider ${
        styles[severity] || styles.LOW
      }`}
    >
      <span className="h-1.5 w-1.5 rounded-full bg-current"></span>
      {text || severity}
    </span>
  );
};
