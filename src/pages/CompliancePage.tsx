import React, { useState } from 'react';
import { COMPLIANCE_CONTROLS } from '../services/demo-data';
import { Award, ShieldAlert, CheckCircle2, AlertTriangle, ExternalLink } from 'lucide-react';

export const CompliancePage: React.FC = () => {
  const [selectedFramework, setSelectedFramework] = useState<string>('ALL');

  const frameworks = [
    'ALL',
    'CIS Kubernetes Benchmark',
    'MITRE ATT&CK for Containers',
    'NSA/CISA Kubernetes Hardening',
  ];

  const filteredControls = COMPLIANCE_CONTROLS.filter((c) =>
    selectedFramework === 'ALL' ? true : c.framework === selectedFramework
  );

  return (
    <div className="space-y-6">
      {/* Title */}
      <div className="border-b border-[#263244] pb-4">
        <h1 className="text-xl font-bold tracking-tight text-[#F8FAFC] sm:text-2xl flex items-center gap-2">
          <Award className="h-6 w-6 text-[#00D4FF]" />
          <span>Security & Compliance Framework Mappings</span>
        </h1>
        <p className="mt-1 text-xs text-[#94A3B8]">
          Informational posture mapping against industry baseline recommendations.
        </p>
      </div>

      {/* Compliance Disclaimer Notice */}
      <div className="rounded-xl border border-[#00D4FF]/30 bg-[#00D4FF]/5 p-4 text-xs text-[#94A3B8] flex items-start gap-3">
        <ShieldAlert className="h-5 w-5 text-[#00D4FF] shrink-0 mt-0.5" />
        <div className="space-y-1">
          <span className="font-bold text-[#F8FAFC]">Regulatory & Certification Scope Notice</span>
          <p className="leading-relaxed">
            Scanning provides automated informational security posture indicators based on public benchmark standards.
            A successful scan does not certify formal third-party regulatory compliance or replace official audits.
          </p>
        </div>
      </div>

      {/* Framework Tabs */}
      <div className="flex flex-wrap gap-2 border-b border-[#263244] pb-2">
        {frameworks.map((fw) => (
          <button
            key={fw}
            onClick={() => setSelectedFramework(fw)}
            className={`rounded-lg px-3.5 py-1.5 text-xs font-semibold transition-all ${
              selectedFramework === fw
                ? 'bg-[#00D4FF] text-[#070B14] shadow-[0_0_12px_rgba(0,212,255,0.3)]'
                : 'bg-[#111827] text-[#94A3B8] hover:text-[#F8FAFC]'
            }`}
          >
            {fw}
          </button>
        ))}
      </div>

      {/* Controls Grid */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {filteredControls.map((control) => (
          <div
            key={control.controlId}
            className="flex flex-col justify-between rounded-xl border border-[#263244] bg-[#0D1320] p-5 space-y-3"
          >
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <span className="font-mono text-xs font-bold text-[#00D4FF] bg-[#00D4FF]/10 border border-[#00D4FF]/30 px-2 py-0.5 rounded">
                  {control.controlId}
                </span>
                <span
                  className={`rounded px-2 py-0.5 text-[10px] font-bold ${
                    control.status === 'Failed'
                      ? 'bg-[#EF4444]/20 text-[#EF4444]'
                      : 'bg-[#F59E0B]/20 text-[#F59E0B]'
                  }`}
                >
                  {control.status}
                </span>
              </div>

              <h3 className="font-bold text-sm text-[#F8FAFC]">{control.title}</h3>
              <p className="text-xs text-[#94A3B8] leading-relaxed">{control.description}</p>
            </div>

            <div className="border-t border-[#263244] pt-3 flex items-center justify-between text-xs">
              <span className="text-[#64748B] font-mono text-[11px]">{control.section}</span>
              <div className="flex items-center gap-1.5">
                <span className="text-[#94A3B8]">Associated Rules:</span>
                {control.associatedRules.map((r) => (
                  <span key={r} className="rounded bg-[#111827] px-1.5 py-0.5 font-mono text-[10px] text-[#00D4FF]">
                    {r}
                  </span>
                ))}
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
