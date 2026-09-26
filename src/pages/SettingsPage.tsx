import React, { useState } from 'react';
import { RULE_DEFINITIONS } from '../services/rbac-rules';
import {
  Settings,
  Shield,
  Cpu,
  Server,
  Sparkles,
  Check,
  ToggleLeft,
  ToggleRight,
  Sliders,
  Palette,
} from 'lucide-react';

export const SettingsPage: React.FC = () => {
  const [clusterName, setClusterName] = useState('production-demo');
  const [k8sVersion, setK8sVersion] = useState('v1.30.2');
  const [enabledRules, setEnabledRules] = useState<Record<string, boolean>>({
    'RBAC-001': true,
    'RBAC-002': true,
    'RBAC-003': true,
    'RBAC-004': true,
    'RBAC-005': true,
    'RBAC-006': true,
    'RBAC-007': true,
    'RBAC-008': true,
    'RBAC-009': true,
    'RBAC-010': true,
    'RBAC-011': true,
    'RBAC-012': true,
  });

  const [savedSuccess, setSavedSuccess] = useState(false);

  const toggleRule = (ruleId: string) => {
    setEnabledRules((prev) => ({
      ...prev,
      [ruleId]: !prev[ruleId],
    }));
  };

  const handleSave = () => {
    setSavedSuccess(true);
    setTimeout(() => setSavedSuccess(false), 2500);
  };

  return (
    <div className="space-y-6">
      {/* Title */}
      <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between border-b border-[#263244] pb-4">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-[#F8FAFC] sm:text-2xl flex items-center gap-2">
            <Settings className="h-6 w-6 text-[#00D4FF]" />
            <span>Platform & Scanner Settings</span>
          </h1>
          <p className="mt-1 text-xs text-[#94A3B8]">
            Configure scanner rules, server-side AI integration, and cluster runtime parameters.
          </p>
        </div>

        <button
          onClick={handleSave}
          className="flex items-center gap-1.5 rounded-lg bg-[#00D4FF] px-4 py-2 text-xs font-bold text-[#070B14] hover:bg-[#00D4FF]/90 shadow-[0_0_12px_rgba(0,212,255,0.25)]"
        >
          <Check className="h-4 w-4" />
          <span>{savedSuccess ? 'Settings Saved' : 'Save Changes'}</span>
        </button>
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        {/* Left Column: Cluster & AI Configuration */}
        <div className="space-y-6 lg:col-span-1">
          {/* Cluster Configuration */}
          <div className="rounded-xl border border-[#263244] bg-[#0D1320] p-5 space-y-4">
            <div className="flex items-center gap-2 border-b border-[#263244] pb-3">
              <Server className="h-4 w-4 text-[#00D4FF]" />
              <h3 className="text-xs font-bold uppercase tracking-wider text-[#F8FAFC]">
                Cluster Profile
              </h3>
            </div>

            <div className="space-y-3 text-xs">
              <div>
                <label className="text-[#94A3B8] font-medium block mb-1">
                  Active Cluster Name
                </label>
                <input
                  type="text"
                  value={clusterName}
                  onChange={(e) => setClusterName(e.target.value)}
                  className="w-full rounded-md border border-[#263244] bg-[#111827] px-3 py-2 text-xs text-[#F8FAFC] outline-none focus:border-[#00D4FF]"
                />
              </div>

              <div>
                <label className="text-[#94A3B8] font-medium block mb-1">
                  Kubernetes API Version
                </label>
                <input
                  type="text"
                  value={k8sVersion}
                  onChange={(e) => setK8sVersion(e.target.value)}
                  className="w-full rounded-md border border-[#263244] bg-[#111827] px-3 py-2 text-xs text-[#F8FAFC] outline-none focus:border-[#00D4FF]"
                />
              </div>

              <div className="rounded-lg border border-[#263244] bg-[#111827] p-2.5">
                <span className="text-[10px] uppercase font-semibold text-[#64748B] block">Demo Mode Status</span>
                <span className="text-xs font-bold text-[#22C55E]">Active (production-demo cluster)</span>
              </div>
            </div>
          </div>

          {/* AI Remediation Configuration */}
          <div className="rounded-xl border border-[#263244] bg-[#0D1320] p-5 space-y-4">
            <div className="flex items-center gap-2 border-b border-[#263244] pb-3">
              <Sparkles className="h-4 w-4 text-[#7C3AED]" />
              <h3 className="text-xs font-bold uppercase tracking-wider text-[#F8FAFC]">
                AI Remediation Config
              </h3>
            </div>

            <div className="space-y-3 text-xs">
              <div>
                <span className="text-[10px] uppercase font-semibold text-[#64748B] block">Target Model</span>
                <p className="font-mono font-bold text-xs text-[#00D4FF]">gemini-3.8-flash</p>
                <p className="text-[11px] text-[#94A3B8] mt-0.5">
                  High-efficiency model executed strictly server-side for least-privilege YAML synthesis.
                </p>
              </div>

              <div>
                <span className="text-[10px] uppercase font-semibold text-[#64748B] block">API Key Provisioning</span>
                <p className="text-[#22C55E] text-xs font-medium">
                  Managed securely via environment variables (`GEMINI_API_KEY`).
                </p>
              </div>

              <div className="rounded-lg border border-[#263244] bg-[#111827] p-3 text-[11px] text-[#94A3B8]">
                Deterministic fallback remediation is active and operates seamlessly even without external cloud connectivity.
              </div>
            </div>
          </div>
        </div>

        {/* Right Column: RBAC Scanner Rules */}
        <div className="rounded-xl border border-[#263244] bg-[#0D1320] p-5 space-y-4 lg:col-span-2">
          <div className="flex items-center justify-between border-b border-[#263244] pb-3">
            <div className="flex items-center gap-2">
              <Shield className="h-4 w-4 text-[#00D4FF]" />
              <h3 className="text-xs font-bold uppercase tracking-wider text-[#F8FAFC]">
                Deterministic RBAC Rules Engine (RBAC-001 – RBAC-012)
              </h3>
            </div>
            <span className="text-xs text-[#94A3B8]">
              {Object.values(enabledRules).filter(Boolean).length} of {Object.keys(RULE_DEFINITIONS).length} Enabled
            </span>
          </div>

          <div className="space-y-2.5">
            {Object.entries(RULE_DEFINITIONS).map(([ruleId, def]) => {
              const isEnabled = enabledRules[ruleId] ?? true;
              return (
                <div
                  key={ruleId}
                  className="flex items-start justify-between gap-4 rounded-lg border border-[#263244] bg-[#111827] p-3 text-xs transition-colors hover:border-[#00D4FF]/30"
                >
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <span className="font-mono font-bold text-[#00D4FF]">{ruleId}</span>
                      <span className="font-bold text-[#F8FAFC]">{def.name}</span>
                      <span
                        className={`rounded px-1.5 py-0.2 text-[9px] font-bold ${
                          def.severity === 'CRITICAL'
                            ? 'bg-[#EF4444]/20 text-[#EF4444]'
                            : def.severity === 'HIGH'
                            ? 'bg-[#F59E0B]/20 text-[#F59E0B]'
                            : 'bg-[#38BDF8]/20 text-[#38BDF8]'
                        }`}
                      >
                        {def.severity}
                      </span>
                    </div>
                    <p className="text-[11px] text-[#94A3B8] leading-relaxed">
                      {def.description}
                    </p>
                  </div>

                  <button
                    onClick={() => toggleRule(ruleId)}
                    className="shrink-0 text-[#00D4FF] hover:opacity-80"
                  >
                    {isEnabled ? (
                      <ToggleRight className="h-6 w-6 text-[#22C55E]" />
                    ) : (
                      <ToggleLeft className="h-6 w-6 text-[#64748B]" />
                    )}
                  </button>
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
};
