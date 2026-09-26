import React, { useState } from 'react';
import { FileValidationResult } from '../types/rbac';
import {
  X,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  FileCode,
  Calendar,
  Clock,
  User,
  Trash2,
  CheckCircle2,
  AlertOctagon,
  HelpCircle,
  Terminal,
  Zap,
  ChevronDown,
  ChevronUp,
  Cpu,
  Lock,
  Flame,
  ArrowRight,
  Network,
  Copy,
  Check,
} from 'lucide-react';

interface FileSecurityReportModalProps {
  file: FileValidationResult | null;
  onClose: () => void;
  onRemoveFile?: (fileId: string) => void;
}

export const FileSecurityReportModal: React.FC<FileSecurityReportModalProps> = ({
  file,
  onClose,
  onRemoveFile,
}) => {
  const [showThinkingTrace, setShowThinkingTrace] = useState<boolean>(true);
  const [copiedFix, setCopiedFix] = useState<boolean>(false);

  if (!file) return null;

  const isRejected = file.status === 'REJECTED';
  const isAccepted = file.status === 'ACCEPTED';
  const isWarning = file.status === 'WARNING';
  const intel = file.threatIntelligence;

  let statusBadgeColor = 'bg-[#22C55E]/15 text-[#22C55E] border-[#22C55E]/40';
  if (isRejected) {
    statusBadgeColor = 'bg-[#EF4444]/15 text-[#EF4444] border-[#EF4444]/40';
  } else if (isWarning) {
    statusBadgeColor = 'bg-[#F59E0B]/15 text-[#F59E0B] border-[#F59E0B]/40';
  }

  const handleCopyFix = () => {
    if (intel?.remediationYaml) {
      navigator.clipboard.writeText(intel.remediationYaml);
      setCopiedFix(true);
      setTimeout(() => setCopiedFix(false), 2000);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-xs">
      <div className="relative w-full max-w-4xl overflow-hidden rounded-xl border border-[#263244] bg-[#0D1320] shadow-2xl">
        {/* Header */}
        <div
          className={`flex items-center justify-between border-b px-6 py-4 ${
            isRejected
              ? 'border-[#EF4444]/30 bg-[#EF4444]/10'
              : isWarning
              ? 'border-[#F59E0B]/30 bg-[#F59E0B]/10'
              : 'border-[#22C55E]/30 bg-[#22C55E]/10'
          }`}
        >
          <div className="flex items-center gap-2.5">
            {isRejected ? (
              <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-[#EF4444]/20 text-[#EF4444] border border-[#EF4444]/40 shadow-sm animate-pulse">
                <ShieldAlert className="h-5 w-5" />
              </div>
            ) : isWarning ? (
              <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-[#F59E0B]/20 text-[#F59E0B] border border-[#F59E0B]/40 shadow-sm">
                <AlertTriangle className="h-5 w-5" />
              </div>
            ) : (
              <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-[#22C55E]/20 text-[#22C55E] border border-[#22C55E]/40 shadow-sm">
                <ShieldCheck className="h-5 w-5" />
              </div>
            )}
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-base font-bold text-[#F8FAFC]">
                  {isRejected
                    ? 'THREAT DETECTED — FILE REJECTED'
                    : isAccepted
                    ? 'SECURITY CLEARANCE GRANTED'
                    : 'File Security Report'}
                </h3>
                {isRejected && (
                  <span className="rounded bg-[#EF4444] px-2 py-0.5 text-[10px] font-black uppercase text-white tracking-wider">
                    STRICT REJECTION POLICY ENFORCED
                  </span>
                )}
                {isAccepted && (
                  <span className="rounded bg-[#22C55E] px-2 py-0.5 text-[10px] font-black uppercase text-[#070B14] tracking-wider">
                    VERIFIED SAFE
                  </span>
                )}
              </div>
              <p className="text-xs text-[#94A3B8]">
                Heuristic behavioral analysis, structural correlation & threat audit
              </p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="rounded p-1 text-[#94A3B8] hover:bg-[#111827] hover:text-[#F8FAFC] transition-colors"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        {/* Content Body */}
        <div className="max-h-[75vh] overflow-y-auto p-6 space-y-5 text-xs">
          {/* File Overview Bar */}
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4 rounded-lg border border-[#263244] bg-[#111827] p-3.5">
            <div>
              <span className="text-[10px] uppercase font-semibold text-[#64748B] block">File</span>
              <span className="font-mono font-bold text-[#F8FAFC] truncate block">{file.fileName}</span>
            </div>

            <div>
              <span className="text-[10px] uppercase font-semibold text-[#64748B] block">Uploaded</span>
              <span className="text-[#F8FAFC] block">{file.uploadDate}</span>
              <span className="text-[10px] text-[#94A3B8]">{file.uploadTime}</span>
            </div>

            <div>
              <span className="text-[10px] uppercase font-semibold text-[#64748B] block">Uploaded By</span>
              <span className="font-semibold text-[#00D4FF] block">{file.uploadedBy}</span>
              <span className="text-[10px] text-[#64748B]">Scan {file.scanId}</span>
            </div>

            <div>
              <span className="text-[10px] uppercase font-semibold text-[#64748B] block">Status</span>
              <span
                className={`inline-block mt-0.5 rounded border px-2 py-0.5 text-[10px] font-black uppercase ${statusBadgeColor}`}
              >
                {file.status}
              </span>
            </div>
          </div>

          {/* Score & Verdict Banner */}
          <div
            className={`rounded-xl border p-4 flex items-center justify-between ${
              isRejected
                ? 'border-[#EF4444]/40 bg-[#EF4444]/10 text-[#EF4444]'
                : isWarning
                ? 'border-[#F59E0B]/40 bg-[#F59E0B]/10 text-[#F59E0B]'
                : 'border-[#22C55E]/40 bg-[#22C55E]/10 text-[#22C55E]'
            }`}
          >
            <div className="space-y-1">
              <span className="text-[11px] font-bold uppercase tracking-wider block flex items-center gap-1.5">
                {isRejected ? (
                  <>
                    <AlertOctagon className="h-4 w-4 shrink-0 text-[#EF4444]" />
                    <span>✕ THREAT DETECTED — FILE REJECTED</span>
                  </>
                ) : isWarning ? (
                  <>
                    <AlertTriangle className="h-4 w-4 shrink-0 text-[#F59E0B]" />
                    <span>⚠ WARNING — REVIEW RECOMMENDED</span>
                  </>
                ) : (
                  <>
                    <CheckCircle2 className="h-4 w-4 shrink-0 text-[#22C55E]" />
                    <span>✓ SECURITY CLEARANCE GRANTED — 100/100</span>
                  </>
                )}
              </span>
              <p className="text-xs text-[#F8FAFC] leading-relaxed">
                {file.reason}
              </p>
            </div>

            <div className="text-center shrink-0 pl-4 border-l border-current/20">
              <span className="text-[10px] uppercase block font-semibold text-[#94A3B8]">Security Score</span>
              <span className="font-mono text-2xl font-black">
                {file.securityScore} / 100
              </span>
            </div>
          </div>

          {/* DEDICATED THREAT INTELLIGENCE REPORT (If Threat Detected) */}
          {intel && (
            <div className="rounded-xl border border-[#EF4444]/40 bg-[#070B14] p-4 space-y-4">
              <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[#263244] pb-3">
                <div className="flex items-center gap-2">
                  <Flame className="h-4 w-4 text-[#EF4444]" />
                  <span className="font-bold text-[#F8FAFC] text-sm">Threat Intelligence Report</span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="rounded bg-[#EF4444]/20 border border-[#EF4444]/50 px-2 py-0.5 text-[10px] font-black uppercase text-[#EF4444]">
                    SEVERITY: {intel.severity}
                  </span>
                  <span className="rounded bg-[#111827] border border-[#263244] px-2 py-0.5 text-[10px] font-mono text-[#00D4FF]">
                    {intel.category}
                  </span>
                  {intel.mitreTechnique && (
                    <span className="rounded bg-[#111827] border border-[#263244] px-2 py-0.5 text-[10px] font-mono text-[#94A3B8]">
                      {intel.mitreTechnique}
                    </span>
                  )}
                </div>
              </div>

              {/* Threat Type Title */}
              <div>
                <span className="text-[10px] uppercase font-bold text-[#64748B] block">Threat Type</span>
                <p className="text-sm font-bold text-[#EF4444] mt-0.5">{intel.threatType}</p>
                <p className="text-xs text-[#CBD5E1] mt-1">{intel.impactSummary}</p>
              </div>

              {/* Malicious Intent (Why this pattern exists) */}
              {intel.maliciousIntent && (
                <div className="rounded-lg border border-[#EF4444]/30 bg-[#EF4444]/5 p-3 space-y-1">
                  <span className="text-[11px] uppercase font-bold text-[#EF4444] flex items-center gap-1.5">
                    <HelpCircle className="h-3.5 w-3.5" />
                    <span>Malicious Intent & Adversary Motivation</span>
                  </span>
                  <p className="text-xs text-[#CBD5E1] leading-relaxed">
                    {intel.maliciousIntent}
                  </p>
                </div>
              )}

              {/* Interactive Threat Map: Attack Chain Topology */}
              {intel.attackChainNodes && intel.attackChainNodes.length > 0 && (
                <div className="space-y-2 rounded-lg border border-[#263244] bg-[#111827] p-3.5">
                  <div className="flex items-center justify-between">
                    <span className="text-[11px] uppercase font-bold text-[#00D4FF] flex items-center gap-1.5">
                      <Network className="h-3.5 w-3.5" />
                      <span>Interactive Threat Map (Attack Chain Progression)</span>
                    </span>
                    <span className="text-[10px] text-[#64748B] font-mono">Zero-Trust Compromise Path</span>
                  </div>

                  <div className="flex flex-col sm:flex-row items-center gap-2 pt-2 overflow-x-auto">
                    {intel.attackChainNodes.map((node, i) => (
                      <React.Fragment key={node.id}>
                        <div
                          className={`p-2.5 rounded-lg border text-center min-w-[130px] flex-1 w-full sm:w-auto transition-all ${
                            node.role === 'source'
                              ? 'border-[#00D4FF]/40 bg-[#00D4FF]/10 text-[#00D4FF]'
                              : node.role === 'escalation'
                              ? 'border-[#F59E0B]/40 bg-[#F59E0B]/10 text-[#F59E0B]'
                              : 'border-[#EF4444]/60 bg-[#EF4444]/20 text-[#EF4444] shadow-[0_0_10px_rgba(239,68,68,0.2)]'
                          }`}
                        >
                          <span className="text-[9px] uppercase font-mono block font-bold opacity-75">
                            {node.role}
                          </span>
                          <span className="text-xs font-bold block mt-0.5 truncate">
                            {node.label}
                          </span>
                          <span className="text-[10px] text-[#94A3B8] block mt-1 leading-tight line-clamp-2">
                            {node.description}
                          </span>
                        </div>
                        {i < (intel.attackChainNodes?.length ?? 0) - 1 && (
                          <ArrowRight className="h-4 w-4 shrink-0 text-[#64748B] rotate-90 sm:rotate-0 my-1 sm:my-0" />
                        )}
                      </React.Fragment>
                    ))}
                  </div>
                </div>
              )}

              {/* Step-by-Step Attack Vector */}
              {intel.attackVectorSteps && intel.attackVectorSteps.length > 0 && (
                <div className="space-y-2 rounded-lg border border-[#263244] bg-[#111827] p-3.5">
                  <span className="text-[11px] uppercase font-bold text-[#EF4444] flex items-center gap-1.5">
                    <Zap className="h-3.5 w-3.5" />
                    <span>Step-by-Step Attack Vector Simulation</span>
                  </span>
                  <div className="space-y-1.5 pt-1">
                    {intel.attackVectorSteps.map((step, idx) => (
                      <div key={idx} className="flex items-start gap-2 text-xs text-[#F8FAFC]">
                        <span className="flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-[#EF4444]/20 border border-[#EF4444]/40 font-mono text-[10px] font-bold text-[#EF4444]">
                          {idx + 1}
                        </span>
                        <p className="leading-snug pt-0.5 text-[#E2E8F0]">{step}</p>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Side-by-Side Code Highlighting: Offending vs Safe Version */}
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-[11px] uppercase font-bold text-[#F8FAFC]">
                    Code Analysis & Safe Remediation Diff
                  </span>
                  {intel.remediationYaml && (
                    <button
                      onClick={handleCopyFix}
                      className="flex items-center gap-1 text-[10px] font-semibold text-[#00D4FF] hover:underline"
                    >
                      {copiedFix ? <Check className="h-3 w-3" /> : <Copy className="h-3 w-3" />}
                      <span>{copiedFix ? 'Copied Safe Fix' : 'Copy Corrected YAML'}</span>
                    </button>
                  )}
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  {/* Left: Offending lines in RED */}
                  <div className="rounded-lg border border-[#EF4444]/40 bg-black/60 p-3 space-y-1.5">
                    <span className="text-[10px] font-mono font-bold text-[#EF4444] flex items-center gap-1">
                      <AlertOctagon className="h-3 w-3" />
                      Offending Vulnerable Lines (REJECTED)
                    </span>
                    <pre className="font-mono text-[11px] text-[#EF4444] overflow-x-auto whitespace-pre-wrap max-h-48 leading-relaxed">
                      {intel.evidenceSnippet || file.content.slice(0, 300)}
                    </pre>
                  </div>

                  {/* Right: Safe Version in GREEN */}
                  <div className="rounded-lg border border-[#22C55E]/40 bg-black/60 p-3 space-y-1.5">
                    <span className="text-[10px] font-mono font-bold text-[#22C55E] flex items-center gap-1">
                      <CheckCircle2 className="h-3 w-3" />
                      Safe Corrected Version (PROPOSED FIX)
                    </span>
                    <pre className="font-mono text-[11px] text-[#22C55E] overflow-x-auto whitespace-pre-wrap max-h-48 leading-relaxed">
                      {intel.remediationYaml || intel.remediationAdvice}
                    </pre>
                  </div>
                </div>
              </div>

              {/* Actionable Remediation Advice */}
              <div className="rounded-lg border border-[#22C55E]/30 bg-[#22C55E]/5 p-3 space-y-1">
                <span className="text-[11px] uppercase font-bold text-[#22C55E] flex items-center gap-1.5">
                  <CheckCircle2 className="h-3.5 w-3.5" />
                  <span>Required Mitigation & Remediation</span>
                </span>
                <p className="text-xs text-[#F8FAFC] leading-relaxed">
                  {intel.remediationAdvice}
                </p>
              </div>
            </div>
          )}

          {/* AI Security Analyst "Thinking" Heuristic Trace */}
          {(file.aiAnalystThinkingSteps || (intel && intel.thinkingTrace)) && (
            <div className="rounded-xl border border-[#263244] bg-[#070B14] overflow-hidden">
              <button
                onClick={() => setShowThinkingTrace(!showThinkingTrace)}
                className="w-full flex items-center justify-between px-4 py-2.5 bg-[#111827] text-left hover:bg-[#1A2234] transition-colors"
              >
                <div className="flex items-center gap-2">
                  <Cpu className="h-4 w-4 text-[#00D4FF]" />
                  <span className="font-bold text-xs text-[#F8FAFC]">
                    AI Security Analyst Heuristic Thinking Trace
                  </span>
                  <span className="rounded bg-[#00D4FF]/10 text-[#00D4FF] border border-[#00D4FF]/30 px-1.5 py-0.2 text-[9px] font-mono">
                    BEHAVIORAL ENGINE
                  </span>
                </div>
                {showThinkingTrace ? (
                  <ChevronUp className="h-4 w-4 text-[#94A3B8]" />
                ) : (
                  <ChevronDown className="h-4 w-4 text-[#94A3B8]" />
                )}
              </button>

              {showThinkingTrace && (
                <div className="p-3 space-y-1.5 font-mono text-[11px] text-[#94A3B8] bg-black/50 border-t border-[#263244]">
                  {(file.aiAnalystThinkingSteps || intel?.thinkingTrace || []).map((step, idx) => (
                    <div key={idx} className="flex items-start gap-2">
                      <span className="text-[#00D4FF] shrink-0 font-bold">›</span>
                      <span
                        className={
                          step.includes('CRITICAL') || step.includes('REJECT') || step.includes('THREAT') || step.includes('Host Takeover')
                            ? 'text-[#EF4444] font-semibold'
                            : step.includes('APPROVED') || step.includes('Verified') || step.includes('ACCEPTED') || step.includes('PASS') || step.includes('CLEARANCE')
                            ? 'text-[#22C55E] font-semibold'
                            : 'text-[#CBD5E1]'
                        }
                      >
                        {step}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* Validation Results Matrix */}
          <div className="space-y-2">
            <span className="text-[11px] font-bold uppercase tracking-wider text-[#94A3B8] block">
              Multi-Layer Validation Matrix
            </span>

            <div className="rounded-lg border border-[#263244] bg-[#070B14] divide-y divide-[#263244]">
              {/* Layer 1: YAML Syntax */}
              <div className="flex items-center justify-between p-3">
                <div className="space-y-0.5">
                  <span className="font-bold text-[#F8FAFC] block">YAML Syntax Validation</span>
                  <p className="text-[11px] text-[#64748B]">Checks indentation, mapping syntax, and multi-doc boundaries</p>
                </div>
                <span
                  className={`font-mono font-bold text-xs px-2.5 py-1 rounded border ${
                    file.yamlSyntax === 'PASS'
                      ? 'bg-[#22C55E]/10 text-[#22C55E] border-[#22C55E]/30'
                      : 'bg-[#EF4444]/10 text-[#EF4444] border-[#EF4444]/30'
                  }`}
                >
                  {file.yamlSyntax === 'PASS' ? 'PASS' : 'FAILED'}
                </span>
              </div>

              {/* Layer 2: Kubernetes Schema */}
              <div className="flex items-center justify-between p-3">
                <div className="space-y-0.5">
                  <span className="font-bold text-[#F8FAFC] block">Kubernetes Structure & Schema</span>
                  <p className="text-[11px] text-[#64748B]">Verifies apiVersion, kind, metadata.name, and object hierarchies</p>
                </div>
                <span
                  className={`font-mono font-bold text-xs px-2.5 py-1 rounded border ${
                    file.k8sStructure === 'PASS'
                      ? 'bg-[#22C55E]/10 text-[#22C55E] border-[#22C55E]/30'
                      : 'bg-[#EF4444]/10 text-[#EF4444] border-[#EF4444]/30'
                  }`}
                >
                  {file.k8sStructure === 'PASS' ? 'PASS' : 'FAILED'}
                </span>
              </div>

              {/* Layer 3: Security Content Check */}
              <div className="flex items-center justify-between p-3">
                <div className="space-y-0.5">
                  <span className="font-bold text-[#F8FAFC] block">Security Content & Pattern Check</span>
                  <p className="text-[11px] text-[#64748B]">Checks for unexpected executables, binary headers, or script injection</p>
                </div>
                <span
                  className={`font-mono font-bold text-xs px-2.5 py-1 rounded border ${
                    file.securityContent === 'PASS'
                      ? 'bg-[#22C55E]/10 text-[#22C55E] border-[#22C55E]/30'
                      : 'bg-[#EF4444]/10 text-[#EF4444] border-[#EF4444]/30'
                  }`}
                >
                  {file.securityContent === 'PASS' ? 'PASS' : 'FAILED'}
                </span>
              </div>

              {/* Layer 4: Threat / Malware Scan */}
              <div className="flex items-center justify-between p-3">
                <div className="space-y-0.5">
                  <span className="font-bold text-[#F8FAFC] block">Heuristic Threat / Malware Detection</span>
                  <p className="text-[11px] text-[#64748B]">Correlates privilege escalation chains, obfuscated code, and persistence</p>
                </div>
                <span
                  className={`font-mono font-bold text-xs px-2.5 py-1 rounded border ${
                    file.threatScan === 'PASS'
                      ? 'bg-[#22C55E]/10 text-[#22C55E] border-[#22C55E]/30'
                      : 'bg-[#EF4444]/20 text-[#EF4444] border-[#EF4444]/50 animate-pulse'
                  }`}
                >
                  {file.threatScan === 'PASS' ? 'PASS' : 'DETECTED'}
                </span>
              </div>
            </div>
          </div>

          {/* Architectural Distinction Note */}
          <div className="rounded-lg border border-[#263244] bg-[#111827] p-3 text-[11px] text-[#94A3B8] space-y-1">
            <span className="font-bold text-[#00D4FF] block flex items-center gap-1">
              <HelpCircle className="h-3.5 w-3.5" />
              <span>Architectural Boundary: Security Validation vs. RBAC Policy Posture</span>
            </span>
            <p>
              <strong>Security Validation</strong> ensures uploaded manifests are free of malicious payloads, privilege escalation chains, obfuscated shell commands, and malformed schemas.
              Files failing this layer are <strong>strictly rejected</strong> and will not be parsed into the RBAC attack graph.
            </p>
          </div>
        </div>

        {/* Footer Actions */}
        <div className="flex items-center justify-between border-t border-[#263244] bg-[#070B14] px-6 py-3">
          {onRemoveFile && (
            <button
              onClick={() => {
                onRemoveFile(file.fileId);
                onClose();
              }}
              className="flex items-center gap-1.5 rounded-lg border border-[#EF4444]/40 bg-[#EF4444]/10 px-3.5 py-1.5 text-xs font-semibold text-[#EF4444] hover:bg-[#EF4444]/20 transition-colors"
            >
              <Trash2 className="h-3.5 w-3.5" />
              <span>Remove this file</span>
            </button>
          )}

          <div className="ml-auto">
            <button
              onClick={onClose}
              className="rounded-lg bg-[#111827] border border-[#263244] px-4 py-1.5 text-xs font-semibold text-[#F8FAFC] hover:border-[#00D4FF]/40 transition-colors"
            >
              Close Report
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
