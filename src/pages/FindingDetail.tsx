import React, { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { Finding, Scan } from '../types/rbac';
import { FindingBadge } from '../components/SeverityCard';
import { RiskMeter } from '../components/RiskMeter';
import { YamlDiff } from '../components/YamlDiff';
import {
  ArrowLeft,
  Wrench,
  GitFork,
  ShieldAlert,
  Award,
  BookOpen,
  CheckCircle2,
  ExternalLink,
  ChevronRight,
  Sparkles,
} from 'lucide-react';

interface FindingDetailProps {
  currentScan: Scan;
  onUpdateFindingStatus?: (findingId: string, status: 'Resolved' | 'Open') => void;
}

export const FindingDetail: React.FC<FindingDetailProps> = ({ currentScan, onUpdateFindingStatus }) => {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const [finding, setFinding] = useState<Finding | null>(null);

  useEffect(() => {
    const found = currentScan.findings.find((f) => f.id === id);
    if (found) {
      setFinding(found);
    } else if (currentScan.findings.length > 0) {
      setFinding(currentScan.findings[0]);
    }
  }, [id, currentScan.findings]);

  if (!finding) {
    return (
      <div className="flex flex-col items-center justify-center p-12 text-center text-[#94A3B8]">
        <ShieldAlert className="h-10 w-10 text-[#263244] mb-3" />
        <h3 className="text-base font-bold text-[#F8FAFC]">Finding Not Found</h3>
        <p className="text-xs text-[#64748B] mt-1">The requested finding ID does not exist in the current scan.</p>
        <button
          onClick={() => navigate('/findings')}
          className="mt-4 rounded-lg bg-[#111827] border border-[#263244] px-4 py-2 text-xs font-semibold text-[#00D4FF]"
        >
          Return to Findings
        </button>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Back Button & Top Navigation */}
      <div className="flex items-center justify-between border-b border-[#263244] pb-3">
        <button
          onClick={() => navigate('/findings')}
          className="flex items-center gap-1.5 text-xs font-medium text-[#94A3B8] hover:text-[#00D4FF]"
        >
          <ArrowLeft className="h-4 w-4" />
          <span>Back to All Findings</span>
        </button>

        <div className="flex items-center gap-2">
          <button
            onClick={() => navigate(`/attack-graph?highlight=${finding.resourceName}`)}
            className="flex items-center gap-1.5 rounded-lg border border-[#263244] bg-[#0D1320] px-3 py-1.5 text-xs font-semibold text-[#94A3B8] hover:border-[#00D4FF]/40 hover:text-[#00D4FF]"
          >
            <GitFork className="h-3.5 w-3.5" />
            <span>View in Attack Graph</span>
          </button>

          <button
            onClick={() => navigate(`/remediation?findingId=${finding.id}`)}
            className="flex items-center gap-1.5 rounded-lg bg-[#00D4FF] px-3.5 py-1.5 text-xs font-bold text-[#070B14] hover:bg-[#00D4FF]/90 shadow-[0_0_12px_rgba(0,212,255,0.25)]"
          >
            <Wrench className="h-3.5 w-3.5" />
            <span>Generate Remediation</span>
          </button>
        </div>
      </div>

      {/* Main Header Card */}
      <div className="rounded-xl border border-[#263244] bg-[#0D1320] p-6 space-y-4">
        <div className="flex flex-wrap items-center gap-3">
          <FindingBadge severity={finding.severity} />
          <span className="font-mono text-xs font-bold text-[#00D4FF] bg-[#00D4FF]/10 border border-[#00D4FF]/30 px-2 py-0.5 rounded">
            {finding.ruleId}
          </span>
          <span className="text-xs text-[#64748B] uppercase tracking-wider font-semibold">
            {finding.category}
          </span>
          {finding.status === 'Resolved' && (
            <span className="flex items-center gap-1 rounded bg-[#22C55E]/10 border border-[#22C55E]/30 px-2 py-0.5 text-xs font-bold text-[#22C55E]">
              <CheckCircle2 className="h-3.5 w-3.5" />
              RESOLVED
            </span>
          )}
        </div>

        <div>
          <h1 className="text-xl font-black text-[#F8FAFC] sm:text-2xl">
            {finding.title}
          </h1>
          <p className="mt-1 text-sm text-[#94A3B8] leading-relaxed">
            {finding.description}
          </p>
        </div>

        {/* Affected Entities Grid */}
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4 rounded-lg border border-[#263244] bg-[#111827] p-3 text-xs">
          <div>
            <span className="text-[10px] uppercase font-semibold text-[#64748B] block">Affected Resource</span>
            <span className="font-mono font-bold text-[#F8FAFC]">
              {finding.resourceKind}/{finding.resourceName}
            </span>
          </div>

          <div>
            <span className="text-[10px] uppercase font-semibold text-[#64748B] block">Namespace</span>
            <span className="font-mono font-semibold text-[#38BDF8]">
              {finding.namespace}
            </span>
          </div>

          <div>
            <span className="text-[10px] uppercase font-semibold text-[#64748B] block">Identity / Subject</span>
            <span className="font-mono font-semibold text-[#7C3AED]">
              {finding.identity || 'Cluster Scope'}
            </span>
          </div>

          <div>
            <span className="text-[10px] uppercase font-semibold text-[#64748B] block">Permission Flagged</span>
            <span className="font-mono font-semibold text-[#EF4444] truncate block">
              {finding.permission || 'Elevated Access'}
            </span>
          </div>
        </div>
      </div>

      {/* Attack Path Visualization */}
      <div className="rounded-xl border border-[#263244] bg-[#0D1320] p-5 space-y-3">
        <h3 className="text-xs font-bold uppercase tracking-wider text-[#F8FAFC] flex items-center gap-2">
          <GitFork className="h-4 w-4 text-[#EF4444]" />
          <span>Privilege Escalation Attack Path</span>
        </h3>

        <div className="flex flex-wrap items-center gap-2 pt-2">
          {finding.attackPath.map((step, idx) => (
            <React.Fragment key={idx}>
              <div
                className={`rounded-lg border px-3 py-2 text-xs font-mono font-semibold ${
                  idx === finding.attackPath.length - 1
                    ? 'border-[#EF4444] bg-[#EF4444]/20 text-[#EF4444] shadow-[0_0_12px_rgba(239,68,68,0.3)]'
                    : 'border-[#263244] bg-[#111827] text-[#F8FAFC]'
                }`}
              >
                {step}
              </div>
              {idx < finding.attackPath.length - 1 && (
                <ChevronRight className="h-4 w-4 text-[#00D4FF] shrink-0" />
              )}
            </React.Fragment>
          ))}
        </div>
      </div>

      {/* Risk explanation & Blast Radius Grid */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {/* Risk Explanation */}
        <div className="rounded-xl border border-[#263244] bg-[#0D1320] p-5 space-y-3">
          <div className="flex items-center gap-2 border-b border-[#263244] pb-2">
            <ShieldAlert className="h-4 w-4 text-[#F59E0B]" />
            <h3 className="text-xs font-bold uppercase tracking-wider text-[#F8FAFC]">
              Security Risk Analysis
            </h3>
          </div>
          <p className="text-xs text-[#94A3B8] leading-relaxed">
            {finding.riskExplanation}
          </p>

          <div className="rounded-lg border border-[#263244] bg-[#111827] p-3 text-xs space-y-1">
            <span className="text-[10px] uppercase font-bold text-[#22C55E] block">
              Remediation Strategy
            </span>
            <p className="text-[#F8FAFC] leading-relaxed">{finding.recommendation}</p>
          </div>
        </div>

        {/* Blast Radius Visual Meters */}
        <RiskMeter blastRadius={finding.blastRadius} />
      </div>

      {/* Compliance & Security References */}
      <div className="rounded-xl border border-[#263244] bg-[#0D1320] p-4 space-y-3">
        <div className="flex items-center justify-between border-b border-[#263244] pb-2">
          <div className="flex items-center gap-2">
            <Award className="h-4 w-4 text-[#00D4FF]" />
            <h3 className="text-xs font-bold uppercase tracking-wider text-[#F8FAFC]">
              Compliance & Security Framework Mappings
            </h3>
          </div>
          <span className="text-[10px] text-[#64748B]">Informational Mappings Only</span>
        </div>

        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <div className="rounded-lg border border-[#263244] bg-[#111827] p-3">
            <span className="text-[10px] uppercase font-bold text-[#38BDF8] block">
              CIS Kubernetes Benchmark
            </span>
            <p className="mt-1 font-mono text-xs font-semibold text-[#F8FAFC]">
              {finding.cisReference}
            </p>
            <p className="mt-1 text-[11px] text-[#94A3B8]">
              Standardized recommendation for cluster privilege containment.
            </p>
          </div>

          <div className="rounded-lg border border-[#263244] bg-[#111827] p-3">
            <span className="text-[10px] uppercase font-bold text-[#F59E0B] block">
              MITRE ATT&CK for Containers
            </span>
            <p className="mt-1 font-mono text-xs font-semibold text-[#F8FAFC]">
              {finding.mitreReference}
            </p>
            <p className="mt-1 text-[11px] text-[#94A3B8]">
              Adversary tactical privilege escalation and credential harvesting matrix.
            </p>
          </div>
        </div>
      </div>

      {/* Side-by-side YAML Diff */}
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <h3 className="text-xs font-bold uppercase tracking-wider text-[#F8FAFC] flex items-center gap-2">
            <BookOpen className="h-4 w-4 text-[#00D4FF]" />
            <span>Configuration Manifest & Proposed Patch</span>
          </h3>
          <button
            onClick={() => navigate(`/remediation?findingId=${finding.id}`)}
            className="flex items-center gap-1 text-xs text-[#00D4FF] hover:underline"
          >
            <span>Open Interactive Remediation</span>
            <ExternalLink className="h-3 w-3" />
          </button>
        </div>

        <YamlDiff
          currentYaml={finding.currentYaml}
          suggestedYaml={finding.suggestedYaml}
        />
      </div>
    </div>
  );
};
