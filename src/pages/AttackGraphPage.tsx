import React, { useState, useEffect } from 'react';
import { useSearchParams } from 'react-router-dom';
import { Scan, AttackGraphData, ExploitationStep } from '../types/rbac';
import { AttackGraphCanvas } from '../components/AttackGraphCanvas';
import { buildAttackGraph } from '../services/attack-graph-builder';
import { parseK8sYaml } from '../services/k8s-parser';
import { GitFork, ShieldAlert, Sparkles, RefreshCw } from 'lucide-react';

interface AttackGraphPageProps {
  currentScan: Scan;
}

export const AttackGraphPage: React.FC<AttackGraphPageProps> = ({ currentScan }) => {
  const [searchParams] = useSearchParams();
  const highlightQuery = searchParams.get('highlight');

  const [graphData, setGraphData] = useState<AttackGraphData | null>(null);
  const [simulationSteps, setSimulationSteps] = useState<ExploitationStep[]>([]);
  const [criticalPathsCount, setCriticalPathsCount] = useState<number>(0);

  useEffect(() => {
    // Generate graph from active scan YAML and findings
    const parseResult = parseK8sYaml(currentScan.rawYaml);
    const result = buildAttackGraph(parseResult.resources, currentScan.findings);
    setGraphData(result.graph);
    setSimulationSteps(result.steps);
    setCriticalPathsCount(result.criticalPathCount);
  }, [currentScan]);

  return (
    <div className="space-y-6">
      {/* Title Header */}
      <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between border-b border-[#263244] pb-4">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-[#F8FAFC] sm:text-2xl flex items-center gap-2">
            <GitFork className="h-6 w-6 text-[#00D4FF]" />
            <span>RBAC Attack Graph & Privilege Escalation Paths</span>
          </h1>
          <p className="mt-1 text-xs text-[#94A3B8]">
            Interactive topological graph tracing paths from compromised workloads through bindings to cluster-wide authority.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <span className="rounded-lg border border-[#EF4444]/40 bg-[#EF4444]/10 px-3 py-1.5 text-xs font-bold text-[#EF4444] flex items-center gap-1.5">
            <ShieldAlert className="h-4 w-4" />
            <span>{criticalPathsCount} Active Escalation Vectors</span>
          </span>
        </div>
      </div>

      {/* Attack Graph Component */}
      {graphData ? (
        <AttackGraphCanvas
          graphData={graphData}
          steps={simulationSteps}
        />
      ) : (
        <div className="flex h-96 items-center justify-center rounded-xl border border-[#263244] bg-[#0D1320] text-center text-[#94A3B8]">
          <RefreshCw className="h-6 w-6 animate-spin text-[#00D4FF] mb-2" />
          <p className="text-xs">Computing topological RBAC attack graph...</p>
        </div>
      )}
    </div>
  );
};
