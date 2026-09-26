import React, { useState, useCallback, useMemo } from 'react';
import {
  ReactFlow,
  Controls,
  Background,
  applyNodeChanges,
  applyEdgeChanges,
  Node,
  Edge,
  NodeChange,
  EdgeChange,
  MarkerType,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { AttackGraphData, ExploitationStep, Severity } from '../types/rbac';
import { FindingBadge } from './SeverityCard';
import {
  ShieldAlert,
  Play,
  RotateCcw,
  Sparkles,
  Info,
  Layers,
  ChevronRight,
  Maximize2,
} from 'lucide-react';

interface AttackGraphCanvasProps {
  graphData: AttackGraphData;
  steps: ExploitationStep[];
  onSelectNode?: (nodeData: any) => void;
}

export const AttackGraphCanvas: React.FC<AttackGraphCanvasProps> = ({
  graphData,
  steps,
}) => {
  const [selectedNode, setSelectedNode] = useState<any>(null);
  const [isTracingAttackPath, setIsTracingAttackPath] = useState(true);
  const [activeSimulationStep, setActiveSimulationStep] = useState<number | null>(null);

  // Initial nodes transformation
  const initialNodes = useMemo(() => {
    return graphData.nodes.map((n) => {
      const isCritical = n.data.severity === 'CRITICAL';
      const isHigh = n.data.severity === 'HIGH';

      let bg = '#111827';
      let border = '#263244';
      if (isCritical) {
        border = '#EF4444';
        bg = 'rgba(239, 68, 68, 0.12)';
      } else if (isHigh) {
        border = '#F59E0B';
        bg = 'rgba(245, 158, 11, 0.12)';
      }

      return {
        ...n,
        style: {
          background: bg,
          color: '#F8FAFC',
          border: `1.5px solid ${border}`,
          borderRadius: '8px',
          padding: '10px 14px',
          fontSize: '12px',
          fontWeight: 600,
          boxShadow: isCritical
            ? '0 0 15px rgba(239, 68, 68, 0.25)'
            : '0 4px 12px rgba(0, 0, 0, 0.4)',
          width: 220,
        },
      };
    });
  }, [graphData.nodes]);

  // Initial edges transformation
  const initialEdges = useMemo(() => {
    return graphData.edges.map((e) => {
      const isCrit = e.data?.isCriticalPath;
      return {
        ...e,
        animated: isCrit || isTracingAttackPath,
        markerEnd: {
          type: MarkerType.ArrowClosed,
          color: isCrit ? '#EF4444' : '#00D4FF',
        },
        style: {
          stroke: isCrit ? '#EF4444' : '#263244',
          strokeWidth: isCrit ? 2.5 : 1.5,
        },
      };
    });
  }, [graphData.edges, isTracingAttackPath]);

  const [nodes, setNodes] = useState<Node[]>(initialNodes);
  const [edges, setEdges] = useState<Edge[]>(initialEdges);

  const onNodesChange = useCallback(
    (changes: NodeChange[]) => setNodes((nds) => applyNodeChanges(changes, nds)),
    []
  );
  const onEdgesChange = useCallback(
    (changes: EdgeChange[]) => setEdges((eds) => applyEdgeChanges(changes, eds)),
    []
  );

  const handleNodeClick = (_: React.MouseEvent, node: Node) => {
    setSelectedNode(node.data);
  };

  // Toggle Attack Path Trace
  const handleToggleTrace = () => {
    const nextState = !isTracingAttackPath;
    setIsTracingAttackPath(nextState);

    setEdges((prev) =>
      prev.map((e) => {
        const isCrit = e.data?.isCriticalPath;
        return {
          ...e,
          animated: nextState ? Boolean(isCrit) : false,
          style: {
            ...e.style,
            stroke: nextState && isCrit ? '#EF4444' : isCrit ? '#EF4444' : '#263244',
            strokeWidth: nextState && isCrit ? 3 : 1.5,
          },
        };
      })
    );
  };

  // Run or advance exploitation walkthrough
  const handleAdvanceSimulation = () => {
    if (activeSimulationStep === null || activeSimulationStep >= steps.length) {
      setActiveSimulationStep(1);
      highlightStepNode(steps[0]);
    } else {
      const nextStepIndex = activeSimulationStep;
      setActiveSimulationStep(nextStepIndex + 1);
      highlightStepNode(steps[nextStepIndex]);
    }
  };

  const handleResetSimulation = () => {
    setActiveSimulationStep(null);
    setSelectedNode(null);
    setNodes(initialNodes);
    setEdges(initialEdges);
  };

  const highlightStepNode = (step: ExploitationStep) => {
    const targetNode = nodes.find((n) => n.id === step.nodeId || n.id.includes(step.nodeId));
    if (targetNode) {
      setSelectedNode(targetNode.data);
    }
  };

  return (
    <div className="relative flex h-[620px] w-full flex-col lg:flex-row overflow-hidden rounded-xl border border-[#263244] bg-[#070B14]">
      {/* Canvas Area */}
      <div className="relative flex-1 h-full w-full">
        {/* Controls Toolbar */}
        <div className="absolute top-4 left-4 z-10 flex flex-wrap items-center gap-2 rounded-lg border border-[#263244] bg-[#0D1320]/90 p-1.5 backdrop-blur-md">
          <button
            onClick={handleToggleTrace}
            className={`flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-semibold transition-all ${
              isTracingAttackPath
                ? 'bg-[#EF4444] text-white shadow-[0_0_12px_rgba(239,68,68,0.4)]'
                : 'bg-[#111827] text-[#94A3B8] hover:text-[#F8FAFC]'
            }`}
          >
            <ShieldAlert className="h-3.5 w-3.5" />
            <span>Trace Attack Path</span>
          </button>

          <button
            onClick={handleAdvanceSimulation}
            className="flex items-center gap-1.5 rounded-md bg-[#00D4FF]/10 border border-[#00D4FF]/30 px-3 py-1.5 text-xs font-semibold text-[#00D4FF] hover:bg-[#00D4FF]/20"
          >
            <Play className="h-3.5 w-3.5" />
            <span>
              {activeSimulationStep === null
                ? 'Simulate Exploitation'
                : `Step ${activeSimulationStep} of ${steps.length} (Next)`}
            </span>
          </button>

          {activeSimulationStep !== null && (
            <button
              onClick={handleResetSimulation}
              className="flex items-center gap-1 rounded-md bg-[#111827] px-2.5 py-1.5 text-xs text-[#94A3B8] hover:text-[#F8FAFC]"
            >
              <RotateCcw className="h-3.5 w-3.5" />
              <span>Reset</span>
            </button>
          )}
        </div>

        {/* Legend */}
        <div className="absolute bottom-4 left-4 z-10 flex items-center gap-4 rounded-lg border border-[#263244] bg-[#0D1320]/90 px-3 py-2 text-[11px] backdrop-blur-md">
          <div className="flex items-center gap-1.5">
            <span className="h-2 w-2 rounded-full bg-[#EF4444] animate-pulse"></span>
            <span className="text-[#F8FAFC]">Critical Privilege Path</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="h-2 w-2 rounded-full bg-[#F59E0B]"></span>
            <span className="text-[#94A3B8]">High Warning</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="h-2 w-2 rounded-full bg-[#00D4FF]"></span>
            <span className="text-[#94A3B8]">Authorized Relationship</span>
          </div>
        </div>

        {/* React Flow Component */}
        <ReactFlow
          nodes={nodes}
          edges={edges}
          onNodesChange={onNodesChange}
          onEdgesChange={onEdgesChange}
          onNodeClick={handleNodeClick}
          fitView
          fitViewOptions={{ padding: 0.2 }}
          minZoom={0.2}
          maxZoom={1.5}
        >
          <Background color="#1E293B" gap={24} size={1} />
          <Controls className="!bg-[#0D1320] !border-[#263244] !fill-[#F8FAFC] [&>button]:!border-[#263244] [&>button]:!bg-[#111827]" />
        </ReactFlow>
      </div>

      {/* Right Details & Simulation Inspector Panel */}
      <div className="w-full lg:w-80 border-t lg:border-t-0 lg:border-l border-[#263244] bg-[#0D1320] p-4 flex flex-col justify-between overflow-y-auto">
        <div className="space-y-4">
          <div className="flex items-center justify-between border-b border-[#263244] pb-2">
            <h3 className="text-xs font-bold uppercase tracking-wider text-[#F8FAFC] flex items-center gap-1.5">
              <Layers className="h-4 w-4 text-[#00D4FF]" />
              <span>Entity Inspector</span>
            </h3>
            {selectedNode && (
              <FindingBadge
                severity={selectedNode.severity || ('LOW' as Severity)}
              />
            )}
          </div>

          {/* Node detail display */}
          {selectedNode ? (
            <div className="space-y-3 text-xs">
              <div>
                <span className="text-[10px] uppercase font-semibold text-[#64748B]">
                  Resource Name
                </span>
                <p className="font-mono font-bold text-sm text-[#F8FAFC] break-all">
                  {selectedNode.name}
                </p>
              </div>

              <div className="grid grid-cols-2 gap-2">
                <div>
                  <span className="text-[10px] uppercase font-semibold text-[#64748B]">Kind</span>
                  <p className="text-[#94A3B8] font-medium">{selectedNode.kind}</p>
                </div>
                <div>
                  <span className="text-[10px] uppercase font-semibold text-[#64748B]">Namespace</span>
                  <p className="text-[#00D4FF] font-mono">{selectedNode.namespace || 'default'}</p>
                </div>
              </div>

              <div>
                <span className="text-[10px] uppercase font-semibold text-[#64748B]">
                  Security Risk Profile
                </span>
                <p className="mt-0.5 rounded-md border border-[#263244] bg-[#111827] p-2 text-[#EF4444] font-medium leading-relaxed">
                  {selectedNode.risk || 'No active anomalies flagged on this node.'}
                </p>
              </div>

              {selectedNode.permissions && selectedNode.permissions.length > 0 && (
                <div>
                  <span className="text-[10px] uppercase font-semibold text-[#64748B]">
                    Effective Privileges
                  </span>
                  <div className="mt-1 flex flex-wrap gap-1">
                    {selectedNode.permissions.map((p: string) => (
                      <span
                        key={p}
                        className="rounded bg-[#111827] border border-[#263244] px-1.5 py-0.5 font-mono text-[10px] text-[#00D4FF]"
                      >
                        {p}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          ) : (
            <div className="flex flex-col items-center justify-center p-6 text-center text-[#94A3B8]">
              <Info className="h-8 w-8 text-[#263244] mb-2" />
              <p className="text-xs">Click any node or relationship edge in the graph to inspect permissions and risk details.</p>
            </div>
          )}

          {/* Active Simulation Step Info */}
          {activeSimulationStep !== null && steps[activeSimulationStep - 1] && (
            <div className="mt-4 rounded-lg border border-[#00D4FF]/30 bg-[#00D4FF]/5 p-3 text-xs space-y-2">
              <div className="flex items-center gap-1.5 font-bold text-[#00D4FF]">
                <Sparkles className="h-4 w-4" />
                <span>Step {activeSimulationStep}: {steps[activeSimulationStep - 1].title}</span>
              </div>
              <p className="text-[#F8FAFC] leading-relaxed">
                {steps[activeSimulationStep - 1].action}
              </p>
              <div className="rounded border border-[#263244] bg-[#070B14] p-2 text-[11px]">
                <span className="text-[#64748B] uppercase font-semibold text-[9px] block">Privilege Escalated</span>
                <span className="text-[#EF4444] font-medium">
                  {steps[activeSimulationStep - 1].privilegeGained}
                </span>
              </div>
            </div>
          )}
        </div>

        {/* Bottom Simulation Walkthrough Button */}
        <div className="border-t border-[#263244] pt-3 mt-4">
          <button
            onClick={handleAdvanceSimulation}
            className="w-full flex items-center justify-center gap-2 rounded-lg bg-[#00D4FF] py-2 text-xs font-bold text-[#070B14] hover:bg-[#00D4FF]/90 shadow-[0_0_12px_rgba(0,212,255,0.25)]"
          >
            <span>
              {activeSimulationStep === null ? 'Run Attack Simulation' : 'Next Attack Phase'}
            </span>
            <ChevronRight className="h-4 w-4" />
          </button>
        </div>
      </div>
    </div>
  );
};
