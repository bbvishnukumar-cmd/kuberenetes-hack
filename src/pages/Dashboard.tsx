import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Scan } from '../types/rbac';
import { SecurityScore } from '../components/SecurityScore';
import { SeverityCard } from '../components/SeverityCard';
import { FindingTable } from '../components/FindingTable';
import { DeploymentApprovalCard } from '../components/DeploymentApprovalCard';
import type { DeploymentApproval } from '../types/deployment-approval';
import { DEMO_SCORE_TREND } from '../services/demo-data';
import {
  ResponsiveContainer,
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  PieChart,
  Pie,
  Cell,
} from 'recharts';
import {
  ShieldAlert,
  SearchCode,
  Users,
  Key,
  Shield,
  FileCode,
  ArrowRight,
  TrendingUp,
  Cpu,
} from 'lucide-react';

interface DashboardProps {
  currentScan: Scan;
  deploymentApproval?: DeploymentApproval;
}

export const Dashboard: React.FC<DashboardProps> = ({ currentScan, deploymentApproval }) => {
  const navigate = useNavigate();

  const criticalCount = currentScan.findings.filter(
    (f) => f.severity === 'CRITICAL' && f.status === 'Open'
  ).length;
  const highCount = currentScan.findings.filter(
    (f) => f.severity === 'HIGH' && f.status === 'Open'
  ).length;
  const mediumCount = currentScan.findings.filter(
    (f) => f.severity === 'MEDIUM' && f.status === 'Open'
  ).length;
  const lowCount = currentScan.findings.filter(
    (f) => f.severity === 'LOW' && f.status === 'Open'
  ).length;
  const resolvedCount = currentScan.findings.filter((f) => f.status === 'Resolved').length;
  const passedCount = 42 + resolvedCount;

  // Pie chart data
  const pieData = [
    { name: 'Critical', value: criticalCount || 1, color: '#EF4444' },
    { name: 'High', value: highCount || 1, color: '#F59E0B' },
    { name: 'Medium', value: mediumCount || 1, color: '#38BDF8' },
    { name: 'Low', value: lowCount || 1, color: '#94A3B8' },
  ];

  return (
    <div className="space-y-6">
      {/* Top Banner / Hero Title */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between border-b border-[#263244] pb-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="flex h-2.5 w-2.5 rounded-full bg-[#00D4FF] shadow-[0_0_8px_#00D4FF]" />
            <h1 className="text-xl font-bold tracking-tight text-[#F8FAFC] sm:text-2xl">
              Kubernetes Security Overview
            </h1>
          </div>
          <p className="mt-1 text-xs text-[#94A3B8]">
            Real-time RBAC privilege graph analysis and posture score for{' '}
            <span className="font-semibold text-[#00D4FF]">{currentScan.cluster}</span>
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={() => navigate('/scanner')}
            className="flex items-center gap-2 rounded-lg bg-[#00D4FF] px-4 py-2 text-xs font-bold text-[#070B14] shadow-[0_0_15px_rgba(0,212,255,0.3)] transition-all hover:bg-[#00D4FF]/90"
          >
            <SearchCode className="h-4 w-4" />
            <span>New Security Scan</span>
          </button>
        </div>
      </div>

      {/* Top metrics row */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        {/* Large Circular Gauge Card */}
        <div className="flex flex-col items-center justify-center rounded-xl border border-[#263244] bg-[#0D1320] p-6 shadow-xl">
          <SecurityScore
            score={currentScan.score}
            previousScore={currentScan.previousScore || 62}
            size="lg"
          />
        </div>

        {/* Severity Metrics Grid */}
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:col-span-2">
          <SeverityCard
            severity="CRITICAL"
            count={criticalCount}
            onClick={() => navigate('/findings')}
          />
          <SeverityCard
            severity="HIGH"
            count={highCount}
            onClick={() => navigate('/findings')}
          />
          <SeverityCard
            severity="MEDIUM"
            count={mediumCount}
            onClick={() => navigate('/findings')}
          />
          <SeverityCard
            severity="LOW"
            count={lowCount}
            onClick={() => navigate('/findings')}
          />
          <SeverityCard
            severity="PASSED"
            count={passedCount}
            label="Passed Checks"
            onClick={() => navigate('/compliance')}
          />

          {/* Quick Attack Path Trigger Widget */}
          <div
            onClick={() => navigate('/attack-graph')}
            className="flex flex-1 flex-col justify-between rounded-lg border border-[#00D4FF]/30 bg-[#00D4FF]/5 p-3 text-left transition-all hover:bg-[#00D4FF]/10 cursor-pointer"
          >
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold uppercase tracking-wider text-[#00D4FF]">
                Attack Graph
              </span>
              <ShieldAlert className="h-4 w-4 text-[#EF4444]" />
            </div>
            <div className="mt-2">
              <p className="text-xs font-bold text-[#F8FAFC]">Trace Escalation</p>
              <p className="text-[11px] text-[#94A3B8] flex items-center gap-1 mt-1">
                <span>View Full Map</span>
                <ArrowRight className="h-3 w-3 text-[#00D4FF]" />
              </p>
            </div>
          </div>
        </div>
      </div>

      <DeploymentApprovalCard approval={deploymentApproval} />

      {/* Charts Row: Trend line & Findings distribution */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {/* A. Security Trend Chart (14-day line chart) */}
        <div className="flex flex-col rounded-xl border border-[#263244] bg-[#0D1320] p-4">
          <div className="flex items-center justify-between border-b border-[#263244] pb-3 mb-4">
            <div>
              <h3 className="text-sm font-bold text-[#F8FAFC]">14-Day Security Trend</h3>
              <p className="text-xs text-[#94A3B8]">Historical score progression</p>
            </div>
            <div className="flex items-center gap-1 text-xs text-[#22C55E]">
              <TrendingUp className="h-4 w-4" />
              <span>+14 pts (Overall)</span>
            </div>
          </div>

          <div className="h-56 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={DEMO_SCORE_TREND}>
                <XAxis
                  dataKey="day"
                  stroke="#64748B"
                  fontSize={11}
                  tickLine={false}
                />
                <YAxis
                  domain={[40, 100]}
                  stroke="#64748B"
                  fontSize={11}
                  tickLine={false}
                />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#111827',
                    borderColor: '#263244',
                    borderRadius: '8px',
                    fontSize: '12px',
                    color: '#F8FAFC',
                  }}
                />
                <Line
                  type="monotone"
                  dataKey="score"
                  stroke="#00D4FF"
                  strokeWidth={2.5}
                  dot={{ fill: '#00D4FF', r: 3 }}
                  activeDot={{ r: 6, fill: '#7C3AED' }}
                />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* B. Findings Distribution Donut Chart */}
        <div className="flex flex-col rounded-xl border border-[#263244] bg-[#0D1320] p-4">
          <div className="flex items-center justify-between border-b border-[#263244] pb-3 mb-4">
            <div>
              <h3 className="text-sm font-bold text-[#F8FAFC]">Findings Distribution</h3>
              <p className="text-xs text-[#94A3B8]">Active issues by severity level</p>
            </div>
            <span className="font-mono text-xs text-[#00D4FF]">
              {currentScan.findings.filter((f) => f.status === 'Open').length} Total Active
            </span>
          </div>

          <div className="flex flex-1 items-center justify-around gap-4">
            <div className="h-52 w-52">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={pieData}
                    cx="50%"
                    cy="50%"
                    innerRadius={55}
                    outerRadius={80}
                    paddingAngle={4}
                    dataKey="value"
                  >
                    {pieData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#111827',
                      borderColor: '#263244',
                      borderRadius: '8px',
                      fontSize: '12px',
                      color: '#F8FAFC',
                    }}
                  />
                </PieChart>
              </ResponsiveContainer>
            </div>

            {/* Legend */}
            <div className="space-y-2 text-xs">
              <div className="flex items-center gap-2">
                <span className="h-3 w-3 rounded-full bg-[#EF4444]" />
                <span className="text-[#94A3B8]">Critical:</span>
                <span className="font-bold text-[#F8FAFC]">{criticalCount}</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="h-3 w-3 rounded-full bg-[#F59E0B]" />
                <span className="text-[#94A3B8]">High:</span>
                <span className="font-bold text-[#F8FAFC]">{highCount}</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="h-3 w-3 rounded-full bg-[#38BDF8]" />
                <span className="text-[#94A3B8]">Medium:</span>
                <span className="font-bold text-[#F8FAFC]">{mediumCount}</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="h-3 w-3 rounded-full bg-[#94A3B8]" />
                <span className="text-[#94A3B8]">Low:</span>
                <span className="font-bold text-[#F8FAFC]">{lowCount}</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* C. Identity Exposure Row */}
      <div className="rounded-xl border border-[#263244] bg-[#0D1320] p-4">
        <div className="flex items-center justify-between border-b border-[#263244] pb-2.5 mb-3">
          <h3 className="text-xs font-bold uppercase tracking-wider text-[#F8FAFC] flex items-center gap-2">
            <Cpu className="h-4 w-4 text-[#00D4FF]" />
            <span>Identity & RBAC Object Exposure Breakdown</span>
          </h3>
          <span className="text-xs text-[#94A3B8]">Cluster Audit Inventory</span>
        </div>

        <div className="grid grid-cols-2 gap-3 sm:grid-cols-5">
          <div className="flex items-center gap-3 rounded-lg border border-[#263244] bg-[#111827] p-3">
            <Users className="h-5 w-5 text-[#7C3AED]" />
            <div>
              <p className="text-[10px] uppercase font-semibold text-[#64748B]">ServiceAccounts</p>
              <p className="text-lg font-bold text-[#F8FAFC]">{currentScan.resourceCounts.serviceAccounts}</p>
            </div>
          </div>

          <div className="flex items-center gap-3 rounded-lg border border-[#263244] bg-[#111827] p-3">
            <Key className="h-5 w-5 text-[#F59E0B]" />
            <div>
              <p className="text-[10px] uppercase font-semibold text-[#64748B]">Roles</p>
              <p className="text-lg font-bold text-[#F8FAFC]">{currentScan.resourceCounts.roles}</p>
            </div>
          </div>

          <div className="flex items-center gap-3 rounded-lg border border-[#263244] bg-[#111827] p-3">
            <Shield className="h-5 w-5 text-[#EF4444]" />
            <div>
              <p className="text-[10px] uppercase font-semibold text-[#64748B]">ClusterRoles</p>
              <p className="text-lg font-bold text-[#F8FAFC]">{currentScan.resourceCounts.clusterRoles}</p>
            </div>
          </div>

          <div className="flex items-center gap-3 rounded-lg border border-[#263244] bg-[#111827] p-3">
            <FileCode className="h-5 w-5 text-[#38BDF8]" />
            <div>
              <p className="text-[10px] uppercase font-semibold text-[#64748B]">RoleBindings</p>
              <p className="text-lg font-bold text-[#F8FAFC]">{currentScan.resourceCounts.roleBindings}</p>
            </div>
          </div>

          <div className="flex items-center gap-3 rounded-lg border border-[#263244] bg-[#111827] p-3">
            <Shield className="h-5 w-5 text-[#EF4444]" />
            <div>
              <p className="text-[10px] uppercase font-semibold text-[#64748B]">ClusterRoleBindings</p>
              <p className="text-lg font-bold text-[#F8FAFC]">{currentScan.resourceCounts.clusterRoleBindings}</p>
            </div>
          </div>
        </div>
      </div>

      {/* D. Recent Findings Table */}
      <FindingTable
        findings={currentScan.findings}
        title="Recent Security Findings"
        limit={8}
      />
    </div>
  );
};
