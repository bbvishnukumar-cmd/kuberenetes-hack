import React, { useState, useEffect } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import {
  History,
  Server,
  ShieldCheck,
  ChevronRight,
  CheckCircle2,
  AlertCircle,
  AlertTriangle,
  Flame,
  FileCode,
  User,
  Calendar,
  Layers,
  Award,
} from 'lucide-react';
import { INITIAL_BENCHMARK_STATS, INITIAL_BENCHMARK_EVENTS } from '../services/benchmark-store';
import { BenchmarkStats, SecurityBenchmarkEvent } from '../types/rbac';

interface HistoryItem {
  id: string;
  date: string;
  cluster: string;
  files: string;
  score: number;
  critical: number;
  high: number;
  status: string;
}

export const ScanHistoryPage: React.FC = () => {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const initialTab = searchParams.get('tab') === 'benchmark' ? 'benchmark' : 'history';

  const [activeTab, setActiveTab] = useState<'history' | 'benchmark'>(initialTab);

  const [clusterHistory, setClusterHistory] = useState<HistoryItem[]>([
    {
      id: 'SCAN-102',
      date: '25 Sep 2026, 09:42 PM',
      cluster: 'production-demo',
      files: '6 files',
      score: 68,
      critical: 3,
      high: 7,
      status: 'Completed',
    },
    {
      id: 'SCAN-101',
      date: '24 Sep 2026, 03:15 PM',
      cluster: 'production-demo',
      files: '4 files',
      score: 62,
      critical: 4,
      high: 8,
      status: 'Completed',
    },
    {
      id: 'SCAN-100',
      date: '22 Sep 2026, 11:30 AM',
      cluster: 'staging-k8s',
      files: '2 files',
      score: 84,
      critical: 1,
      high: 3,
      status: 'Completed',
    },
    {
      id: 'SCAN-099',
      date: '18 Sep 2026, 08:20 PM',
      cluster: 'development-cluster',
      files: '3 files',
      score: 91,
      critical: 0,
      high: 2,
      status: 'Completed',
    },
  ]);

  const [benchmarkStats, setBenchmarkStats] = useState<BenchmarkStats>(INITIAL_BENCHMARK_STATS);
  const [securityEvents, setSecurityEvents] = useState<SecurityBenchmarkEvent[]>(INITIAL_BENCHMARK_EVENTS);
  const [selectedEvent, setSelectedEvent] = useState<SecurityBenchmarkEvent | null>(null);

  useEffect(() => {
    fetch('/api/scans/history')
      .then((res) => res.json())
      .then((data) => {
        if (data.success && data.history && data.history.length > 0) {
          setClusterHistory(data.history);
        }
      })
      .catch(() => {});

    fetch('/api/benchmark/events')
      .then((res) => res.json())
      .then((data) => {
        if (data.success) {
          if (data.stats) setBenchmarkStats(data.stats);
          if (data.events) setSecurityEvents(data.events);
        }
      })
      .catch(() => {});
  }, []);

  return (
    <div className="space-y-6">
      {/* Title */}
      <div className="border-b border-[#263244] pb-4 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-[#F8FAFC] sm:text-2xl flex items-center gap-2">
            <History className="h-6 w-6 text-[#00D4FF]" />
            <span>Audit History & Security Benchmark</span>
          </h1>
          <p className="mt-1 text-xs text-[#94A3B8]">
            Cluster posture revisions, threat audit log, and file security validation event records.
          </p>
        </div>

        {/* Tab Switcher */}
        <div className="flex rounded-lg border border-[#263244] bg-[#0D1320] p-1">
          <button
            onClick={() => setActiveTab('history')}
            className={`rounded-md px-3.5 py-1.5 text-xs font-semibold transition-all ${
              activeTab === 'history'
                ? 'bg-[#00D4FF] text-[#070B14] shadow-[0_0_12px_rgba(0,212,255,0.3)]'
                : 'text-[#94A3B8] hover:text-[#F8FAFC]'
            }`}
          >
            Cluster Scan Audits
          </button>
          <button
            onClick={() => setActiveTab('benchmark')}
            className={`rounded-md px-3.5 py-1.5 text-xs font-semibold transition-all ${
              activeTab === 'benchmark'
                ? 'bg-[#00D4FF] text-[#070B14] shadow-[0_0_12px_rgba(0,212,255,0.3)]'
                : 'text-[#94A3B8] hover:text-[#F8FAFC]'
            }`}
          >
            Security Benchmark Events
          </button>
        </div>
      </div>

      {/* TAB 1: Cluster Scan Audits */}
      {activeTab === 'history' && (
        <div className="space-y-4">
          <div className="overflow-hidden rounded-xl border border-[#263244] bg-[#0D1320]">
            <table className="w-full text-left text-xs">
              <thead className="border-b border-[#263244] bg-[#070B14] uppercase text-[#64748B] font-semibold tracking-wider text-[10px]">
                <tr>
                  <th className="px-4 py-3">Scan ID</th>
                  <th className="px-4 py-3">Date</th>
                  <th className="px-4 py-3">Cluster</th>
                  <th className="px-4 py-3">Files</th>
                  <th className="px-4 py-3">Score</th>
                  <th className="px-4 py-3">Critical</th>
                  <th className="px-4 py-3">High</th>
                  <th className="px-4 py-3">Status</th>
                  <th className="px-4 py-3 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#263244]">
                {clusterHistory.map((item) => (
                  <tr
                    key={item.id}
                    onClick={() => navigate('/dashboard')}
                    className="group cursor-pointer hover:bg-[#111827] transition-colors"
                  >
                    <td className="px-4 py-3 whitespace-nowrap font-mono font-bold text-[#00D4FF]">
                      {item.id}
                    </td>
                    <td className="px-4 py-3 whitespace-nowrap text-[#94A3B8]">
                      {item.date}
                    </td>
                    <td className="px-4 py-3 whitespace-nowrap font-medium text-[#F8FAFC]">
                      {item.cluster}
                    </td>
                    <td className="px-4 py-3 whitespace-nowrap font-mono text-[#64748B]">
                      {item.files}
                    </td>
                    <td className="px-4 py-3 whitespace-nowrap font-mono font-bold">
                      <span
                        className={
                          item.score >= 75
                            ? 'text-[#22C55E]'
                            : item.score >= 50
                            ? 'text-[#F59E0B]'
                            : 'text-[#EF4444]'
                        }
                      >
                        {item.score}/100
                      </span>
                    </td>
                    <td className="px-4 py-3 whitespace-nowrap font-mono font-bold text-[#EF4444]">
                      {item.critical}
                    </td>
                    <td className="px-4 py-3 whitespace-nowrap font-mono font-bold text-[#F59E0B]">
                      {item.high}
                    </td>
                    <td className="px-4 py-3 whitespace-nowrap">
                      <span className="inline-flex items-center gap-1 rounded bg-[#22C55E]/10 border border-[#22C55E]/30 px-2 py-0.5 text-[11px] font-bold text-[#22C55E]">
                        <CheckCircle2 className="h-3 w-3" />
                        {item.status}
                      </span>
                    </td>
                    <td className="px-4 py-3 whitespace-nowrap text-right text-[#64748B] group-hover:text-[#00D4FF]">
                      <ChevronRight className="h-4 w-4 inline-block transform group-hover:translate-x-0.5 transition-transform" />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* TAB 2: Security Benchmark & Event History */}
      {activeTab === 'benchmark' && (
        <div className="space-y-6">
          {/* Section 13: Security Benchmark Summary Cards */}
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-5">
            <div className="rounded-xl border border-[#263244] bg-[#0D1320] p-4 text-center">
              <span className="text-[10px] uppercase font-semibold text-[#64748B] block">Files Scanned</span>
              <span className="text-2xl font-black text-[#F8FAFC]">{benchmarkStats.filesScanned}</span>
              <span className="text-[10px] text-[#00D4FF] block mt-0.5">Ingested manifests</span>
            </div>

            <div className="rounded-xl border border-[#22C55E]/30 bg-[#0D1320] p-4 text-center">
              <span className="text-[10px] uppercase font-semibold text-[#64748B] block">Files Accepted</span>
              <span className="text-2xl font-black text-[#22C55E]">{benchmarkStats.filesAccepted}</span>
              <span className="text-[10px] text-[#22C55E] block mt-0.5">Passed validation</span>
            </div>

            <div className="rounded-xl border border-[#EF4444]/30 bg-[#0D1320] p-4 text-center">
              <span className="text-[10px] uppercase font-semibold text-[#64748B] block">Files Rejected</span>
              <span className="text-2xl font-black text-[#EF4444]">{benchmarkStats.filesRejected}</span>
              <span className="text-[10px] text-[#EF4444] block mt-0.5">Blocked by filter</span>
            </div>

            <div className="rounded-xl border border-[#EF4444]/40 bg-[#EF4444]/10 p-4 text-center">
              <span className="text-[10px] uppercase font-semibold text-[#EF4444] block">Threats Detected</span>
              <span className="text-2xl font-black text-[#EF4444]">{benchmarkStats.threatsDetected}</span>
              <span className="text-[10px] text-[#EF4444] block mt-0.5">Reverse shells / C2</span>
            </div>

            <div className="rounded-xl border border-[#F59E0B]/30 bg-[#0D1320] p-4 text-center">
              <span className="text-[10px] uppercase font-semibold text-[#64748B] block">Warnings</span>
              <span className="text-2xl font-black text-[#F59E0B]">{benchmarkStats.warnings}</span>
              <span className="text-[10px] text-[#F59E0B] block mt-0.5">Schema deviations</span>
            </div>
          </div>

          {/* Section 12 & 14: Recent Security Events Table with User Attribution */}
          <div className="overflow-hidden rounded-xl border border-[#263244] bg-[#0D1320]">
            <div className="border-b border-[#263244] bg-[#111827] px-4 py-3 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <ShieldCheck className="h-4 w-4 text-[#00D4FF]" />
                <h3 className="text-xs font-bold uppercase tracking-wider text-[#F8FAFC]">
                  Recent Security Events & Ingestion Audit Log
                </h3>
              </div>
              <span className="text-[10px] text-[#94A3B8]">Audit-grade provenance & user attribution</span>
            </div>

            <table className="w-full text-left text-xs">
              <thead className="border-b border-[#263244] bg-[#070B14] uppercase text-[#64748B] font-semibold tracking-wider text-[10px]">
                <tr>
                  <th className="px-4 py-3">Event ID</th>
                  <th className="px-4 py-3">File Name</th>
                  <th className="px-4 py-3">Uploaded By</th>
                  <th className="px-4 py-3">Timestamp</th>
                  <th className="px-4 py-3">Result</th>
                  <th className="px-4 py-3">Security Score</th>
                  <th className="px-4 py-3">Reason / Details</th>
                  <th className="px-4 py-3">Scan ID</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#263244]">
                {securityEvents.map((ev) => (
                  <tr
                    key={ev.id}
                    onClick={() => setSelectedEvent(ev)}
                    className="cursor-pointer hover:bg-[#111827] transition-colors"
                  >
                    <td className="px-4 py-3 whitespace-nowrap font-mono font-bold text-[#00D4FF]">
                      {ev.id}
                    </td>
                    <td className="px-4 py-3 whitespace-nowrap font-mono font-bold text-[#F8FAFC]">
                      {ev.fileName}
                    </td>
                    <td className="px-4 py-3 whitespace-nowrap font-semibold text-[#00D4FF]">
                      {ev.uploadedBy}
                    </td>
                    <td className="px-4 py-3 whitespace-nowrap text-[#94A3B8]">
                      {ev.time}
                      <span className="text-[10px] text-[#64748B] ml-1">({ev.date})</span>
                    </td>
                    <td className="px-4 py-3 whitespace-nowrap">
                      <span
                        className={`rounded px-2 py-0.5 text-[10px] font-black uppercase ${
                          ev.result === 'ACCEPTED'
                            ? 'bg-[#22C55E]/15 text-[#22C55E] border border-[#22C55E]/30'
                            : ev.result === 'WARNING'
                            ? 'bg-[#F59E0B]/15 text-[#F59E0B] border border-[#F59E0B]/30'
                            : 'bg-[#EF4444]/15 text-[#EF4444] border border-[#EF4444]/30'
                        }`}
                      >
                        {ev.result}
                      </span>
                    </td>
                    <td className="px-4 py-3 whitespace-nowrap font-mono font-bold">
                      <span
                        className={
                          ev.score >= 80
                            ? 'text-[#22C55E]'
                            : ev.score >= 50
                            ? 'text-[#F59E0B]'
                            : 'text-[#EF4444]'
                        }
                      >
                        {ev.score}/100
                      </span>
                    </td>
                    <td className="px-4 py-3 text-[#94A3B8] max-w-xs truncate">
                      {ev.reason}
                    </td>
                    <td className="px-4 py-3 whitespace-nowrap font-mono text-[#64748B]">
                      {ev.scanId}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Selected Event Details Modal */}
      {selectedEvent && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-xs">
          <div className="relative w-full max-w-lg rounded-xl border border-[#263244] bg-[#0D1320] p-6 shadow-2xl space-y-4 text-xs">
            <div className="flex items-center justify-between border-b border-[#263244] pb-3">
              <div className="flex items-center gap-2">
                <ShieldCheck className="h-5 w-5 text-[#00D4FF]" />
                <h3 className="text-base font-bold text-[#F8FAFC]">Security Event #{selectedEvent.id}</h3>
              </div>
              <button
                onClick={() => setSelectedEvent(null)}
                className="text-[#94A3B8] hover:text-[#F8FAFC]"
              >
                ✕
              </button>
            </div>

            <div className="grid grid-cols-2 gap-3 rounded-lg border border-[#263244] bg-[#111827] p-3">
              <div>
                <span className="text-[10px] uppercase font-semibold text-[#64748B] block">File</span>
                <span className="font-mono font-bold text-[#F8FAFC]">{selectedEvent.fileName}</span>
              </div>
              <div>
                <span className="text-[10px] uppercase font-semibold text-[#64748B] block">Uploaded By</span>
                <span className="font-bold text-[#00D4FF]">{selectedEvent.uploadedBy}</span>
              </div>
              <div>
                <span className="text-[10px] uppercase font-semibold text-[#64748B] block">Date</span>
                <span className="text-[#F8FAFC]">{selectedEvent.date}</span>
              </div>
              <div>
                <span className="text-[10px] uppercase font-semibold text-[#64748B] block">Time</span>
                <span className="text-[#F8FAFC]">{selectedEvent.time}</span>
              </div>
              <div>
                <span className="text-[10px] uppercase font-semibold text-[#64748B] block">Result</span>
                <span
                  className={`inline-block mt-0.5 rounded px-2 py-0.5 text-[10px] font-black uppercase ${
                    selectedEvent.result === 'ACCEPTED'
                      ? 'bg-[#22C55E]/15 text-[#22C55E]'
                      : 'bg-[#EF4444]/15 text-[#EF4444]'
                  }`}
                >
                  {selectedEvent.result}
                </span>
              </div>
              <div>
                <span className="text-[10px] uppercase font-semibold text-[#64748B] block">File Security Score</span>
                <span className="font-mono font-bold text-sm text-[#F8FAFC]">{selectedEvent.score} / 100</span>
              </div>
            </div>

            <div className="rounded-lg border border-[#263244] bg-[#070B14] p-3 space-y-1">
              <span className="text-[10px] uppercase font-bold text-[#64748B] block">Validation Reason</span>
              <p className="text-[#F8FAFC] leading-relaxed">{selectedEvent.reason}</p>
            </div>

            {selectedEvent.threatDetails && (
              <div className="rounded-lg border border-[#EF4444]/40 bg-[#EF4444]/10 p-3 space-y-1">
                <span className="text-[10px] uppercase font-bold text-[#EF4444] block">Threat Signature</span>
                <p className="text-[#F8FAFC] font-mono">{selectedEvent.threatDetails}</p>
              </div>
            )}

            <div className="flex justify-end pt-2">
              <button
                onClick={() => setSelectedEvent(null)}
                className="rounded-lg bg-[#111827] border border-[#263244] px-4 py-1.5 text-xs font-semibold text-[#F8FAFC] hover:border-[#00D4FF]/40"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
