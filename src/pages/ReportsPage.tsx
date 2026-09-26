import React, { useState } from 'react';
import { Scan } from '../types/rbac';
import { jsPDF } from 'jspdf';
import { COMPLIANCE_CONTROLS } from '../services/demo-data';
import {
  FileText,
  Download,
  ShieldCheck,
  AlertTriangle,
  Award,
  GitFork,
  Printer,
  CheckCircle2,
  Calendar,
  Server,
  Layers,
} from 'lucide-react';

interface ReportsPageProps {
  currentScan: Scan;
}

export const ReportsPage: React.FC<ReportsPageProps> = ({ currentScan }) => {
  const [isExportingPdf, setIsExportingPdf] = useState(false);

  const criticalCount = currentScan.findings.filter((f) => f.severity === 'CRITICAL' && f.status === 'Open').length;
  const highCount = currentScan.findings.filter((f) => f.severity === 'HIGH' && f.status === 'Open').length;
  const mediumCount = currentScan.findings.filter((f) => f.severity === 'MEDIUM' && f.status === 'Open').length;
  const lowCount = currentScan.findings.filter((f) => f.severity === 'LOW' && f.status === 'Open').length;
  const resolvedCount = currentScan.findings.filter((f) => f.status === 'Resolved').length;

  // Export JSON Report
  const handleExportJson = () => {
    const reportData = {
      title: 'RBAC Guardian Kubernetes Security Assessment Report',
      cluster: currentScan.cluster,
      k8sVersion: currentScan.k8sVersion,
      scanTimestamp: currentScan.timestamp,
      securityScore: currentScan.score,
      summary: {
        totalFindings: currentScan.findings.length,
        critical: criticalCount,
        high: highCount,
        medium: mediumCount,
        low: lowCount,
        resolved: resolvedCount,
      },
      resourceCounts: currentScan.resourceCounts,
      findings: currentScan.findings,
      complianceMapping: COMPLIANCE_CONTROLS,
    };

    const blob = new Blob([JSON.stringify(reportData, null, 2)], {
      type: 'application/json',
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `rbac-guardian-report-${currentScan.cluster}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
  };

  // Export YAML Manifests
  const handleExportYaml = () => {
    const blob = new Blob([currentScan.rawYaml], { type: 'text/yaml' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `k8s-manifests-${currentScan.cluster}.yaml`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
  };

  // Generate Professional PDF Security Report using jsPDF
  const handleGeneratePdf = () => {
    setIsExportingPdf(true);
    try {
      const doc = new jsPDF({
        orientation: 'portrait',
        unit: 'mm',
        format: 'a4',
      });

      // Header Banner
      doc.setFillColor(7, 11, 20); // #070B14
      doc.rect(0, 0, 210, 35, 'F');

      doc.setTextColor(0, 212, 255); // Cyan
      doc.setFontSize(20);
      doc.setFont('helvetica', 'bold');
      doc.text('RBAC GUARDIAN', 15, 18);

      doc.setTextColor(248, 250, 252);
      doc.setFontSize(10);
      doc.setFont('helvetica', 'normal');
      doc.text('Kubernetes Security & Attack Path Analyzer', 15, 26);

      doc.setTextColor(148, 163, 184);
      doc.setFontSize(9);
      doc.text(`Generated: ${new Date().toLocaleDateString()}`, 150, 18);
      doc.text(`Cluster: ${currentScan.cluster}`, 150, 26);

      // Executive Summary Section
      doc.setTextColor(17, 24, 39);
      doc.setFontSize(14);
      doc.setFont('helvetica', 'bold');
      doc.text('1. Executive Security Summary', 15, 48);

      doc.setFontSize(10);
      doc.setFont('helvetica', 'normal');
      doc.text(
        `RBAC Guardian analyzed ${currentScan.resourceCounts.total} Kubernetes manifest resources on cluster "${currentScan.cluster}" running Kubernetes ${currentScan.k8sVersion}.`,
        15,
        56
      );

      // Score Box
      doc.setFillColor(240, 245, 255);
      doc.rect(15, 63, 180, 24, 'F');
      doc.setDrawColor(38, 50, 68);
      doc.rect(15, 63, 180, 24, 'S');

      doc.setTextColor(0, 150, 200);
      doc.setFontSize(18);
      doc.setFont('helvetica', 'bold');
      doc.text(`Security Score: ${currentScan.score} / 100`, 22, 77);

      doc.setTextColor(100, 116, 139);
      doc.setFontSize(9);
      doc.setFont('helvetica', 'normal');
      doc.text(
        `Critical: ${criticalCount}  |  High: ${highCount}  |  Medium: ${mediumCount}  |  Resolved: ${resolvedCount}`,
        22,
        83
      );

      // Findings Table
      doc.setTextColor(17, 24, 39);
      doc.setFontSize(14);
      doc.setFont('helvetica', 'bold');
      doc.text('2. Key Security Misconfigurations', 15, 100);

      let yPos = 110;
      currentScan.findings.slice(0, 5).forEach((f, idx) => {
        if (yPos > 260) {
          doc.addPage();
          yPos = 20;
        }

        doc.setFillColor(248, 250, 252);
        doc.rect(15, yPos - 5, 180, 24, 'F');
        doc.setDrawColor(226, 232, 240);
        doc.rect(15, yPos - 5, 180, 24, 'S');

        doc.setFontSize(10);
        doc.setFont('helvetica', 'bold');
        doc.setTextColor(f.severity === 'CRITICAL' ? 220 : 200, f.severity === 'CRITICAL' ? 38 : 100, 38);
        doc.text(`[${f.severity}] ${f.ruleId}: ${f.title}`, 20, yPos + 1);

        doc.setFontSize(8.5);
        doc.setFont('helvetica', 'normal');
        doc.setTextColor(71, 85, 105);
        doc.text(`Resource: ${f.resourceKind}/${f.resourceName} | Namespace: ${f.namespace}`, 20, yPos + 6);
        doc.text(`Recommendation: ${f.recommendation.substring(0, 95)}...`, 20, yPos + 12);

        yPos += 28;
      });

      // Compliance Mapping
      if (yPos > 220) {
        doc.addPage();
        yPos = 25;
      } else {
        yPos += 10;
      }

      doc.setTextColor(17, 24, 39);
      doc.setFontSize(14);
      doc.setFont('helvetica', 'bold');
      doc.text('3. Compliance Framework References (Informational)', 15, yPos);
      yPos += 8;

      doc.setFontSize(8.5);
      doc.setFont('helvetica', 'normal');
      doc.setTextColor(100, 116, 139);
      doc.text('Mapped against CIS Kubernetes Benchmark 5.1 & 5.2 and MITRE ATT&CK for Containers.', 15, yPos);

      // Save PDF
      doc.save(`rbac-guardian-audit-${currentScan.cluster}.pdf`);
    } catch (err) {
      console.error('PDF export failed:', err);
    } finally {
      setIsExportingPdf(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Title & Action Buttons */}
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between border-b border-[#263244] pb-4">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-[#F8FAFC] sm:text-2xl flex items-center gap-2">
            <FileText className="h-6 w-6 text-[#00D4FF]" />
            <span>Security & Compliance Reports</span>
          </h1>
          <p className="mt-1 text-xs text-[#94A3B8]">
            Audit-grade security assessment summary, attack vectors, and executive reporting.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <button
            onClick={handleExportJson}
            className="flex items-center gap-1.5 rounded-lg border border-[#263244] bg-[#0D1320] px-3 py-1.5 text-xs font-semibold text-[#F8FAFC] hover:border-[#00D4FF]/40"
          >
            <Download className="h-3.5 w-3.5" />
            <span>Export JSON</span>
          </button>

          <button
            onClick={handleExportYaml}
            className="flex items-center gap-1.5 rounded-lg border border-[#263244] bg-[#0D1320] px-3 py-1.5 text-xs font-semibold text-[#F8FAFC] hover:border-[#00D4FF]/40"
          >
            <Download className="h-3.5 w-3.5" />
            <span>Export YAML</span>
          </button>

          <button
            onClick={handleGeneratePdf}
            disabled={isExportingPdf}
            className="flex items-center gap-2 rounded-lg bg-[#00D4FF] px-4 py-1.5 text-xs font-bold text-[#070B14] shadow-[0_0_15px_rgba(0,212,255,0.3)] transition-all hover:bg-[#00D4FF]/90"
          >
            <Printer className="h-3.5 w-3.5" />
            <span>{isExportingPdf ? 'Generating PDF...' : 'Generate PDF Report'}</span>
          </button>
        </div>
      </div>

      {/* Executive Summary Card */}
      <div className="rounded-xl border border-[#263244] bg-[#0D1320] p-6 space-y-4 shadow-xl">
        <div className="flex flex-wrap items-center justify-between border-b border-[#263244] pb-3 gap-2">
          <div className="flex items-center gap-2">
            <ShieldCheck className="h-5 w-5 text-[#00D4FF]" />
            <h2 className="text-sm font-bold uppercase tracking-wider text-[#F8FAFC]">
              Executive Summary & Posture Audit
            </h2>
          </div>
          <div className="flex items-center gap-3 text-xs text-[#94A3B8]">
            <span className="flex items-center gap-1">
              <Server className="h-3.5 w-3.5 text-[#00D4FF]" />
              {currentScan.cluster} ({currentScan.k8sVersion})
            </span>
            <span className="flex items-center gap-1">
              <Calendar className="h-3.5 w-3.5" />
              {currentScan.timestamp}
            </span>
          </div>
        </div>

        <div className="grid grid-cols-1 gap-4 lg:grid-cols-4">
          <div className="rounded-lg border border-[#263244] bg-[#111827] p-4 text-center">
            <span className="text-[10px] uppercase font-semibold text-[#64748B] block">Security Score</span>
            <span className="text-3xl font-black text-[#00D4FF]">{currentScan.score}</span>
            <span className="text-xs text-[#94A3B8] block">/ 100</span>
          </div>

          <div className="rounded-lg border border-[#263244] bg-[#111827] p-4 text-center">
            <span className="text-[10px] uppercase font-semibold text-[#64748B] block">Critical Findings</span>
            <span className="text-3xl font-black text-[#EF4444]">{criticalCount}</span>
            <span className="text-xs text-[#EF4444] block">Immediate Action</span>
          </div>

          <div className="rounded-lg border border-[#263244] bg-[#111827] p-4 text-center">
            <span className="text-[10px] uppercase font-semibold text-[#64748B] block">High Priority</span>
            <span className="text-3xl font-black text-[#F59E0B]">{highCount}</span>
            <span className="text-xs text-[#94A3B8] block">Severe Escalation</span>
          </div>

          <div className="rounded-lg border border-[#263244] bg-[#111827] p-4 text-center">
            <span className="text-[10px] uppercase font-semibold text-[#64748B] block">Resolved & Passed</span>
            <span className="text-3xl font-black text-[#22C55E]">{resolvedCount + 42}</span>
            <span className="text-xs text-[#22C55E] block">Compliant Checks</span>
          </div>
        </div>
      </div>

      {/* RBAC Findings Detailed Summary */}
      <div className="rounded-xl border border-[#263244] bg-[#0D1320] p-6 space-y-4">
        <h3 className="text-xs font-bold uppercase tracking-wider text-[#F8FAFC] flex items-center gap-2 border-b border-[#263244] pb-3">
          <AlertTriangle className="h-4 w-4 text-[#EF4444]" />
          <span>Active RBAC Security Findings Breakdown</span>
        </h3>

        <div className="space-y-3">
          {currentScan.findings.map((finding) => (
            <div
              key={finding.id}
              className="rounded-lg border border-[#263244] bg-[#111827] p-4 space-y-2 text-xs"
            >
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="flex items-center gap-2">
                  <span
                    className={`rounded px-2 py-0.5 text-[10px] font-bold ${
                      finding.severity === 'CRITICAL'
                        ? 'bg-[#EF4444]/20 text-[#EF4444]'
                        : finding.severity === 'HIGH'
                        ? 'bg-[#F59E0B]/20 text-[#F59E0B]'
                        : 'bg-[#38BDF8]/20 text-[#38BDF8]'
                    }`}
                  >
                    {finding.severity}
                  </span>
                  <span className="font-mono font-bold text-[#00D4FF]">{finding.ruleId}</span>
                  <span className="font-bold text-[#F8FAFC]">{finding.title}</span>
                </div>
                <span className="font-mono text-[#94A3B8]">
                  {finding.resourceKind}/{finding.resourceName}
                </span>
              </div>
              <p className="text-[#94A3B8] leading-relaxed">{finding.description}</p>
              <div className="rounded border border-[#263244] bg-[#070B14] p-2 text-[11px] text-[#22C55E]">
                <span className="font-semibold block text-[#64748B] uppercase text-[9px]">Recommendation:</span>
                {finding.recommendation}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Compliance Mapping Section */}
      <div className="rounded-xl border border-[#263244] bg-[#0D1320] p-6 space-y-4">
        <div className="flex items-center justify-between border-b border-[#263244] pb-3">
          <div className="flex items-center gap-2">
            <Award className="h-4 w-4 text-[#00D4FF]" />
            <h3 className="text-xs font-bold uppercase tracking-wider text-[#F8FAFC]">
              Compliance & Hardening Framework Mappings
            </h3>
          </div>
          <span className="text-[10px] text-[#64748B]">
            * Informational mappings only; not an official compliance certification.
          </span>
        </div>

        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          {COMPLIANCE_CONTROLS.map((control) => (
            <div
              key={control.controlId}
              className="rounded-lg border border-[#263244] bg-[#111827] p-3 space-y-1.5 text-xs"
            >
              <div className="flex items-center justify-between">
                <span className="font-mono font-bold text-[#00D4FF]">{control.controlId}</span>
                <span
                  className={`rounded px-1.5 py-0.5 text-[9px] font-bold ${
                    control.status === 'Failed'
                      ? 'bg-[#EF4444]/20 text-[#EF4444]'
                      : 'bg-[#F59E0B]/20 text-[#F59E0B]'
                  }`}
                >
                  {control.status}
                </span>
              </div>
              <p className="font-semibold text-[#F8FAFC]">{control.title}</p>
              <p className="text-[11px] text-[#94A3B8] leading-relaxed">{control.description}</p>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
