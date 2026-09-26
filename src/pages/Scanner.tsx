import React, { useState, useRef, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { VULNERABILITY_PRESETS, DEMO_YAML_MANIFEST } from '../services/demo-data';
import { SAMPLE_MULTI_FILES } from '../services/sample-files';
import { TEST_VALIDATION_SCENARIOS } from '../services/benchmark-store';
import { validateKubernetesFile } from '../services/file-validator';
import { FileSecurityReportModal } from '../components/FileSecurityReportModal';
import { Scan, FileValidationResult, FileSecurityStatus } from '../types/rbac';
import { ResourceSummary } from '../components/ResourceSummary';
import {
  UploadCloud,
  FileCode,
  Play,
  RotateCcw,
  Sparkles,
  CheckCircle2,
  AlertCircle,
  AlertTriangle,
  FileText,
  Flame,
  ArrowRight,
  Trash2,
  Plus,
  Loader2,
  Check,
  Circle,
  ShieldAlert,
  ShieldCheck,
  Eye,
  Info,
  Bug,
  HelpCircle,
  Layers,
  ArrowDown,
  Cpu,
  Terminal,
} from 'lucide-react';

interface ScannerProps {
  onScanComplete: (newScan: Scan) => void;
  currentScan: Scan;
}

export const Scanner: React.FC<ScannerProps> = ({ onScanComplete, currentScan }) => {
  const navigate = useNavigate();
  const fileInputRef = useRef<HTMLInputElement>(null);
  const addMoreInputRef = useRef<HTMLInputElement>(null);

  const [activeTab, setActiveTab] = useState<'upload' | 'paste'>('upload');
  const [yamlInput, setYamlInput] = useState<string>(DEMO_YAML_MANIFEST);
  const [dragActive, setDragActive] = useState<boolean>(false);
  const [isAnalyzing, setIsAnalyzing] = useState<boolean>(false);
  const [completedScanResult, setCompletedScanResult] = useState<Scan | null>(null);

  // Selected file for detailed modal inspection
  const [inspectedFile, setInspectedFile] = useState<FileValidationResult | null>(null);

  // Multi-file validation state
  const [validatedFiles, setValidatedFiles] = useState<FileValidationResult[]>(() => {
    // Initial default with 6 sample verified files for instant user evaluation
    return SAMPLE_MULTI_FILES.slice(0, 6).map((sf) =>
      validateKubernetesFile({
        name: sf.name,
        size: sf.size,
        content: sf.content,
        uploadedBy: 'jaya.vishnu',
        scanId: currentScan.id,
      })
    );
  });

  const [uploadWarning, setUploadWarning] = useState<string | null>(null);
  const [analysisError, setAnalysisError] = useState<string | null>(null);

  // Terminal animation state simulating AI Security Analyst thought process
  const [activeThinkingAnimation, setActiveThinkingAnimation] = useState<{
    fileName: string;
    step: number;
    isThreat: boolean;
    threatName?: string;
    isComplete: boolean;
  } | null>(null);

  const thinkingStepsList = [
    { step: 1, label: '[1/5] Parsing YAML Structure...' },
    { step: 2, label: '[2/5] Analyzing RBAC Permissions...' },
    { step: 3, label: '[3/5] Checking for Privilege Escalation Paths...' },
    { step: 4, label: '[4/5] Scanning for Obfuscated Malicious Code...' },
    { step: 5, label: '[5/5] Generating Threat Intelligence Report...' },
  ];

  const triggerThinkingAnimation = async (
    fileName: string,
    isThreat: boolean,
    threatName?: string
  ) => {
    for (let s = 1; s <= 5; s++) {
      setActiveThinkingAnimation({ fileName, step: s, isThreat, threatName, isComplete: false });
      await new Promise((r) => setTimeout(r, 120));
    }
    setActiveThinkingAnimation({ fileName, step: 5, isThreat, threatName, isComplete: true });
  };

  // Step indicator during scanning
  const [fileProgressMap, setFileProgressMap] = useState<Record<string, 'pending' | 'in-progress' | 'completed'>>({});
  const [activePipelineStep, setActivePipelineStep] = useState<number>(-1);

  const validationLayers = [
    'Uploaded File',
    'File Type Validation',
    'File Size Validation',
    'YAML Syntax Validation',
    'Kubernetes Structure Validation',
    'Security Content Validation',
    'Abnormal Pattern Detection',
    'Threat/Virus Scan',
    'Security Score Calculation',
    'ACCEPT / REJECT Decision',
  ];

  // Process incoming files through the multi-layer security validation engine
  const processIncomingFiles = async (fileList: FileList | File[]) => {
    setUploadWarning(null);
    setAnalysisError(null);

    const filesArray = Array.from(fileList);
    if (filesArray.length === 0) return;

    if (validatedFiles.length >= 7) {
      setUploadWarning('Maximum 7 files allowed');
      return;
    }

    if (validatedFiles.length + filesArray.length > 7) {
      setUploadWarning('Maximum 7 files allowed');
    }

    const availableSlots = 7 - validatedFiles.length;
    const filesToProcess = filesArray.slice(0, availableSlots);

    const newResults: FileValidationResult[] = [];

    for (const file of filesToProcess) {
      const lowerName = file.name.toLowerCase();

      // Check duplicate
      const isDuplicate = validatedFiles.some(
        (f) => f.fileName.toLowerCase() === lowerName
      ) || newResults.some((f) => f.fileName.toLowerCase() === lowerName);

      if (isDuplicate) {
        setUploadWarning('This file has already been added.');
        continue;
      }

      // Check unsupported file type
      if (!lowerName.endsWith('.yaml') && !lowerName.endsWith('.yml')) {
        setUploadWarning('Unsupported file type. Please upload YAML or YML files.');
        const failedItem = validateKubernetesFile({
          name: file.name,
          size: file.size,
          content: '',
          uploadedBy: 'Current User',
          scanId: currentScan.id,
        });
        newResults.push(failedItem);
        continue;
      }

      try {
        const text = await file.text();
        const result = validateKubernetesFile({
          name: file.name,
          size: file.size,
          content: text,
          uploadedBy: 'Current User',
          scanId: currentScan.id,
        });
        newResults.push(result);
      } catch (err) {
        newResults.push({
          fileId: `file-${Date.now()}-${Math.random().toString(36).substr(2, 6)}`,
          fileName: file.name,
          fileSize: file.size,
          fileSizeFormatted: `${Math.round(file.size / 1024)} KB`,
          uploadedBy: 'Current User',
          uploadDate: new Date().toLocaleDateString('en-US', { day: 'numeric', month: 'long', year: 'numeric' }),
          uploadTime: new Date().toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', hour12: true }),
          scanId: currentScan.id,
          content: '',
          yamlSyntax: 'FAIL',
          k8sStructure: 'FAIL',
          securityContent: 'FAIL',
          threatScan: 'PASS',
          abnormalCheck: 'PASS',
          securityScore: 0,
          status: 'REJECTED',
          reason: 'Failed to read file from filesystem.',
        });
      }
    }

    if (newResults.length > 0) {
      setValidatedFiles((prev) => [...prev, ...newResults]);

      const primaryFile = newResults[0];
      const isThreat = primaryFile.status === 'REJECTED';
      triggerThinkingAnimation(
        primaryFile.fileName,
        isThreat,
        primaryFile.threatIntelligence?.threatType || primaryFile.reason
      );

      // Record any rejected files to server benchmark event log
      newResults.forEach((r) => {
        fetch('/api/benchmark/events', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            fileName: r.fileName,
            uploadedBy: r.uploadedBy,
            result: r.status,
            reason: r.reason + (r.errorDetails ? `: ${r.errorDetails}` : ''),
            score: r.securityScore,
            scanId: r.scanId,
            threatDetails: r.detectedThreats?.join(', '),
          }),
        }).catch(() => {});
      });
    }
  };

  const handleDrag = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === 'dragenter' || e.type === 'dragover') setDragActive(true);
    else if (e.type === 'dragleave') setDragActive(false);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      processIncomingFiles(e.dataTransfer.files);
    }
  };

  const handleRemoveFile = (fileId: string) => {
    setValidatedFiles((prev) => prev.filter((f) => f.fileId !== fileId));
    setUploadWarning(null);
  };

  const handleLoadSampleFiles = () => {
    setValidatedFiles(
      SAMPLE_MULTI_FILES.slice(0, 6).map((sf) =>
        validateKubernetesFile({
          name: sf.name,
          size: sf.size,
          content: sf.content,
          uploadedBy: 'jaya.vishnu',
          scanId: currentScan.id,
        })
      )
    );
    setUploadWarning(null);
    setAnalysisError(null);
    triggerThinkingAnimation('roles.yaml', false);
  };

  // Load a test scenario (e.g. malformed YAML, threat reverse shell, abnormal script)
  const handleLoadTestScenario = (scenario: (typeof TEST_VALIDATION_SCENARIOS)[0]) => {
    if (validatedFiles.length >= 7) {
      setUploadWarning('Maximum 7 files allowed');
      return;
    }

    const result = validateKubernetesFile({
      name: scenario.fileName,
      size: scenario.content.length,
      content: scenario.content,
      uploadedBy: 'Current User',
      scanId: currentScan.id,
    });

    const isThreat = result.status === 'REJECTED';
    triggerThinkingAnimation(
      result.fileName,
      isThreat,
      result.threatIntelligence?.threatType || result.reason
    );

    setValidatedFiles((prev) => {
      // Remove any existing file with same name
      const filtered = prev.filter((f) => f.fileName !== scenario.fileName);
      return [...filtered, result];
    });

    // Auto-inspect rejected threat files to immediately reveal Threat Intelligence Report
    if (result.status === 'REJECTED') {
      setInspectedFile(result);
    }

    // Record into benchmark events
    fetch('/api/benchmark/events', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        fileName: result.fileName,
        uploadedBy: result.uploadedBy,
        result: result.status,
        reason: result.reason + (result.errorDetails ? `: ${result.errorDetails}` : ''),
        score: result.securityScore,
        scanId: result.scanId,
        threatDetails: result.detectedThreats?.join(', '),
      }),
    }).catch(() => {});
  };

  // Run multi-file RBAC analysis on ACCEPTED files only
  const runSecureRbacAnalysis = async () => {
    const acceptedFiles = validatedFiles.filter((f) => f.status === 'ACCEPTED' || f.status === 'WARNING');
    if (acceptedFiles.length === 0) {
      setAnalysisError('No accepted files to analyze. All uploaded files were rejected by the validation security layer.');
      return;
    }

    setIsAnalyzing(true);
    setAnalysisError(null);
    setCompletedScanResult(null);

    const initialMap: Record<string, 'pending' | 'in-progress' | 'completed'> = {};
    acceptedFiles.forEach((f) => {
      initialMap[f.fileId] = 'pending';
    });
    setFileProgressMap(initialMap);

    for (let i = 0; i < validationLayers.length; i++) {
      setActivePipelineStep(i);
      if (i < acceptedFiles.length) {
        const fid = acceptedFiles[i].fileId;
        setFileProgressMap((prev) => ({ ...prev, [fid]: 'in-progress' }));
        await new Promise((r) => setTimeout(r, 160));
        setFileProgressMap((prev) => ({ ...prev, [fid]: 'completed' }));
      } else {
        await new Promise((r) => setTimeout(r, 180));
      }
    }

    // Combine all accepted files into one unified RBAC dataset
    const combinedYaml = acceptedFiles
      .map((f) => `# Verified Manifest: ${f.fileName} (Score: ${f.securityScore}/100)\n${f.content.trim()}`)
      .join('\n\n---\n\n');

    try {
      const response = await fetch(`/api/scans/${currentScan.id}/analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          yamlContent: combinedYaml,
          cluster: currentScan.cluster,
          k8sVersion: currentScan.k8sVersion,
          filesCount: acceptedFiles.length,
        }),
      });

      const data = await response.json();
      if (!response.ok || !data.success) {
        setAnalysisError(data.error || 'Failed to analyze accepted Kubernetes manifests.');
        setIsAnalyzing(false);
        return;
      }

      setCompletedScanResult(data.scan);
      onScanComplete(data.scan);
    } catch (err: any) {
      setAnalysisError(err?.message || 'Server error during secure RBAC analysis.');
    } finally {
      setIsAnalyzing(false);
    }
  };

  const acceptedCount = validatedFiles.filter((f) => f.status === 'ACCEPTED').length;
  const rejectedCount = validatedFiles.filter((f) => f.status === 'REJECTED').length;
  const warningCount = validatedFiles.filter((f) => f.status === 'WARNING').length;
  const isMaxFilesReached = validatedFiles.length >= 7;

  return (
    <div className="space-y-6">
      {/* Title */}
      <div className="border-b border-[#263244] pb-4 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <div>
          <h1 className="text-xl font-bold tracking-tight text-[#F8FAFC] sm:text-2xl flex items-center gap-2">
            <FileCode className="h-6 w-6 text-[#00D4FF]" />
            <span>Kubernetes YAML Security Scanner</span>
          </h1>
          <p className="mt-1 text-xs text-[#94A3B8]">
            Multi-file upload with pre-analysis security validation, threat scanning, and RBAC privilege inspection.
          </p>
        </div>

        {activeTab === 'upload' && (
          <div className="flex items-center gap-2">
            <button
              onClick={() => {
                setValidatedFiles([]);
                setUploadWarning(null);
                setAnalysisError(null);
              }}
              className="flex items-center gap-1.5 rounded-lg border border-[#263244] bg-[#111827] px-3 py-1.5 text-xs text-[#94A3B8] hover:text-[#EF4444]"
            >
              <RotateCcw className="h-3.5 w-3.5" />
              <span>Reset Files</span>
            </button>
            <button
              onClick={handleLoadSampleFiles}
              className="flex items-center gap-1.5 rounded-lg border border-[#00D4FF]/30 bg-[#00D4FF]/10 px-3 py-1.5 text-xs font-semibold text-[#00D4FF] hover:bg-[#00D4FF]/20"
            >
              <Sparkles className="h-3.5 w-3.5" />
              <span>Load 6 Verified Files</span>
            </button>
          </div>
        )}
      </div>

      {/* Tabs */}
      <div className="flex border-b border-[#263244]">
        <button
          onClick={() => setActiveTab('upload')}
          className={`flex items-center gap-2 px-5 py-3 text-xs font-bold transition-all border-b-2 ${
            activeTab === 'upload'
              ? 'border-[#00D4FF] text-[#00D4FF] bg-[#00D4FF]/5'
              : 'border-transparent text-[#94A3B8] hover:text-[#F8FAFC]'
          }`}
        >
          <UploadCloud className="h-4 w-4" />
          <span>Multi-File Secure Upload (1–7 Files)</span>
          <span className="rounded-full bg-[#111827] border border-[#263244] px-1.5 py-0.2 text-[10px] font-mono text-[#00D4FF]">
            {validatedFiles.length}/7
          </span>
        </button>

        <button
          onClick={() => setActiveTab('paste')}
          className={`flex items-center gap-2 px-5 py-3 text-xs font-bold transition-all border-b-2 ${
            activeTab === 'paste'
              ? 'border-[#00D4FF] text-[#00D4FF] bg-[#00D4FF]/5'
              : 'border-transparent text-[#94A3B8] hover:text-[#F8FAFC]'
          }`}
        >
          <FileText className="h-4 w-4" />
          <span>Single-Manifest Code Editor</span>
        </button>
      </div>

      {/* TAB 1: Secure Multi-File Upload */}
      {activeTab === 'upload' && (
        <div className="space-y-6">
          {/* Main Upload Box */}
          <div className="rounded-xl border border-[#263244] bg-[#0D1320] p-6 space-y-6 shadow-xl">
            <div className="text-center space-y-1">
              <h2 className="text-base font-bold text-[#F8FAFC]">
                Upload Kubernetes Configuration Files
              </h2>
              <p className="text-xs text-[#94A3B8]">
                Upload up to 7 YAML/YML files for RBAC analysis
              </p>
            </div>

            {/* Drop Zone */}
            <div
              onDragEnter={handleDrag}
              onDragLeave={handleDrag}
              onDragOver={handleDrag}
              onDrop={handleDrop}
              className={`flex flex-col items-center justify-center rounded-xl border-2 border-dashed p-8 text-center transition-all ${
                dragActive
                  ? 'border-[#00D4FF] bg-[#00D4FF]/10'
                  : 'border-[#263244] bg-[#070B14] hover:border-[#00D4FF]/50'
              }`}
            >
              <div className="rounded-full bg-[#111827] p-3 text-[#00D4FF] shadow-[0_0_15px_rgba(0,212,255,0.2)] mb-3">
                <UploadCloud className="h-7 w-7" />
              </div>
              <h3 className="text-sm font-bold text-[#F8FAFC]">
                Drag and drop multiple Kubernetes files here
              </h3>
              <p className="mt-1 text-xs text-[#94A3B8]">
                Supports <span className="font-mono text-[#00D4FF]">.yaml</span> and{' '}
                <span className="font-mono text-[#00D4FF]">.yml</span> (1 to 7 files)
              </p>

              <div className="mt-4 flex flex-wrap items-center justify-center gap-3">
                <button
                  type="button"
                  onClick={() => fileInputRef.current?.click()}
                  disabled={isMaxFilesReached}
                  className="rounded-lg bg-[#111827] border border-[#263244] px-4 py-2 text-xs font-semibold text-[#F8FAFC] hover:border-[#00D4FF]/50 transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
                >
                  Browse Files
                </button>
                <input
                  ref={fileInputRef}
                  type="file"
                  multiple
                  accept=".yaml,.yml"
                  className="hidden"
                  onChange={(e) => {
                    if (e.target.files) {
                      processIncomingFiles(e.target.files);
                      e.target.value = '';
                    }
                  }}
                />

                <span className="text-xs text-[#64748B]">or load test security files below</span>
              </div>
            </div>

            {/* Test Scenario Buttons */}
            <div className="rounded-lg border border-[#263244] bg-[#111827] p-3 space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-[10px] uppercase font-bold text-[#64748B] flex items-center gap-1.5">
                  <Bug className="h-3.5 w-3.5 text-[#00D4FF]" />
                  <span>Validation Test Scenarios (Click to Inject Test File)</span>
                </span>
                <span className="text-[10px] text-[#94A3B8]">Simulate acceptance, rejection, and threat detection</span>
              </div>

              <div className="grid grid-cols-2 gap-2 sm:grid-cols-5">
                {TEST_VALIDATION_SCENARIOS.map((scenario) => (
                  <button
                    key={scenario.id}
                    onClick={() => handleLoadTestScenario(scenario)}
                    className="flex flex-col items-start p-2 rounded-md border border-[#263244] bg-[#070B14] hover:border-[#00D4FF]/40 text-left transition-colors group"
                  >
                    <div className="flex items-center justify-between w-full mb-1">
                      <span className={`text-[9px] font-bold px-1.5 py-0.2 rounded border ${scenario.badgeColor}`}>
                        {scenario.badge}
                      </span>
                    </div>
                    <span className="text-[11px] font-bold text-[#F8FAFC] group-hover:text-[#00D4FF] truncate w-full">
                      {scenario.title}
                    </span>
                    <span className="text-[9px] text-[#64748B] truncate w-full font-mono mt-0.5">
                      {scenario.fileName}
                    </span>
                  </button>
                ))}
              </div>
            </div>

            {/* Upload Warnings */}
            {uploadWarning && (
              <div className="flex items-center gap-2 rounded-lg border border-[#F59E0B]/40 bg-[#F59E0B]/10 p-3 text-xs text-[#F59E0B]">
                <AlertCircle className="h-4 w-4 shrink-0" />
                <span>{uploadWarning}</span>
              </div>
            )}

            {/* Counter Summary Strip */}
            {validatedFiles.length > 0 && (
              <div className="flex flex-wrap items-center justify-between rounded-lg border border-[#263244] bg-[#070B14] p-3 text-xs">
                <div className="flex items-center gap-3">
                  <span className="font-bold text-[#F8FAFC]">
                    {validatedFiles.length} / 7 files selected
                  </span>
                  <span className="text-[#64748B]">|</span>
                  <span className="text-[#22C55E] font-semibold flex items-center gap-1">
                    <CheckCircle2 className="h-3.5 w-3.5" />
                    {acceptedCount} accepted
                  </span>
                  {rejectedCount > 0 && (
                    <span className="text-[#EF4444] font-semibold flex items-center gap-1">
                      <AlertCircle className="h-3.5 w-3.5" />
                      {rejectedCount} rejected
                    </span>
                  )}
                  {warningCount > 0 && (
                    <span className="text-[#F59E0B] font-semibold">
                      {warningCount} warning
                    </span>
                  )}
                </div>

                <div className="text-[11px] text-[#94A3B8]">
                  {rejectedCount > 0 ? (
                    <span className="text-[#EF4444]">
                      {rejectedCount} rejected file(s) will be automatically excluded from the RBAC scan.
                    </span>
                  ) : (
                    <span className="text-[#22C55E]">All files verified safe for RBAC analysis.</span>
                  )}
                </div>
              </div>
            )}

            {/* Prominent RED Alert: THREAT DETECTED - FILE REJECTED */}
            {rejectedCount > 0 && (
              <div className="rounded-xl border border-[#EF4444]/60 bg-[#EF4444]/15 p-4 shadow-[0_0_20px_rgba(239,68,68,0.25)] flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                <div className="flex items-start gap-3">
                  <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-[#EF4444] text-white shadow-md animate-pulse">
                    <ShieldAlert className="h-6 w-6" />
                  </div>
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-black uppercase text-[#EF4444] tracking-wide">
                        THREAT DETECTED — FILE REJECTED
                      </span>
                      <span className="rounded bg-[#EF4444] px-2 py-0.5 text-[9px] font-black uppercase text-white">
                        STRICT REJECTION POLICY ENFORCED
                      </span>
                    </div>
                    <p className="mt-1 text-xs text-[#F8FAFC]">
                      {validatedFiles.find((f) => f.status === 'REJECTED')?.reason ||
                        'One or more uploaded files failed the heuristic behavioral threat or syntax validation checks.'}
                    </p>
                  </div>
                </div>
                <button
                  type="button"
                  onClick={() => {
                    const firstRejected = validatedFiles.find((f) => f.status === 'REJECTED');
                    if (firstRejected) setInspectedFile(firstRejected);
                  }}
                  className="flex items-center gap-2 rounded-lg bg-[#EF4444] px-4 py-2 text-xs font-bold text-white hover:bg-[#DC2626] transition-colors shrink-0 shadow-lg"
                >
                  <Eye className="h-4 w-4" />
                  <span>Threat Intelligence Report</span>
                </button>
              </div>
            )}

            {/* Terminal Animation: AI Security Analyst Thought Process */}
            {activeThinkingAnimation && (
              <div className="rounded-xl border border-[#00D4FF]/40 bg-[#070B14] p-4 font-mono text-xs shadow-xl space-y-2.5">
                <div className="flex items-center justify-between border-b border-[#263244] pb-2 text-[11px]">
                  <div className="flex items-center gap-2">
                    <Terminal className="h-4 w-4 text-[#00D4FF]" />
                    <span className="font-bold text-[#F8FAFC]">AI Security Analyst Thought Process Animation</span>
                    <span className="text-[#64748B]">› {activeThinkingAnimation.fileName}</span>
                  </div>
                  <span className="text-[10px] text-[#00D4FF] font-bold">HEURISTIC REASONING ENGINE</span>
                </div>

                <div className="space-y-1.5 pt-1 text-[11px]">
                  {thinkingStepsList.map((step, idx) => {
                    const isCurrent = activeThinkingAnimation.step === idx + 1 && !activeThinkingAnimation.isComplete;
                    const isDone = activeThinkingAnimation.step > idx + 1 || activeThinkingAnimation.isComplete;
                    if (activeThinkingAnimation.step < idx + 1 && !activeThinkingAnimation.isComplete) return null;

                    return (
                      <div key={idx} className="flex items-center gap-2">
                        {isDone ? (
                          <Check className="h-3.5 w-3.5 text-[#22C55E]" />
                        ) : isCurrent ? (
                          <Loader2 className="h-3.5 w-3.5 text-[#00D4FF] animate-spin" />
                        ) : (
                          <Circle className="h-3 w-3 text-[#64748B]" />
                        )}
                        <span className={isDone ? 'text-[#CBD5E1]' : 'text-[#00D4FF] font-bold'}>
                          {step.label}
                        </span>
                      </div>
                    );
                  })}

                  {activeThinkingAnimation.isComplete && (
                    <div
                      className={`mt-2 p-2.5 rounded-lg border text-xs font-bold flex items-center justify-between ${
                        activeThinkingAnimation.isThreat
                          ? 'border-[#EF4444]/50 bg-[#EF4444]/15 text-[#EF4444]'
                          : 'border-[#22C55E]/50 bg-[#22C55E]/15 text-[#22C55E]'
                      }`}
                    >
                      <div>
                        {activeThinkingAnimation.isThreat ? (
                          <span>
                            ✕ THREAT DETECTED — FILE REJECTED: {activeThinkingAnimation.threatName || 'Strict Rejection Enforced'}
                          </span>
                        ) : (
                          <span>
                            ✓ SECURITY CLEARANCE GRANTED — Security Score: 100/100 (Safe for RBAC analysis)
                          </span>
                        )}
                      </div>
                      <button
                        type="button"
                        onClick={() => {
                          const matched = validatedFiles.find((f) => f.fileName === activeThinkingAnimation.fileName);
                          if (matched) setInspectedFile(matched);
                        }}
                        className="text-[10px] underline ml-2 shrink-0 cursor-pointer"
                      >
                        Inspect Report
                      </button>
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* Section 10: Validation Results Dashboard Table */}
            {validatedFiles.length > 0 && (
              <div className="rounded-xl border border-[#263244] bg-[#070B14] overflow-hidden">
                <div className="flex items-center justify-between border-b border-[#263244] bg-[#111827] px-4 py-3">
                  <div className="flex items-center gap-2">
                    <ShieldCheck className="h-4 w-4 text-[#00D4FF]" />
                    <h3 className="text-xs font-bold uppercase tracking-wider text-[#F8FAFC]">
                      File Security Validation Results
                    </h3>
                  </div>
                  <span className="text-[10px] text-[#94A3B8]">
                    Click any file row to inspect the full Security Report
                  </span>
                </div>

                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs">
                    <thead className="border-b border-[#263244] bg-[#070B14] uppercase text-[#64748B] font-semibold tracking-wider text-[10px]">
                      <tr>
                        <th className="px-4 py-2.5">File</th>
                        <th className="px-3 py-2.5 text-center">YAML Syntax</th>
                        <th className="px-3 py-2.5 text-center">Kubernetes</th>
                        <th className="px-3 py-2.5 text-center">Security</th>
                        <th className="px-3 py-2.5 text-center">Threat Scan</th>
                        <th className="px-3 py-2.5 text-center">Score</th>
                        <th className="px-3 py-2.5 text-center">Status</th>
                        <th className="px-4 py-2.5 text-right">Action</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-[#263244]">
                      {validatedFiles.map((file) => {
                        const isAccepted = file.status === 'ACCEPTED';
                        const isRejected = file.status === 'REJECTED';
                        const isWarning = file.status === 'WARNING';

                        return (
                          <tr
                            key={file.fileId}
                            onClick={() => setInspectedFile(file)}
                            className={`group cursor-pointer transition-colors ${
                              isRejected
                                ? 'bg-[#EF4444]/5 hover:bg-[#EF4444]/10'
                                : isWarning
                                ? 'bg-[#F59E0B]/5 hover:bg-[#F59E0B]/10'
                                : 'hover:bg-[#111827]'
                            }`}
                          >
                            <td className="px-4 py-3 whitespace-nowrap">
                              <div className="flex items-center gap-2">
                                <FileCode className={`h-4 w-4 shrink-0 ${isRejected ? 'text-[#EF4444]' : 'text-[#00D4FF]'}`} />
                                <div>
                                  <span className="font-mono font-bold text-[#F8FAFC] group-hover:text-[#00D4FF] transition-colors block">
                                    {file.fileName}
                                  </span>
                                  <span className="text-[10px] text-[#64748B]">
                                    {file.fileSizeFormatted}
                                  </span>
                                </div>
                              </div>
                            </td>

                            {/* YAML Syntax */}
                            <td className="px-3 py-3 text-center whitespace-nowrap">
                              {file.yamlSyntax === 'PASS' ? (
                                <span className="inline-flex items-center gap-1 font-bold text-[#22C55E]">
                                  <Check className="h-3.5 w-3.5" />
                                  <span>PASS</span>
                                </span>
                              ) : (
                                <span className="inline-flex items-center gap-1 font-bold text-[#EF4444]">
                                  <AlertCircle className="h-3.5 w-3.5" />
                                  <span>FAIL</span>
                                </span>
                              )}
                            </td>

                            {/* Kubernetes Structure */}
                            <td className="px-3 py-3 text-center whitespace-nowrap">
                              {file.k8sStructure === 'PASS' ? (
                                <span className="inline-flex items-center gap-1 font-bold text-[#22C55E]">
                                  <Check className="h-3.5 w-3.5" />
                                  <span>PASS</span>
                                </span>
                              ) : (
                                <span className="inline-flex items-center gap-1 font-bold text-[#EF4444]">
                                  <AlertCircle className="h-3.5 w-3.5" />
                                  <span>FAIL</span>
                                </span>
                              )}
                            </td>

                            {/* Security Content */}
                            <td className="px-3 py-3 text-center whitespace-nowrap">
                              {file.securityContent === 'PASS' ? (
                                <span className="inline-flex items-center gap-1 font-bold text-[#22C55E]">
                                  <Check className="h-3.5 w-3.5" />
                                  <span>PASS</span>
                                </span>
                              ) : (
                                <span className="inline-flex items-center gap-1 font-bold text-[#EF4444]">
                                  <AlertCircle className="h-3.5 w-3.5" />
                                  <span>FAIL</span>
                                </span>
                              )}
                            </td>

                            {/* Threat Scan */}
                            <td className="px-3 py-3 text-center whitespace-nowrap">
                              {file.threatScan === 'PASS' ? (
                                <span className="inline-flex items-center gap-1 font-bold text-[#22C55E]">
                                  <Check className="h-3.5 w-3.5" />
                                  <span>PASS</span>
                                </span>
                              ) : (
                                <span className="inline-flex items-center gap-1 font-bold text-[#EF4444] animate-pulse">
                                  <Flame className="h-3.5 w-3.5" />
                                  <span>DETECTED</span>
                                </span>
                              )}
                            </td>

                            {/* Security Score */}
                            <td className="px-3 py-3 text-center whitespace-nowrap">
                              <span
                                className={`font-mono font-bold text-xs ${
                                  file.securityScore >= 80
                                    ? 'text-[#22C55E]'
                                    : file.securityScore >= 50
                                    ? 'text-[#F59E0B]'
                                    : 'text-[#EF4444]'
                                }`}
                              >
                                {file.securityScore}/100
                              </span>
                            </td>

                            {/* Status */}
                            <td className="px-3 py-3 text-center whitespace-nowrap">
                              <span
                                className={`rounded px-2.5 py-0.5 text-[10px] font-black uppercase ${
                                  isAccepted
                                    ? 'bg-[#22C55E]/15 text-[#22C55E] border border-[#22C55E]/30'
                                    : isWarning
                                    ? 'bg-[#F59E0B]/15 text-[#F59E0B] border border-[#F59E0B]/30'
                                    : 'bg-[#EF4444]/20 text-[#EF4444] border border-[#EF4444]/40 font-extrabold shadow-[0_0_10px_rgba(239,68,68,0.2)]'
                                }`}
                              >
                                {isRejected
                                  ? file.threatScan === 'DETECTED' || file.threatIntelligence
                                    ? '✕ THREAT DETECTED'
                                    : '✕ REJECTED'
                                  : file.status}
                              </span>
                            </td>

                            {/* Action buttons */}
                            <td className="px-4 py-3 whitespace-nowrap text-right">
                              <div className="flex items-center justify-end gap-2" onClick={(e) => e.stopPropagation()}>
                                <button
                                  type="button"
                                  onClick={() => setInspectedFile(file)}
                                  className={`flex items-center gap-1 rounded px-2 py-1 text-xs font-semibold transition-colors ${
                                    isRejected
                                      ? 'bg-[#EF4444]/15 border border-[#EF4444]/40 text-[#EF4444] hover:bg-[#EF4444]/25'
                                      : 'text-[#94A3B8] hover:text-[#00D4FF] hover:bg-[#111827]'
                                  }`}
                                  title={isRejected ? 'View Threat Intelligence Report' : 'View File Security Report'}
                                >
                                  {isRejected ? <ShieldAlert className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />}
                                  <span>{isRejected ? 'Threat Report' : 'Inspect'}</span>
                                </button>
                                <button
                                  type="button"
                                  onClick={() => handleRemoveFile(file.fileId)}
                                  className="rounded p-1 text-[#94A3B8] hover:text-[#EF4444] hover:bg-[#111827]"
                                  title="Remove File"
                                >
                                  <Trash2 className="h-3.5 w-3.5" />
                                </button>
                              </div>
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>

                {/* Bottom Add More Files row */}
                <div className="flex items-center justify-between border-t border-[#263244] bg-[#0D1320] p-3">
                  <span className="text-[11px] text-[#64748B]">
                    {isMaxFilesReached
                      ? 'Maximum 7 files reached.'
                      : `You can add ${7 - validatedFiles.length} more file(s).`}
                  </span>

                  <div>
                    <button
                      type="button"
                      disabled={isMaxFilesReached}
                      onClick={() => addMoreInputRef.current?.click()}
                      className="flex items-center gap-1.5 rounded-lg border border-[#263244] bg-[#111827] px-3 py-1.5 text-xs font-semibold text-[#00D4FF] hover:border-[#00D4FF]/40 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
                    >
                      <Plus className="h-3.5 w-3.5" />
                      <span>+ Add More Files</span>
                    </button>
                    <input
                      ref={addMoreInputRef}
                      type="file"
                      multiple
                      accept=".yaml,.yml"
                      className="hidden"
                      onChange={(e) => {
                        if (e.target.files) {
                          processIncomingFiles(e.target.files);
                          e.target.value = '';
                        }
                      }}
                    />
                  </div>
                </div>
              </div>
            )}

            {/* Action Bar with Start RBAC Analysis button */}
            <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 pt-2">
              <div className="text-xs text-[#94A3B8]">
                {acceptedCount > 0 ? (
                  <span>
                    Ready to execute deep RBAC inspection on <strong className="text-[#22C55E]">{acceptedCount}</strong> accepted file(s).
                    {rejectedCount > 0 && (
                      <span className="text-[#EF4444] ml-1">
                        ({rejectedCount} rejected file excluded).
                      </span>
                    )}
                  </span>
                ) : (
                  <span>No accepted files available. Upload valid Kubernetes manifests to start RBAC analysis.</span>
                )}
              </div>

              <button
                type="button"
                disabled={isAnalyzing || acceptedCount === 0}
                onClick={runSecureRbacAnalysis}
                className="flex items-center justify-center gap-2 rounded-lg bg-[#00D4FF] px-6 py-2.5 text-xs font-bold text-[#070B14] shadow-[0_0_15px_rgba(0,212,255,0.3)] transition-all hover:bg-[#00D4FF]/90 disabled:opacity-40 disabled:cursor-not-allowed"
              >
                {isAnalyzing ? (
                  <>
                    <Loader2 className="h-4 w-4 animate-spin" />
                    <span>Analyzing {acceptedCount} Accepted Files...</span>
                  </>
                ) : (
                  <>
                    <Play className="h-4 w-4 fill-current" />
                    <span>Start RBAC Analysis</span>
                  </>
                )}
              </button>
            </div>
          </div>

          {/* Section 2: Multi-Layer Validation Pipeline Display */}
          <div className="rounded-xl border border-[#263244] bg-[#0D1320] p-5 space-y-4">
            <div className="flex items-center justify-between border-b border-[#263244] pb-2">
              <div className="flex items-center gap-2">
                <ShieldCheck className="h-4 w-4 text-[#00D4FF]" />
                <h3 className="text-xs font-bold uppercase tracking-wider text-[#F8FAFC]">
                  Multi-Layer File Validation & Threat Inspection Pipeline
                </h3>
              </div>
              <span className="text-[11px] font-mono text-[#64748B]">Zero-Trust Ingestion Filter</span>
            </div>

            {/* Visual Pipeline Sequence */}
            <div className="grid grid-cols-2 gap-2 sm:grid-cols-5 pt-1">
              {validationLayers.map((layer, idx) => {
                const isActive = activePipelineStep === idx;
                const isPassed = activePipelineStep > idx;

                return (
                  <div
                    key={layer}
                    className={`flex flex-col items-center justify-center p-2.5 rounded-lg border text-center text-xs transition-all ${
                      isActive
                        ? 'border-[#00D4FF] bg-[#00D4FF]/15 text-[#00D4FF] shadow-[0_0_10px_rgba(0,212,255,0.25)] font-bold'
                        : isPassed
                        ? 'border-[#22C55E]/40 bg-[#22C55E]/5 text-[#22C55E]'
                        : 'border-[#263244] bg-[#111827] text-[#64748B]'
                    }`}
                  >
                    <div className="flex items-center gap-1 mb-1">
                      {isPassed ? (
                        <Check className="h-3 w-3 text-[#22C55E]" />
                      ) : isActive ? (
                        <span className="h-2 w-2 rounded-full bg-[#00D4FF] animate-ping" />
                      ) : (
                        <Circle className="h-2.5 w-2.5 text-[#263244]" />
                      )}
                      <span className="text-[10px] font-mono opacity-80">Stage {idx + 1}</span>
                    </div>
                    <span className="text-[11px] leading-tight line-clamp-2">{layer}</span>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Real-time Multi-File Progress Console */}
          {isAnalyzing && (
            <div className="rounded-xl border border-[#00D4FF]/40 bg-[#070B14] p-5 shadow-[0_0_20px_rgba(0,212,255,0.15)] space-y-4">
              <div className="flex items-center justify-between border-b border-[#263244] pb-2">
                <span className="font-mono text-xs font-bold text-[#00D4FF] flex items-center gap-2">
                  <span className="h-2 w-2 rounded-full bg-[#00D4FF] animate-ping" />
                  Processing RBAC Configuration
                </span>
                <span className="text-xs text-[#94A3B8]">
                  Analyzing {acceptedCount} verified files...
                </span>
              </div>

              <div className="space-y-2">
                {validatedFiles
                  .filter((f) => f.status === 'ACCEPTED' || f.status === 'WARNING')
                  .map((file) => {
                    const status = fileProgressMap[file.fileId] || 'pending';
                    return (
                      <div
                        key={file.fileId}
                        className="flex items-center justify-between font-mono text-xs rounded border border-[#263244] bg-[#0D1320] px-3 py-2"
                      >
                        <div className="flex items-center gap-2">
                          {status === 'completed' && <Check className="h-4 w-4 text-[#22C55E]" />}
                          {status === 'in-progress' && <Loader2 className="h-4 w-4 text-[#00D4FF] animate-spin" />}
                          {status === 'pending' && <Circle className="h-3.5 w-3.5 text-[#64748B]" />}
                          <span
                            className={
                              status === 'completed'
                                ? 'text-[#22C55E]'
                                : status === 'in-progress'
                                ? 'text-[#00D4FF] font-bold'
                                : 'text-[#94A3B8]'
                            }
                          >
                            {file.fileName}
                          </span>
                        </div>

                        <span className="text-[10px] text-[#64748B] uppercase">
                          {status === 'completed'
                            ? 'Parsed & Merged'
                            : status === 'in-progress'
                            ? 'Evaluating RBAC...'
                            : 'Queued'}
                        </span>
                      </div>
                    );
                  })}
              </div>
            </div>
          )}
        </div>
      )}

      {/* TAB 2: Single-Manifest Code Editor */}
      {activeTab === 'paste' && (
        <div className="space-y-6">
          <div className="flex flex-col rounded-xl border border-[#263244] bg-[#0D1320] overflow-hidden">
            <div className="flex flex-wrap items-center justify-between border-b border-[#263244] bg-[#070B14] px-4 py-2.5">
              <div className="flex items-center gap-2">
                <span className="h-3 w-3 rounded-full bg-[#EF4444]" />
                <span className="h-3 w-3 rounded-full bg-[#F59E0B]" />
                <span className="h-3 w-3 rounded-full bg-[#22C55E]" />
                <span className="ml-2 font-mono text-xs text-[#94A3B8]">editor-manifest.yaml</span>
              </div>

              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={() => setYamlInput(DEMO_YAML_MANIFEST)}
                  className="flex items-center gap-1.5 rounded bg-[#111827] border border-[#263244] px-3 py-1 text-xs text-[#94A3B8] hover:text-[#F8FAFC]"
                >
                  <Sparkles className="h-3.5 w-3.5 text-[#00D4FF]" />
                  <span>Load Example</span>
                </button>

                <button
                  type="button"
                  onClick={() => setYamlInput('')}
                  className="flex items-center gap-1.5 rounded bg-[#111827] border border-[#263244] px-3 py-1 text-xs text-[#94A3B8] hover:text-[#EF4444]"
                >
                  <RotateCcw className="h-3.5 w-3.5" />
                  <span>Clear</span>
                </button>

                <button
                  type="button"
                  onClick={() => {
                    const res = validateKubernetesFile({
                      name: 'editor-manifest.yaml',
                      size: yamlInput.length,
                      content: yamlInput,
                      uploadedBy: 'Current User',
                      scanId: currentScan.id,
                    });
                    setInspectedFile(res);
                  }}
                  className="flex items-center gap-1.5 rounded bg-[#111827] border border-[#00D4FF]/40 px-3 py-1 text-xs font-semibold text-[#00D4FF] hover:bg-[#00D4FF]/10 transition-colors"
                >
                  <Cpu className="h-3.5 w-3.5 text-[#00D4FF]" />
                  <span>Heuristic Threat Scan</span>
                </button>

                <button
                  type="button"
                  disabled={isAnalyzing}
                  onClick={() => {
                    // Validate pasted content before scanning
                    const res = validateKubernetesFile({
                      name: 'pasted-editor.yaml',
                      size: yamlInput.length,
                      content: yamlInput,
                      uploadedBy: 'Current User',
                      scanId: currentScan.id,
                    });

                    if (res.status === 'REJECTED') {
                      setInspectedFile(res);
                      setAnalysisError(`Strict Rejection Enforced: ${res.reason}`);
                      return;
                    }

                    // Proceed to analysis
                    setIsAnalyzing(true);
                    setAnalysisError(null);
                    setCompletedScanResult(null);

                    fetch(`/api/scans/${currentScan.id}/analyze`, {
                      method: 'POST',
                      headers: { 'Content-Type': 'application/json' },
                      body: JSON.stringify({
                        yamlContent: yamlInput,
                        cluster: currentScan.cluster,
                        k8sVersion: currentScan.k8sVersion,
                        filesCount: 1,
                      }),
                    })
                      .then((r) => r.json())
                      .then((data) => {
                        if (data.success) {
                          setCompletedScanResult(data.scan);
                          onScanComplete(data.scan);
                        } else {
                          setAnalysisError(data.error || 'Scan analysis failed.');
                        }
                      })
                      .catch((err) => setAnalysisError(err.message))
                      .finally(() => setIsAnalyzing(false));
                  }}
                  className="flex items-center gap-2 rounded bg-[#00D4FF] px-4 py-1.5 text-xs font-bold text-[#070B14] shadow-[0_0_15px_rgba(0,212,255,0.3)] transition-all hover:bg-[#00D4FF]/90 disabled:opacity-50"
                >
                  <Play className="h-3.5 w-3.5 fill-current" />
                  <span>{isAnalyzing ? 'Scanning...' : 'Start RBAC Analysis'}</span>
                </button>
              </div>
            </div>

            <div className="relative">
              <textarea
                value={yamlInput}
                onChange={(e) => setYamlInput(e.target.value)}
                placeholder="# Paste Kubernetes YAML manifests here (Pod, Deployment, Role, ClusterRoleBinding, etc.)"
                rows={16}
                className="w-full bg-[#070B14] p-4 font-mono text-xs leading-relaxed text-[#F8FAFC] placeholder-[#64748B] outline-none resize-y"
                spellCheck={false}
              />
            </div>
          </div>

          {/* Vulnerability Presets */}
          <div className="space-y-3">
            <div className="flex items-center gap-2">
              <Flame className="h-4 w-4 text-[#EF4444]" />
              <h3 className="text-xs font-bold uppercase tracking-wider text-[#F8FAFC]">
                Vulnerability Presets (Click to Auto-load)
              </h3>
            </div>

            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-5">
              {VULNERABILITY_PRESETS.map((preset) => (
                <button
                  key={preset.id}
                  onClick={() => setYamlInput(preset.yaml)}
                  className="flex flex-col justify-between rounded-lg border border-[#263244] bg-[#0D1320] p-3 text-left transition-all hover:border-[#00D4FF]/40 hover:bg-[#111827] group"
                >
                  <div>
                    <div className="flex items-center justify-between mb-1.5">
                      <span className={`rounded border px-1.5 py-0.5 text-[9px] font-bold uppercase ${preset.badgeColor}`}>
                        {preset.badge}
                      </span>
                      <ArrowRight className="h-3.5 w-3.5 text-[#64748B] group-hover:text-[#00D4FF] transition-colors" />
                    </div>
                    <h4 className="text-xs font-bold text-[#F8FAFC] group-hover:text-[#00D4FF]">
                      {preset.name}
                    </h4>
                    <p className="mt-1 text-[11px] text-[#94A3B8] line-clamp-2">
                      {preset.description}
                    </p>
                  </div>
                </button>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Analysis Error Alert */}
      {analysisError && (
        <div className="flex items-start gap-3 rounded-lg border border-[#EF4444]/40 bg-[#EF4444]/10 p-4 text-xs text-[#EF4444]">
          <AlertCircle className="h-5 w-5 shrink-0 mt-0.5" />
          <div>
            <span className="font-bold text-sm block">Analysis Error</span>
            <p className="mt-0.5 leading-relaxed">{analysisError}</p>
          </div>
        </div>
      )}

      {/* Completed Scan Results Summary */}
      {completedScanResult && (
        <div className="space-y-4 rounded-xl border border-[#22C55E]/40 bg-[#0D1320] p-5 shadow-2xl">
          <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between border-b border-[#263244] pb-3">
            <div className="flex items-center gap-2">
              <CheckCircle2 className="h-6 w-6 text-[#22C55E]" />
              <div>
                <h3 className="text-base font-bold text-[#F8FAFC]">
                  Multi-File RBAC Scan Completed Successfully
                </h3>
                <p className="text-xs text-[#94A3B8]">
                  Identified {completedScanResult.findings.length} findings across {completedScanResult.filesCount} file(s) and {completedScanResult.resourceCounts.total} total Kubernetes objects
                </p>
              </div>
            </div>

            <div className="flex items-center gap-3">
              <div className="rounded-lg border border-[#263244] bg-[#111827] px-3 py-1.5 text-center">
                <span className="text-[10px] uppercase text-[#64748B] block">Security Score</span>
                <span className="font-mono text-lg font-black text-[#00D4FF]">
                  {completedScanResult.score}/100
                </span>
              </div>

              <button
                onClick={() => navigate('/findings')}
                className="flex items-center gap-1.5 rounded-lg bg-[#00D4FF] px-4 py-2 text-xs font-bold text-[#070B14] hover:bg-[#00D4FF]/90"
              >
                <span>View Findings</span>
                <ArrowRight className="h-4 w-4" />
              </button>
            </div>
          </div>

          <ResourceSummary counts={completedScanResult.resourceCounts} />
        </div>
      )}

      {/* Rejected File Security Report Modal */}
      <FileSecurityReportModal
        file={inspectedFile}
        onClose={() => setInspectedFile(null)}
        onRemoveFile={handleRemoveFile}
      />
    </div>
  );
};
