import express from 'express';
import dotenv from 'dotenv';
import path from 'path';
import { GoogleGenAI } from '@google/genai';
import { parseK8sYaml } from './src/services/k8s-parser';
import { executeRbacRules, calculateSecurityScore } from './src/services/rbac-rules';
import { buildAttackGraph } from './src/services/attack-graph-builder';
import { INITIAL_DEMO_SCAN, INITIAL_DEMO_FINDINGS, DEMO_YAML_MANIFEST } from './src/services/demo-data';
import { Finding, Scan } from './src/types/rbac';
import { validateKubernetesFile } from './src/services/file-validator';
import { INITIAL_BENCHMARK_STATS, INITIAL_BENCHMARK_EVENTS } from './src/services/benchmark-store';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json({ limit: '15mb' }));
app.use(express.urlencoded({ extended: true, limit: '15mb' }));

// In-memory scan store (seeded with Demo Scan)
const scansStore = new Map<string, Scan>();
scansStore.set(INITIAL_DEMO_SCAN.id, JSON.parse(JSON.stringify(INITIAL_DEMO_SCAN)));

// In-memory benchmark store
const benchmarkEvents = [...INITIAL_BENCHMARK_EVENTS];
const benchmarkStats = { ...INITIAL_BENCHMARK_STATS };

// Gemini AI Client configuration
let aiClient: GoogleGenAI | null = null;
if (process.env.GEMINI_API_KEY) {
  try {
    aiClient = new GoogleGenAI({
      apiKey: process.env.GEMINI_API_KEY,
      httpOptions: {
        headers: {
          'User-Agent': 'aistudio-build',
        },
      },
    });
  } catch (err) {
    console.warn('Failed to initialize GoogleGenAI client:', err);
  }
}

// ----------------------------------------------------
// API ROUTES
// ----------------------------------------------------

// 1. POST /api/scans - Create new scan session
app.post('/api/scans', (req, res) => {
  const { cluster = 'production-demo', k8sVersion = 'v1.30.2', yamlContent = '' } = req.body;
  const scanId = `scan-${Date.now().toString(36)}`;

  const newScan: Scan = {
    id: scanId,
    timestamp: new Date().toLocaleDateString('en-US', {
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    }),
    cluster,
    k8sVersion,
    score: 100,
    filesCount: 1,
    rawYaml: yamlContent,
    resourceCounts: {
      pods: 0,
      deployments: 0,
      serviceAccounts: 0,
      roles: 0,
      clusterRoles: 0,
      roleBindings: 0,
      clusterRoleBindings: 0,
      secrets: 0,
      namespaces: 0,
      total: 0,
    },
    findings: [],
    status: 'Running',
  };

  scansStore.set(scanId, newScan);
  res.json({ success: true, scan: newScan });
});

// 2. POST /api/scans/:scan_id/upload - Upload or update YAML content
app.post('/api/scans/:scan_id/upload', (req, res) => {
  const { scan_id } = req.params;
  const { yamlContent, filesCount = 1 } = req.body;

  let scan = scansStore.get(scan_id);
  if (!scan) {
    scan = {
      id: scan_id,
      timestamp: new Date().toLocaleDateString('en-US', {
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
      }),
      cluster: 'production-demo',
      k8sVersion: 'v1.30.2',
      score: 100,
      filesCount,
      rawYaml: yamlContent || '',
      resourceCounts: {
        pods: 0,
        deployments: 0,
        serviceAccounts: 0,
        roles: 0,
        clusterRoles: 0,
        roleBindings: 0,
        clusterRoleBindings: 0,
        secrets: 0,
        namespaces: 0,
        total: 0,
      },
      findings: [],
      status: 'Running',
    };
    scansStore.set(scan_id, scan);
  } else {
    scan.rawYaml = yamlContent;
    scan.filesCount = filesCount;
  }

  res.json({ success: true, scanId: scan.id, filesCount: scan.filesCount });
});

// 3. POST /api/scans/:scan_id/analyze - Execute real parsing and RBAC rules
app.post('/api/scans/:scan_id/analyze', (req, res) => {
  const { scan_id } = req.params;
  const scan = scansStore.get(scan_id);

  const rawYaml = req.body.yamlContent || scan?.rawYaml || '';
  if (!rawYaml.trim()) {
    res.status(400).json({
      success: false,
      error: 'Empty YAML provided. Please upload or paste valid Kubernetes manifests.',
    });
    return;
  }

  // Parse YAML
  const parseResult = parseK8sYaml(rawYaml);
  if (!parseResult.success) {
    res.status(422).json({
      success: false,
      error: parseResult.errors?.[0] || 'Unable to parse Kubernetes manifests',
      details: parseResult.errors,
    });
    return;
  }

  // Execute RBAC Security Rules
  const findings = executeRbacRules(parseResult.resources, scan_id);
  const calculatedScore = calculateSecurityScore(findings);

  const updatedScan: Scan = {
    id: scan_id,
    timestamp: scan?.timestamp || 'Today, 09:42 PM',
    cluster: req.body.cluster || scan?.cluster || 'production-demo',
    k8sVersion: req.body.k8sVersion || scan?.k8sVersion || 'v1.30.2',
    score: calculatedScore,
    previousScore: scan?.score,
    filesCount: req.body.filesCount || scan?.filesCount || 1,
    rawYaml,
    resourceCounts: parseResult.counts,
    findings,
    status: 'Completed',
  };

  scansStore.set(scan_id, updatedScan);

  res.json({
    success: true,
    scan: updatedScan,
    resourceCounts: parseResult.counts,
    findingsCount: findings.length,
    score: calculatedScore,
  });
});

// 4. GET /api/scans/:scan_id - Get scan info
app.get('/api/scans/:scan_id', (req, res) => {
  const { scan_id } = req.params;
  const scan = scansStore.get(scan_id);

  if (!scan) {
    res.status(404).json({ success: false, error: 'Scan not found' });
    return;
  }

  res.json({ success: true, scan });
});

// 5. GET /api/scans/:scan_id/findings - List findings for scan
app.get('/api/scans/:scan_id/findings', (req, res) => {
  const { scan_id } = req.params;
  const scan = scansStore.get(scan_id);

  if (!scan) {
    res.status(404).json({ success: false, error: 'Scan not found' });
    return;
  }

  res.json({ success: true, findings: scan.findings });
});

// 6. GET /api/findings/:finding_id - Get finding detail
app.get('/api/findings/:finding_id', (req, res) => {
  const { finding_id } = req.params;

  for (const scan of scansStore.values()) {
    const finding = scan.findings.find((f) => f.id === finding_id);
    if (finding) {
      res.json({ success: true, finding, scanId: scan.id });
      return;
    }
  }

  res.status(404).json({ success: false, error: 'Finding not found' });
});

// 7. GET /api/scans/:scan_id/graph - Get attack graph and steps
app.get('/api/scans/:scan_id/graph', (req, res) => {
  const { scan_id } = req.params;
  const scan = scansStore.get(scan_id);

  if (!scan) {
    res.status(404).json({ success: false, error: 'Scan not found' });
    return;
  }

  const parseResult = parseK8sYaml(scan.rawYaml || DEMO_YAML_MANIFEST);
  const graphData = buildAttackGraph(parseResult.resources, scan.findings);

  res.json({
    success: true,
    graph: graphData.graph,
    steps: graphData.steps,
    criticalPathCount: graphData.criticalPathCount,
  });
});

// 8. POST /api/findings/:finding_id/remediate - AI Remediation with Gemini & Fallback
app.post('/api/findings/:finding_id/remediate', async (req, res) => {
  const { finding_id } = req.params;

  let targetFinding: Finding | null = null;
  let targetScan: Scan | null = null;

  for (const scan of scansStore.values()) {
    const f = scan.findings.find((item) => item.id === finding_id);
    if (f) {
      targetFinding = f;
      targetScan = scan;
      break;
    }
  }

  if (!targetFinding) {
    res.status(404).json({ success: false, error: 'Finding not found' });
    return;
  }

  // Check if Gemini API is available
  if (aiClient && process.env.GEMINI_API_KEY) {
    try {
      const prompt = `You are a Principal Kubernetes Security Engineer and RBAC Specialist.
Analyze this security finding and provide a production-grade least-privilege remediation.

Finding Details:
- Rule ID: ${targetFinding.ruleId}
- Title: ${targetFinding.title}
- Resource Kind: ${targetFinding.resourceKind}
- Resource Name: ${targetFinding.resourceName}
- Namespace: ${targetFinding.namespace}
- Severity: ${targetFinding.severity}
- Risk Description: ${targetFinding.description}

Current Manifest Snippet:
\`\`\`yaml
${targetFinding.currentYaml}
\`\`\`

Return a strictly valid JSON response matching this schema:
{
  "explanation": "Clear explanation of the privilege escalation vector and why this violates least-privilege.",
  "leastPrivilegeRecommendation": "Specific recommendation for how to scope this resource safely.",
  "correctedYaml": "Clean, syntactically valid Kubernetes YAML snippet adhering to least privilege.",
  "reasoning": [
    "Reason 1 for specific verb or resource choice",
    "Reason 2 for scoping",
    "Reason 3 for security hardening"
  ],
  "potentialImpact": "Operational impact on workloads using this configuration."
}`;

      const aiResponse = await aiClient.models.generateContent({
        model: 'gemini-3.8-flash',
        contents: prompt,
        config: {
          responseMimeType: 'application/json',
          temperature: 0.2,
        },
      });

      const text = aiResponse.text;
      if (text) {
        const parsed = JSON.parse(text);
        targetFinding.suggestedYaml = parsed.correctedYaml || targetFinding.suggestedYaml;
        targetFinding.reasoning = parsed.reasoning || targetFinding.reasoning;
        targetFinding.potentialImpact = parsed.potentialImpact || targetFinding.potentialImpact;
        targetFinding.recommendation = parsed.leastPrivilegeRecommendation || targetFinding.recommendation;

        res.json({
          success: true,
          source: 'Gemini AI (gemini-3.8-flash)',
          remediation: {
            explanation: parsed.explanation,
            recommendation: parsed.leastPrivilegeRecommendation,
            suggestedYaml: parsed.correctedYaml,
            reasoning: parsed.reasoning,
            potentialImpact: parsed.potentialImpact,
          },
        });
        return;
      }
    } catch (aiErr) {
      console.warn('Gemini AI remediation call encountered an issue, falling back to deterministic remediation engine:', aiErr);
    }
  }

  // Deterministic Fallback Engine (Guaranteed, Instant, Zero Dependency)
  res.json({
    success: true,
    source: 'Deterministic Remediation Engine',
    remediation: {
      explanation: targetFinding.riskExplanation,
      recommendation: targetFinding.recommendation,
      suggestedYaml: targetFinding.suggestedYaml,
      reasoning: targetFinding.reasoning || [
        'Enforces least privilege by replacing wildcards or superuser bindings',
        'Restricts scope to target namespace boundary',
        'Precludes unauthorized API tampering',
      ],
      potentialImpact: targetFinding.potentialImpact || 'Workloads will be restricted to designated resources and verbs.',
    },
  });
});

// 9. POST /api/scans/:scan_id/rescan - Re-evaluate after applying fix
app.post('/api/scans/:scan_id/rescan', (req, res) => {
  const { scan_id } = req.params;
  const { resolvedFindingId, updatedYaml } = req.body;

  const scan = scansStore.get(scan_id);
  if (!scan) {
    res.status(404).json({ success: false, error: 'Scan not found' });
    return;
  }

  const previousScore = scan.score;

  if (resolvedFindingId) {
    const finding = scan.findings.find((f) => f.id === resolvedFindingId);
    if (finding) {
      finding.status = 'Resolved';
    }
  }

  // Recalculate score from actual findings
  const newScore = calculateSecurityScore(scan.findings);
  scan.previousScore = previousScore;
  scan.score = newScore;

  const resolvedCount = scan.findings.filter((f) => f.status === 'Resolved').length;
  const remainingCount = scan.findings.filter((f) => f.status === 'Open').length;

  res.json({
    success: true,
    previousScore,
    newScore,
    resolvedCount,
    remainingCount,
    newCount: 0,
    scan,
  });
});

// 10. GET /api/scans/:scan_id/report - Get comprehensive report
app.get('/api/scans/:scan_id/report', (req, res) => {
  const { scan_id } = req.params;
  const scan = scansStore.get(scan_id);

  if (!scan) {
    res.status(404).json({ success: false, error: 'Scan not found' });
    return;
  }

  const criticalCount = scan.findings.filter((f) => f.severity === 'CRITICAL' && f.status === 'Open').length;
  const highCount = scan.findings.filter((f) => f.severity === 'HIGH' && f.status === 'Open').length;
  const mediumCount = scan.findings.filter((f) => f.severity === 'MEDIUM' && f.status === 'Open').length;
  const lowCount = scan.findings.filter((f) => f.severity === 'LOW' && f.status === 'Open').length;
  const resolvedCount = scan.findings.filter((f) => f.status === 'Resolved').length;

  res.json({
    success: true,
    report: {
      scanId: scan.id,
      cluster: scan.cluster,
      k8sVersion: scan.k8sVersion,
      timestamp: scan.timestamp,
      score: scan.score,
      previousScore: scan.previousScore,
      summary: {
        totalFindings: scan.findings.length,
        critical: criticalCount,
        high: highCount,
        medium: mediumCount,
        low: lowCount,
        resolved: resolvedCount,
      },
      resourceCounts: scan.resourceCounts,
      findings: scan.findings,
    },
  });
});

// 11. GET /api/scans/history - Scan History list
app.get('/api/scans/history', (req, res) => {
  const history = Array.from(scansStore.values()).map((s) => ({
    id: s.id,
    date: s.timestamp,
    cluster: s.cluster,
    files: `${s.filesCount} file(s)`,
    score: s.score,
    critical: s.findings.filter((f) => f.severity === 'CRITICAL' && f.status === 'Open').length,
    high: s.findings.filter((f) => f.severity === 'HIGH' && f.status === 'Open').length,
    status: s.status,
  }));

  res.json({ success: true, history });
});

// 12. POST /api/files/validate - Multi-Layer Secure File & Threat Validation
app.post('/api/files/validate', (req, res) => {
  const { files = [], uploadedBy = 'Current User', scanId = 'SCAN-8492' } = req.body;

  if (!Array.isArray(files) || files.length === 0) {
    res.status(400).json({ success: false, error: 'No files provided for validation.' });
    return;
  }

  const results = files.map((fileObj: any) => {
    return validateKubernetesFile({
      name: fileObj.name,
      size: fileObj.size || (fileObj.content ? Buffer.byteLength(fileObj.content, 'utf8') : 0),
      content: fileObj.content || '',
      uploadedBy,
      scanId,
    });
  });

  // Update benchmark events and metrics for rejected/suspicious or threat events
  results.forEach((r) => {
    benchmarkStats.filesScanned++;
    if (r.status === 'ACCEPTED') {
      benchmarkStats.filesAccepted++;
    } else if (r.status === 'REJECTED') {
      benchmarkStats.filesRejected++;
      if (r.threatScan === 'DETECTED') {
        benchmarkStats.threatsDetected++;
      }
    } else if (r.status === 'WARNING') {
      benchmarkStats.warnings++;
    }

    // Add security event
    benchmarkEvents.unshift({
      id: `SEC-${Date.now().toString().slice(-4)}`,
      fileName: r.fileName,
      uploadedBy: r.uploadedBy,
      date: r.uploadDate,
      time: r.uploadTime,
      timestamp: new Date().toISOString(),
      result: (r.status === 'SCANNING' ? 'WARNING' : r.status) as 'ACCEPTED' | 'REJECTED' | 'WARNING',
      reason: r.reason + (r.errorDetails ? ` (${r.errorDetails})` : ''),
      score: r.securityScore,
      scanId: r.scanId,
      threatDetails: r.detectedThreats?.join(', '),
    });
  });

  // Keep latest 50 events
  if (benchmarkEvents.length > 50) {
    benchmarkEvents.length = 50;
  }

  const acceptedCount = results.filter((r) => r.status === 'ACCEPTED').length;
  const rejectedCount = results.filter((r) => r.status === 'REJECTED').length;
  const warningCount = results.filter((r) => r.status === 'WARNING').length;

  res.json({
    success: true,
    results,
    summary: {
      total: results.length,
      accepted: acceptedCount,
      rejected: rejectedCount,
      warnings: warningCount,
    },
  });
});

// 13. GET /api/benchmark/events - Get Security Benchmark Metrics & Audit Log
app.get('/api/benchmark/events', (req, res) => {
  res.json({
    success: true,
    stats: benchmarkStats,
    events: benchmarkEvents,
  });
});

// 14. POST /api/benchmark/events - Record a security event
app.post('/api/benchmark/events', (req, res) => {
  const event = req.body;
  if (!event || !event.fileName) {
    res.status(400).json({ success: false, error: 'Invalid event data.' });
    return;
  }

  const newEvent = {
    id: event.id || `SEC-${Date.now().toString().slice(-4)}`,
    fileName: event.fileName,
    uploadedBy: event.uploadedBy || 'Current User',
    date: event.date || new Date().toLocaleDateString('en-US', { day: 'numeric', month: 'long', year: 'numeric' }),
    time: event.time || new Date().toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', hour12: true }),
    timestamp: new Date().toISOString(),
    result: event.result || 'REJECTED',
    reason: event.reason || 'Security validation triggered',
    score: typeof event.score === 'number' ? event.score : 0,
    scanId: event.scanId || 'SCAN-0000',
    threatDetails: event.threatDetails,
  };

  benchmarkEvents.unshift(newEvent);
  if (benchmarkEvents.length > 50) benchmarkEvents.length = 50;

  res.json({ success: true, event: newEvent });
});

// ----------------------------------------------------
// FRONTEND DEV / STATIC SERVING
// ----------------------------------------------------
async function setupFrontend() {
  if (process.env.NODE_ENV === 'production') {
    app.use(express.static(path.resolve('dist')));
    app.get('*', (req, res) => {
      res.sendFile(path.resolve('dist/index.html'));
    });
  } else {
    // In dev mode, mount Vite middlewares
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  }

  app.listen(Number(PORT), '0.0.0.0', () => {
    console.log(`🛡️ RBAC GUARDIAN backend running on http://0.0.0.0:${PORT}`);
  });
}

setupFrontend();
