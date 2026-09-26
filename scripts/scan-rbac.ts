import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { parseK8sYaml } from '../src/services/k8s-parser';
import { executeRbacRules, calculateSecurityScore, RULE_DEFINITIONS } from '../src/services/rbac-rules';
import type { Finding, Severity } from '../src/types/rbac';

type RuleRisk = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'NONE';
type MlRisk = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

interface MlPrediction {
  risk: MlRisk;
  modelName?: string;
  modelVersion?: string;
}

interface ScanFinding extends Finding {
  sourceFile: string;
}

interface GateResult {
  passed: boolean;
  reasons: string[];
  scoreThreshold: number;
}

interface ScanResult {
  schemaVersion: '1.0';
  generatedAt: string;
  score: number;
  scoreThreshold: number;
  ruleRisk: RuleRisk;
  mlRisk: MlRisk | null;
  ml: MlPrediction | null;
  severityCounts: Record<Severity, number>;
  findings: ScanFinding[];
  errors: Array<{ file: string; message: string }>;
  gate: GateResult;
}

function option(name: string): string | undefined {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : undefined;
}

function hasFlag(name: string): boolean {
  return process.argv.includes(name);
}

function riskFor(severityCounts: Record<Severity, number>): RuleRisk {
  if (severityCounts.CRITICAL > 0) return 'CRITICAL';
  if (severityCounts.HIGH > 0) return 'HIGH';
  if (severityCounts.MEDIUM > 0) return 'MEDIUM';
  if (severityCounts.LOW > 0) return 'LOW';
  return 'NONE';
}

function asMlPrediction(value: unknown): MlPrediction | null {
  if (!value || typeof value !== 'object') return null;
  const candidate = value as Record<string, unknown>;
  const risk = typeof candidate.risk === 'string' ? candidate.risk.toUpperCase() : '';
  if (!['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].includes(risk)) return null;
  return {
    risk: risk as MlRisk,
    ...(typeof candidate.modelName === 'string' ? { modelName: candidate.modelName } : {}),
    ...(typeof candidate.modelVersion === 'string' ? { modelVersion: candidate.modelVersion } : {}),
  };
}

function toSarif(result: ScanResult) {
  const rules = Object.values(RULE_DEFINITIONS).map((rule) => ({
    id: rule.ruleId,
    name: rule.name,
    shortDescription: { text: rule.description },
    defaultConfiguration: {
      level: rule.severity === 'CRITICAL' || rule.severity === 'HIGH' ? 'error' : 'warning',
    },
    help: { text: rule.recommendation },
    properties: { tags: [rule.category, rule.cisReference, rule.mitreReference] },
  }));

  return {
    version: '2.1.0',
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    runs: [{
      tool: { driver: { name: 'RBAC Guardian', version: '1.0', rules } },
      results: result.findings.map((finding) => ({
        ruleId: finding.ruleId,
        level: finding.severity === 'CRITICAL' || finding.severity === 'HIGH' ? 'error' : 'warning',
        message: { text: `${finding.description} Recommended fix: ${finding.recommendation}` },
        locations: [{
          physicalLocation: {
            artifactLocation: { uri: finding.sourceFile },
            // The existing parser has no trustworthy source-location mapping. Deliberately omit region.
          },
        }],
        properties: {
          severity: finding.severity,
          resourceKind: finding.resourceKind,
          resourceName: finding.resourceName,
          namespace: finding.namespace,
        },
      })),
    }],
  };
}

async function main() {
  const output = option('--output') ?? '.rbac-artifacts/security-result.json';
  const sarifOutput = option('--sarif') ?? '.rbac-artifacts/rbac-guardian.sarif';
  const fileListPath = option('--file-list');
  const threshold = Number(option('--score-threshold') ?? process.env.RBAC_SECURITY_SCORE_THRESHOLD ?? '80');
  const requireMl = hasFlag('--require-ml');
  const enforceGate = hasFlag('--enforce-gate');
  const allowEmpty = hasFlag('--allow-empty');
  const errors: Array<{ file: string; message: string }> = [];
  const findings: ScanFinding[] = [];
  const severityCounts: Record<Severity, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, PASSED: 0 };

  if (!Number.isFinite(threshold) || threshold < 0 || threshold > 100) {
    throw new Error('Security score threshold must be a number from 0 to 100.');
  }

  const files = fileListPath
    ? (await readFile(fileListPath, 'utf8')).split(/\r?\n/).map((file) => file.trim()).filter(Boolean)
    : process.argv.slice(2).filter((arg) => !arg.startsWith('--'));

  for (const file of files) {
    let yaml: string;
    try {
      yaml = await readFile(file, 'utf8');
    } catch (error) {
      errors.push({ file, message: `Unable to read manifest: ${error instanceof Error ? error.message : String(error)}` });
      continue;
    }
    const parsed = parseK8sYaml(yaml);
    if (!parsed.success) {
      errors.push({ file, message: parsed.errors?.join(' ') ?? 'Invalid Kubernetes YAML.' });
      continue;
    }
    const fileFindings = executeRbacRules(parsed.resources, `ci-${path.basename(file)}`);
    for (const finding of fileFindings) {
      severityCounts[finding.severity] += 1;
      findings.push({ ...finding, sourceFile: file.replaceAll('\\', '/') });
    }
  }

  let ml: MlPrediction | null = null;
  const mlResultPath = option('--ml-result');
  if (mlResultPath) {
    try {
      ml = asMlPrediction(JSON.parse(await readFile(mlResultPath, 'utf8')));
      if (!ml) errors.push({ file: mlResultPath, message: 'ML prediction must be JSON with risk set to CRITICAL, HIGH, MEDIUM, or LOW.' });
    } catch (error) {
      errors.push({ file: mlResultPath, message: `ML prediction could not be read: ${error instanceof Error ? error.message : String(error)}` });
    }
  }

  const score = calculateSecurityScore(findings);
  const reasons: string[] = [];
  if (errors.length > 0) reasons.push('YAML parsing or required ML analysis failed.');
  if (!allowEmpty && files.length === 0) reasons.push('No Kubernetes YAML manifests were supplied to the security scan.');
  if (severityCounts.CRITICAL > 0) reasons.push('Critical RBAC or workload security findings were detected.');
  if (score < threshold) reasons.push(`Security score ${score}/100 is below the required ${threshold}/100 threshold.`);
  if (requireMl && !ml) reasons.push('A real pre-trained ML prediction is required but was not produced.');

  const result: ScanResult = {
    schemaVersion: '1.0',
    generatedAt: new Date().toISOString(),
    score,
    scoreThreshold: threshold,
    ruleRisk: riskFor(severityCounts),
    mlRisk: ml?.risk ?? null,
    ml,
    severityCounts,
    findings,
    errors,
    gate: { passed: reasons.length === 0, reasons, scoreThreshold: threshold },
  };

  await mkdir(path.dirname(output), { recursive: true });
  await mkdir(path.dirname(sarifOutput), { recursive: true });
  await writeFile(output, `${JSON.stringify(result, null, 2)}\n`);
  await writeFile(sarifOutput, `${JSON.stringify(toSarif(result), null, 2)}\n`);
  console.log(JSON.stringify({ score, ruleRisk: result.ruleRisk, mlRisk: result.mlRisk, gate: result.gate }, null, 2));
  if (enforceGate && !result.gate.passed) process.exitCode = 1;
}

main().catch((error) => {
  console.error(error instanceof Error ? error.stack : error);
  process.exitCode = 2;
});
