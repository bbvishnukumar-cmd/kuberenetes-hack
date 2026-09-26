export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'PASSED';
export type FindingStatus = 'Open' | 'Resolved' | 'Ignored';

export interface BlastRadius {
  resourceSensitivity: number;  // 0 - 100%
  permissionScope: number;      // 0 - 100%
  namespaceCriticality: number; // 0 - 100%
  privilegeEscalation: number;  // 0 - 100%
  overallScore: number;
}

export interface Finding {
  id: string;
  scanId: string;
  ruleId: string;
  title: string;
  description: string;
  severity: Severity;
  category: 'Privilege Escalation' | 'Excessive Permissions' | 'Identity Security' | 'Pod Security' | 'Resource Exposure';
  resourceKind: string;
  resourceName: string;
  namespace: string;
  identity?: string;
  permission?: string;
  status: FindingStatus;
  riskExplanation: string;
  recommendation: string;
  cisReference: string;
  mitreReference: string;
  attackPath: string[];
  blastRadius: BlastRadius;
  currentYaml: string;
  suggestedYaml: string;
  reasoning?: string[];
  potentialImpact?: string;
  createdAt: string;
}

export interface ResourceCounts {
  pods: number;
  deployments: number;
  serviceAccounts: number;
  roles: number;
  clusterRoles: number;
  roleBindings: number;
  clusterRoleBindings: number;
  secrets: number;
  namespaces: number;
  total: number;
}

export interface Scan {
  id: string;
  timestamp: string;
  cluster: string;
  k8sVersion: string;
  score: number;
  previousScore?: number;
  filesCount: number;
  rawYaml: string;
  resourceCounts: ResourceCounts;
  findings: Finding[];
  status: 'Completed' | 'Failed' | 'Running';
}

export interface RuleDefinition {
  ruleId: string;
  name: string;
  description: string;
  severity: Severity;
  category: Finding['category'];
  cisReference: string;
  mitreReference: string;
  recommendation: string;
}

export interface GraphNodeData {
  label: string;
  name: string;
  kind: string;
  namespace?: string;
  severity?: Severity;
  isPrivileged?: boolean;
  isCompromised?: boolean;
  permissions?: string[];
  risk?: string;
  metadata?: Record<string, any>;
  [key: string]: unknown;
}

export interface GraphEdgeData {
  label?: string;
  isCriticalPath?: boolean;
  [key: string]: unknown;
}

export interface AttackGraphData {
  nodes: Array<{
    id: string;
    type?: string;
    position: { x: number; y: number };
    data: GraphNodeData;
  }>;
  edges: Array<{
    id: string;
    source: string;
    target: string;
    label?: string;
    animated?: boolean;
    data?: GraphEdgeData;
    style?: Record<string, any>;
  }>;
}

export interface ExploitationStep {
  step: number;
  title: string;
  nodeId: string;
  action: string;
  privilegeGained: string;
  impact: string;
}

export interface ComplianceControl {
  framework: 'CIS Kubernetes Benchmark' | 'MITRE ATT&CK for Containers' | 'NSA/CISA Kubernetes Hardening';
  controlId: string;
  title: string;
  section: string;
  description: string;
  findingsCount: number;
  status: 'Passed' | 'Warning' | 'Failed';
  associatedRules: string[];
}

export type FileSecurityStatus = 'ACCEPTED' | 'WARNING' | 'REJECTED' | 'SCANNING';

export interface AttackChainNode {
  id: string;
  label: string;
  role: 'source' | 'escalation' | 'compromise';
  description: string;
}

export interface ThreatIntelligenceReport {
  threatType: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  category:
    | 'Privilege Escalation Chain'
    | 'Data Exfiltration Risk'
    | 'Persistence Mechanism'
    | 'Resource Hijacking'
    | 'Supply Chain Attack'
    | 'Logic Bomb / Obfuscated Code'
    | 'Suspicious Payload';
  attackVectorSteps: string[];
  remediationAdvice: string;
  thinkingTrace: string[];
  evidenceSnippet?: string;
  impactSummary: string;
  mitreTechnique?: string;
  maliciousIntent?: string;
  remediationYaml?: string;
  attackChainNodes?: AttackChainNode[];
}

export interface FileValidationResult {
  fileId: string;
  fileName: string;
  fileSize: number;
  fileSizeFormatted: string;
  uploadedBy: string;
  uploadDate: string;
  uploadTime: string;
  scanId: string;
  content: string;
  yamlSyntax: 'PASS' | 'FAIL';
  k8sStructure: 'PASS' | 'FAIL';
  securityContent: 'PASS' | 'FAIL';
  threatScan: 'PASS' | 'DETECTED';
  abnormalCheck: 'PASS' | 'DETECTED';
  securityScore: number;
  status: FileSecurityStatus;
  reason: string;
  errorDetails?: string;
  detectedThreats?: string[];
  k8sResourceCount?: number;
  threatIntelligence?: ThreatIntelligenceReport;
  aiAnalystThinkingSteps?: string[];
}

export interface SecurityBenchmarkEvent {
  id: string;
  fileName: string;
  uploadedBy: string;
  date: string;
  time: string;
  timestamp: string;
  result: 'ACCEPTED' | 'REJECTED' | 'WARNING';
  reason: string;
  score: number;
  scanId: string;
  threatDetails?: string;
}

export interface BenchmarkStats {
  filesScanned: number;
  filesAccepted: number;
  filesRejected: number;
  threatsDetected: number;
  warnings: number;
}

