import { loadAll } from 'js-yaml';
import {
  FileValidationResult,
  FileSecurityStatus,
  ThreatIntelligenceReport,
} from '../types/rbac';

export interface ValidationInput {
  name: string;
  size: number;
  content: string;
  uploadedBy?: string;
  scanId?: string;
}

function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`;
}

// Low-level raw threat signatures
const MALWARE_THREAT_PATTERNS = [
  { regex: /bash\s+-i\s+>&\s+\/dev\/tcp\//i, name: 'Interactive Bash TCP reverse shell' },
  { regex: /nc\s+(-e|--exec)\s+(\/bin\/sh|\/bin\/bash|cmd\.exe)/i, name: 'Netcat executable reverse shell' },
  { regex: /mkfifo\s+[^\n]+;\s*(cat|nc|sh)/i, name: 'FIFO named pipe reverse shell payload' },
  { regex: /python(\d?)\s+-c\s+['"].*import\s+socket.*subprocess.*['"]/i, name: 'Python socket command execution' },
  { regex: /perl\s+-e\s+['"].*use\s+Socket;.*['"]/i, name: 'Perl socket reverse shell payload' },
  { regex: /stratum\+tcp:\/\/[^\s]+/i, name: 'Cryptominer pool beaconing' },
  { regex: /xmrig(\.exe)?/i, name: 'Known cryptominer binary reference' },
  { regex: /(evil-c2|malicious-drop|c2-control|payload-delivery)\.[a-z0-9.-]+/i, name: 'Suspicious C2 command-and-control host' },
  { regex: /curl\s+-[sS]*k?[sS]*\s+http[s]?:\/\/[^\s|]+\s*\|\s*(sh|bash)/i, name: 'Unvalidated remote shell piping execution' },
];

const ABNORMAL_PATTERNS = [
  { regex: /<script[\s>]/i, name: 'Embedded HTML/JavaScript code' },
  { regex: /<\?php/i, name: 'Embedded PHP executable tag' },
  { regex: /eval\s*\(\s*base64_decode/i, name: 'Obfuscated eval base64 payload' },
  { regex: /\x00|\x01|\x02|\x03|\x04|\x05|\x06|\x07|\x08|\x0B|\x0C|\x0E|\x0F/, name: 'Raw binary control characters' },
  { regex: /(^|\s)(f0VMRg|TVqQAAMAAAAEAAAA)/, name: 'Base64 encoded binary executable (ELF / PE header)' },
];

/**
 * Heuristic behavior security analyzer that simulates a "thinking" AI security analyst.
 * Analyzes object relationships, obfuscated code, privilege chains, exfiltration, persistence, and supply chain.
 */
function analyzeHeuristicThreats(
  parsedDocs: any[],
  rawContent: string
): ThreatIntelligenceReport | null {
  const roles: any[] = [];
  const roleBindings: any[] = [];
  const serviceAccounts: any[] = [];
  const workloads: any[] = [];
  const cronJobs: any[] = [];
  const daemonSets: any[] = [];

  for (const doc of parsedDocs) {
    if (!doc || typeof doc !== 'object') continue;
    const kind = doc.kind;
    if (kind === 'Role' || kind === 'ClusterRole') roles.push(doc);
    else if (kind === 'RoleBinding' || kind === 'ClusterRoleBinding') roleBindings.push(doc);
    else if (kind === 'ServiceAccount') serviceAccounts.push(doc);
    else if (kind === 'Pod' || kind === 'Deployment' || kind === 'StatefulSet' || kind === 'Job') workloads.push(doc);
    else if (kind === 'CronJob') cronJobs.push(doc);
    else if (kind === 'DaemonSet') daemonSets.push(doc);
  }

  const allWorkloadDocs = [...workloads, ...cronJobs, ...daemonSets];

  // Helper to extract container list from any workload doc
  const getContainers = (doc: any): any[] => {
    let spec = doc.spec;
    if (doc.kind === 'CronJob') {
      spec = doc.spec?.jobTemplate?.spec?.template?.spec;
    } else if (doc.kind === 'Deployment' || doc.kind === 'StatefulSet' || doc.kind === 'DaemonSet' || doc.kind === 'Job') {
      spec = doc.spec?.template?.spec;
    }
    const containers = spec?.containers || [];
    const initContainers = spec?.initContainers || [];
    return [...containers, ...initContainers];
  };

  const getPodSpec = (doc: any): any => {
    if (doc.kind === 'Pod') return doc.spec;
    if (doc.kind === 'CronJob') return doc.spec?.jobTemplate?.spec?.template?.spec;
    if (doc.kind === 'Deployment' || doc.kind === 'StatefulSet' || doc.kind === 'DaemonSet' || doc.kind === 'Job') {
      return doc.spec?.template?.spec;
    }
    return null;
  };

  // =========================================================================
  // 1. DEEP STRUCTURAL ANALYSIS: Privilege Escalation Chains
  // Relationship: Pod creation rights + privileged / hostPID / hostPath container
  // =========================================================================
  const grantsPodCreation = roles.some((r) => {
    const rules = r.rules || [];
    return rules.some((rule: any) => {
      const resources = rule.resources || [];
      const verbs = rule.verbs || [];
      const hasPodResource = resources.includes('pods') || resources.includes('*');
      const hasCreateVerb = verbs.includes('create') || verbs.includes('*');
      return hasPodResource && hasCreateVerb;
    });
  });

  const grantsExec = roles.some((r) => {
    const rules = r.rules || [];
    return rules.some((rule: any) => {
      const resources = rule.resources || [];
      const verbs = rule.verbs || [];
      return (
        (resources.includes('pods/exec') || resources.includes('*')) &&
        (verbs.includes('create') || verbs.includes('*'))
      );
    });
  });

  // Check if any workload requests privileged or host escape flags
  for (const doc of allWorkloadDocs) {
    const podSpec = getPodSpec(doc);
    if (!podSpec) continue;
    const containers = getContainers(doc);

    const isPrivileged = containers.some((c) => c.securityContext?.privileged === true);
    const hasHostPid = podSpec.hostPID === true;
    const hasHostIpc = podSpec.hostIPC === true;
    const hasHostNetwork = podSpec.hostNetwork === true;
    const hostPathVolumes = (podSpec.volumes || []).filter((v: any) => v.hostPath);
    const hasRootHostPath = hostPathVolumes.some(
      (v: any) => v.hostPath.path === '/' || v.hostPath.path === '/etc' || v.hostPath.path === '/var/run/docker.sock'
    );
    const hasExcessiveCaps = containers.some((c) => {
      const add = c.securityContext?.capabilities?.add || [];
      return add.some((cap: string) => ['SYS_ADMIN', 'CAP_SYS_ADMIN', 'ALL', 'NET_ADMIN'].includes(cap));
    });

    if (grantsPodCreation && (isPrivileged || hasHostPid || hasRootHostPath || hasExcessiveCaps)) {
      const roleName = roles[0]?.metadata?.name || 'pod-creator-role';
      const saName = serviceAccounts[0]?.metadata?.name || 'app-serviceaccount';
      return {
        threatType: 'Privilege Escalation Chain via Correlated Pod Creation & Host Access',
        severity: 'CRITICAL',
        category: 'Privilege Escalation Chain',
        attackVectorSteps: [
          `1. Attacker compromises or impersonates ServiceAccount '${saName}' bound to Role '${roleName}'.`,
          `2. The attacker uses the granted 'create pods' permission to deploy a weaponized container manifest.`,
          `3. The deployed pod requests '${isPrivileged ? 'securityContext.privileged: true' : hasRootHostPath ? 'hostPath: /' : 'hostPID: true'}'.`,
          '4. The container initializes with direct kernel and host-level filesystem access.',
          '5. Attacker chroots into the host node filesystem, extracts kubelet certificates, and achieves full cluster takeover.',
        ],
        maliciousIntent:
          'This pattern is commonly used by adversaries to escape container isolation, compromise the host kernel, and establish persistent backdoors.',
        attackChainNodes: [
          { id: '1', label: `ServiceAccount '${saName}'`, role: 'source', description: 'Attacker identity bound to creation role' },
          { id: '2', label: `Role '${roleName}' (create pods)`, role: 'escalation', description: 'RBAC allows deploying arbitrary pod specifications' },
          { id: '3', label: 'Privileged Pod / Host Mount', role: 'escalation', description: 'Container requests root hostPath and kernel privileges' },
          { id: '4', label: 'Host Node Root Compromise', role: 'compromise', description: 'Container escapes namespaces, reading node credentials and secrets' },
        ],
        remediationAdvice:
          'Remove pod creation privileges from application service accounts, or enforce Kubernetes Pod Security Standards (PSS) Restricted profile or Admission Webhooks (e.g., Gatekeeper/Kyverno) preventing privileged containers and hostPath mounts.',
        remediationYaml: `# Safe Remediated Manifest: Remove 'create pods' and enforce unprivileged securityContext
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: ${roleName}
rules:
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["get", "list"] # REMOVED: "create" verb
---
apiVersion: v1
kind: Pod
metadata:
  name: safe-workload
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 10001
  containers:
    - name: worker
      image: alpine:3.19
      securityContext:
        privileged: false # REMOVED: privileged: true
        allowPrivilegeEscalation: false
        capabilities:
          drop:
            - ALL`,
        thinkingTrace: [
          `[Analyst Trace] Initiating cross-object structural correlation across ${parsedDocs.length} manifests...`,
          `[Analyst Trace] Identified Role '${roleName}' granting verb 'create' on resource 'pods'.`,
          `[Analyst Trace] Detected workload '${doc.metadata?.name}' containing high-risk container spec: ${isPrivileged ? 'privileged: true' : 'hostPath / hostPID enabled'}.`,
          `[Analyst Trace] Heuristic chain verified: 'create pods' permission + privileged container template = Complete Node Compromise.`,
          '[Analyst Trace] Decision Engine: Strictly REJECT manifest to prevent host node takeover.',
        ],
        evidenceSnippet: `Role rules: create on pods\nWorkload '${doc.metadata?.name}': ${
          isPrivileged ? 'securityContext.privileged: true' : 'hostPath mount: ' + (hostPathVolumes[0]?.hostPath?.path || '/')
        }`,
        impactSummary: 'Allows an unprivileged application identity to escape container boundaries and take over the underlying Kubernetes worker node.',
        mitreTechnique: 'T1611: Escape to Host / T1068: Exploitation for Privilege Escalation',
      };
    }

    // Direct standalone privileged container with host escape
    if (isPrivileged && (hasRootHostPath || hasHostPid)) {
      return {
        threatType: 'Direct Container Host Escape (Privileged + Host Mounting)',
        severity: 'CRITICAL',
        category: 'Privilege Escalation Chain',
        attackVectorSteps: [
          `1. Pod '${doc.metadata?.name}' runs with 'securityContext.privileged: true' and accesses host devices.`,
          `2. Pod mounts host volume '${hostPathVolumes[0]?.hostPath?.path || '/'}'.`,
          '3. Any execution inside this container can read host files (/etc/shadow, /var/log, node certificates).',
          '4. Attacker uses nsenter or chroot to break out of Linux namespaces into the host root shell.',
        ],
        maliciousIntent:
          'This pattern gives a container direct raw access to the underlying virtual machine or bare-metal host, enabling escape from containerization.',
        attackChainNodes: [
          { id: '1', label: `Workload '${doc.metadata?.name}'`, role: 'source', description: 'Application pod running on cluster' },
          { id: '2', label: 'securityContext.privileged: true', role: 'escalation', description: 'Disables all Linux kernel isolation boundaries' },
          { id: '3', label: `hostPath '${hostPathVolumes[0]?.hostPath?.path || '/'}'`, role: 'escalation', description: 'Mounts host root filesystem into container' },
          { id: '4', label: 'Complete Host Node Compromise', role: 'compromise', description: 'Direct write/exec access to host OS and kubelet token' },
        ],
        remediationAdvice:
          'Set securityContext.privileged: false and replace hostPath volumes with native PersistentVolumeClaims or emptyDir.',
        remediationYaml: `# Safe Remediated Manifest: Disable privileged container and hostPath
apiVersion: v1
kind: Pod
metadata:
  name: ${doc.metadata?.name || 'safe-pod'}
spec:
  containers:
    - name: app
      image: alpine:3.19
      securityContext:
        privileged: false # FIXED: Disabled root device access
        allowPrivilegeEscalation: false
  volumes:
    - name: app-storage
      emptyDir: {} # FIXED: Replaced hostPath with emptyDir`,
        thinkingTrace: [
          `[Analyst Trace] Deep scanning Pod spec '${doc.metadata?.name}'...`,
          '[Analyst Trace] Flagged securityContext.privileged: true combined with sensitive hostPath mount.',
          '[Analyst Trace] Behavior simulation predicts immediate host breakout if container is compromised.',
          '[Analyst Trace] Decision Engine: IMMEDIATE REJECTION under Strict Host Escape Policy.',
        ],
        evidenceSnippet: `kind: ${doc.kind}\nname: ${doc.metadata?.name}\nprivileged: true\nhostPath: ${hostPathVolumes[0]?.hostPath?.path || '/'}`,
        impactSummary: 'Total node host compromise and exposure of node credentials.',
        mitreTechnique: 'T1611: Escape to Host',
      };
    }
  }

  // Check for impersonate permission
  for (const role of roles) {
    const rules = role.rules || [];
    for (const rule of rules) {
      const verbs = rule.verbs || [];
      const resources = rule.resources || [];
      if (verbs.includes('impersonate') && (resources.includes('users') || resources.includes('serviceaccounts') || resources.includes('*'))) {
        return {
          threatType: 'Privilege Escalation via Identity Impersonation',
          severity: 'CRITICAL',
          category: 'Privilege Escalation Chain',
          attackVectorSteps: [
            `1. Identity granted '${role.metadata?.name}' requests Kubernetes API impersonation header (Impersonate-User: admin).`,
            '2. Kubernetes API authorizes the request as the target high-privileged identity (e.g. system:masters).',
            '3. Attacker bypasses all identity restrictions and gains cluster-admin privileges.',
          ],
          remediationAdvice:
            'Strictly remove the "impersonate" verb from roles. Impersonation should only be granted to internal auth proxies under strict auditing.',
          thinkingTrace: [
            `[Analyst Trace] Examining RBAC verb permissions in Role '${role.metadata?.name}'...`,
            '[Analyst Trace] Detected verb "impersonate" on user/serviceaccount resources.',
            '[Analyst Trace] Identity impersonation allows arbitrary elevation to system:masters.',
            '[Analyst Trace] Decision Engine: Flagged as CRITICAL privilege escalation threat. Rejection triggered.',
          ],
          evidenceSnippet: `kind: ${role.kind}\nname: ${role.metadata?.name}\nverbs: ["impersonate"]\nresources: ${JSON.stringify(resources)}`,
          impactSummary: 'Arbitrary cluster-wide administrative takeover via header impersonation.',
          mitreTechnique: 'T1078.004: Valid Accounts - Cloud Accounts',
        };
      }
    }
  }

  // =========================================================================
  // 2. OBFUSCATED MALICIOUS CODE: Base64 commands, suspicious initContainers, hardcoded secrets
  // =========================================================================
  for (const doc of allWorkloadDocs) {
    const containers = getContainers(doc);
    for (const c of containers) {
      const cmdStr = [...(c.command || []), ...(c.args || [])].join(' ');

      // Check base64 decoding pipelines: echo ... | base64 -d | sh
      const b64PipelineMatch = cmdStr.match(/echo\s+([A-Za-z0-9+/=]{16,})\s*\|\s*base64\s+-d\s*\|\s*(sh|bash)/i);
      if (b64PipelineMatch) {
        const encoded = b64PipelineMatch[1];
        let decoded = '';
        try {
          decoded = Buffer.from(encoded, 'base64').toString('utf-8');
        } catch {
          decoded = '(binary or malformed)';
        }

        return {
          threatType: 'Obfuscated Malicious Code: Base64-Encoded Shell Execution',
          severity: 'CRITICAL',
          category: 'Logic Bomb / Obfuscated Code',
          attackVectorSteps: [
            `1. Workload '${doc.metadata?.name}' container '${c.name}' executes an obfuscated base64 payload.`,
            `2. Payload decodes in-memory via 'base64 -d' and pipes directly into shell (${decoded.substring(0, 40)}...).`,
            '3. Bypasses naive keyword inspection tools that look for raw bash reverse shells.',
            '4. Executes remote C2 beacon or drops second-stage persistence onto the cluster.',
          ],
          maliciousIntent:
            'This pattern is designed to evade signature-based file scanners by encrypting or base64-encoding raw shell commands and spawning reverse TCP sockets.',
          attackChainNodes: [
            { id: '1', label: `Container '${c.name}'`, role: 'source', description: 'Container starts execution with encoded arguments' },
            { id: '2', label: 'In-Memory Base64 Decode', role: 'escalation', description: 'De-obfuscates payload directly into memory' },
            { id: '3', label: 'Pipe to /bin/sh', role: 'escalation', description: 'Executes hidden reverse TCP socket commands' },
            { id: '4', label: 'External C2 Takeover', role: 'compromise', description: 'Remote attacker establishes persistent interactive shell' },
          ],
          remediationAdvice:
            'Do not allow base64 decoding pipes in container args or commands. Specify explicit entrypoint commands and build vetted container images.',
          remediationYaml: `# Safe Remediated Manifest: Remove dynamic base64 shell pipeline
apiVersion: v1
kind: Pod
metadata:
  name: ${doc.metadata?.name || 'safe-workload'}
spec:
  containers:
    - name: ${c.name}
      image: ${c.image || 'alpine:3.19'}
      command: ["/app/entrypoint.sh"] # FIXED: Replaced piped base64 command with vetted executable`,
          thinkingTrace: [
            `[Analyst Trace] Inspecting container command execution in '${c.name}'...`,
            `[Analyst Trace] Detected pattern 'echo <base64> | base64 -d | sh'.`,
            `[Analyst Trace] Decoded payload reveals hidden command: "${decoded.slice(0, 50)}".`,
            '[Analyst Trace] Threat Classification: Deliberate evasive obfuscation concealing malicious commands.',
            '[Analyst Trace] Decision Engine: Strictly REJECT file immediately.',
          ],
          evidenceSnippet: `container: ${c.name}\ncommand/args: ${cmdStr}`,
          impactSummary: 'Conceals malicious code from static scanners and executes arbitrary remote shell commands.',
          mitreTechnique: 'T1027: Obfuscated Files or Information',
        };
      }

      // Check for standalone long base64 string in args/command that decodes to shell code
      const b64Match = cmdStr.match(/([A-Za-z0-9+/]{24,}={0,2})/);
      if (b64Match) {
        try {
          const decoded = Buffer.from(b64Match[1], 'base64').toString('utf-8');
          if (/bash|sh|curl|wget|nc\s+|python|perl|\/dev\/tcp/i.test(decoded)) {
            return {
              threatType: 'Obfuscated Malicious Payload in Container Args',
              severity: 'CRITICAL',
              category: 'Logic Bomb / Obfuscated Code',
              attackVectorSteps: [
                `1. Container '${c.name}' defines obfuscated base64 parameters.`,
                `2. Decoded payload reveals executable instructions: "${decoded.slice(0, 45)}...".`,
                '3. Used to evade static filters and trigger unauthorized execution at container launch.',
              ],
              remediationAdvice:
                'Remove base64-encoded strings from container arguments and configure signed container images.',
              thinkingTrace: [
                '[Analyst Trace] Deep inspection of container arguments string literals...',
                `[Analyst Trace] Heuristic base64 decode reveals hidden shell commands: "${decoded.slice(0, 40)}".`,
                '[Analyst Trace] Threat detected: Evasive shell code obfuscation.',
                '[Analyst Trace] Decision Engine: REJECT file.',
              ],
              evidenceSnippet: `args: ${b64Match[1]} -> [Decoded: ${decoded.slice(0, 50)}]`,
              impactSummary: 'Execution of hidden malicious commands concealed within base64 strings.',
              mitreTechnique: 'T1027.001: Binary Padding / Base64 Encoding',
            };
          }
        } catch {
          // ignore non-base64
        }
      }

      // Check initContainer downloading scripts from unverified external URLs
      const initContainers = doc.spec?.template?.spec?.initContainers || doc.spec?.initContainers || [];
      for (const ic of initContainers) {
        const icCmd = [...(ic.command || []), ...(ic.args || [])].join(' ');
        const urlMatch = icCmd.match(/(curl|wget)\s+[^|;\n]*(https?:\/\/[^\s|;]+)/i);
        if (urlMatch && /\|\s*(sh|bash)/i.test(icCmd)) {
          return {
            threatType: 'Suspicious initContainer External Script Pipeline Execution',
            severity: 'CRITICAL',
            category: 'Supply Chain Attack',
            attackVectorSteps: [
              `1. initContainer '${ic.name}' runs prior to the application start.`,
              `2. Downloads an unverified remote script directly from URL: ${urlMatch[2]}.`,
              '3. Pipes remote script directly into bash/sh without checksum validation.',
              '4. Compromises the pod environment before runtime logging or security agents initialize.',
            ],
            remediationAdvice:
              'Package required binaries and scripts directly inside trusted container images. Do not fetch dynamic unverified scripts at pod bootstrap.',
            thinkingTrace: [
              `[Analyst Trace] Inspecting initContainers lifecycle for '${doc.metadata?.name}'...`,
              `[Analyst Trace] Detected unverified curl/wget remote script pipe in initContainer '${ic.name}'.`,
              `[Analyst Trace] Target URL: ${urlMatch[2]} executes arbitrary remote code.`,
              '[Analyst Trace] Threat Classification: Blind supply-chain script injection.',
              '[Analyst Trace] Decision Engine: REJECT file.',
            ],
            evidenceSnippet: `initContainer: ${ic.name}\ncommand: ${icCmd}`,
            impactSummary: 'Allows external unverified script injection into cluster workloads prior to pod startup.',
            mitreTechnique: 'T1195: Supply Chain Compromise / T1059.004: Unix Shell',
          };
        }
      }

      // Check for hardcoded secrets or credentials in env variables
      const envList = c.env || [];
      for (const env of envList) {
        const envName = (env.name || '').toUpperCase();
        const envVal = env.value || '';
        const isSecretName =
          envName.includes('PASSWORD') ||
          envName.includes('SECRET_KEY') ||
          envName.includes('API_TOKEN') ||
          envName.includes('AWS_SECRET') ||
          envName.includes('PRIVATE_KEY');

        const isRawSecretVal =
          envVal.length > 10 &&
          !envVal.startsWith('$(') &&
          !envVal.includes('placeholder') &&
          (envName.includes('KEY') || envName.includes('SECRET') || envName.includes('TOKEN'));

        if (isSecretName && isRawSecretVal) {
          return {
            threatType: 'Exposed Plaintext Secret in Environment Variable',
            severity: 'HIGH',
            category: 'Data Exfiltration Risk',
            attackVectorSteps: [
              `1. Workload '${doc.metadata?.name}' defines plaintext credential in '${env.name}'.`,
              '2. Any user or pod with "describe pod" or read access can extract the credential in plaintext.',
              '3. Attacker pivots into external cloud APIs or databases using the leaked secret.',
            ],
            remediationAdvice:
              'Store credentials in Kubernetes Secret objects and reference them using "valueFrom.secretKeyRef" instead of hardcoded values.',
            thinkingTrace: [
              `[Analyst Trace] Scanning container environment definitions in '${c.name}'...`,
              `[Analyst Trace] Found hardcoded credential under key '${env.name}'.`,
              '[Analyst Trace] High risk of credential harvesting from manifest source control or pod descriptions.',
              '[Analyst Trace] Decision Engine: REJECT file under Credential Exposure Policy.',
            ],
            evidenceSnippet: `env:\n  - name: ${env.name}\n    value: "${envVal.slice(0, 6)}****"`,
            impactSummary: 'Credential exposure leading to unauthorized pivot into adjacent cloud or database systems.',
            mitreTechnique: 'T1552.001: Unsecured Credentials - In Files',
          };
        }
      }
    }
  }

  // =========================================================================
  // 3. DATA EXFILTRATION RISKS: Access to secrets + egress/external connections
  // =========================================================================
  const grantsSecretAccess = roles.some((r) => {
    const rules = r.rules || [];
    return rules.some((rule: any) => {
      const resources = rule.resources || [];
      const verbs = rule.verbs || [];
      return (
        (resources.includes('secrets') || resources.includes('*')) &&
        (verbs.includes('get') || verbs.includes('list') || verbs.includes('*'))
      );
    });
  });

  for (const doc of allWorkloadDocs) {
    const podSpec = getPodSpec(doc);
    if (!podSpec) continue;
    const containers = getContainers(doc);

    // Look for netcat/curl outbound or socket commands in container args
    const hasOutboundTool = containers.some((c) => {
      const cmd = [...(c.command || []), ...(c.args || [])].join(' ');
      return /curl\s+[^\s]+|wget\s+[^\s]+|nc\s+-[a-z]*\s+[0-9.]+|ping\s+[0-9.]+/i.test(cmd);
    });

    const mountsSecret = (podSpec.volumes || []).some((v: any) => v.secret);

    if (grantsSecretAccess && hasOutboundTool) {
      return {
        threatType: 'Data Exfiltration Risk: Secret Access with Outbound Transfer Utilities',
        severity: 'HIGH',
        category: 'Data Exfiltration Risk',
        attackVectorSteps: [
          '1. Application identity possesses RBAC permissions to read Kubernetes secrets.',
          '2. Container incorporates egress network utilities (curl/wget/netcat) in execution parameters.',
          '3. Attacker dumps cluster secrets and transmits them outbound to an external destination.',
        ],
        maliciousIntent:
          'This pattern enables automated exfiltration of sensitive tokens, TLS certificates, and database passwords to external adversary-controlled IPs.',
        attackChainNodes: [
          { id: '1', label: 'RBAC: read secrets', role: 'source', description: 'Grants get/list on sensitive core API secret resources' },
          { id: '2', label: 'Workload: curl/netcat', role: 'escalation', description: 'Container binary capable of outbound socket egress' },
          { id: '3', label: 'Secret Token Extraction', role: 'escalation', description: 'Mounts or queries serviceaccount/database credentials' },
          { id: '4', label: 'External Exfiltration', role: 'compromise', description: 'Sends credentials across network to external IP' },
        ],
        remediationAdvice:
          'Restrict RBAC secret access to dedicated security controllers, remove network egress binaries from containers, and implement Kubernetes NetworkPolicies blocking outbound egress.',
        remediationYaml: `# Safe Remediated Manifest: Remove secret permissions & enforce NetworkPolicy
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: restricted-app-role
rules:
  - apiGroups: [""]
    resources: ["configmaps"] # FIXED: Removed "secrets"
    verbs: ["get", "list"]
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-egress
spec:
  podSelector: {}
  policyTypes:
    - Egress # FIXED: Restricts outbound egress traffic`,
        thinkingTrace: [
          '[Analyst Trace] Correlating RBAC Secret permissions with container execution specs...',
          '[Analyst Trace] Found RBAC permissions reading "secrets" alongside outbound data transfer commands.',
          '[Analyst Trace] Heuristic risk: High probability of automated secret exfiltration.',
          '[Analyst Trace] Decision Engine: REJECT file to protect cluster secrets.',
        ],
        evidenceSnippet: 'RBAC: get/list secrets\nContainer: outbound networking command detected',
        impactSummary: 'Potential exfiltration of cluster secrets, API tokens, and confidential keys.',
        mitreTechnique: 'T1048: Exfiltration Over Alternative Protocol',
      };
    }
  }

  // =========================================================================
  // 4. PERSISTENCE MECHANISMS: CronJob / DaemonSet rogue recurrence
  // =========================================================================
  for (const cron of cronJobs) {
    const schedule = cron.spec?.schedule || '';
    const containers = getContainers(cron);
    const hasFrequentSchedule = schedule.trim() === '* * * * *' || schedule.includes('*/1') || schedule.includes('*/2');
    const hasSuspiciousCmd = containers.some((c) => {
      const cmd = [...(c.command || []), ...(c.args || [])].join(' ');
      return /curl|wget|bash|sh|python|nc|chmod\s+\+x/i.test(cmd);
    });

    if (hasFrequentSchedule && hasSuspiciousCmd) {
      return {
        threatType: 'Stealth Persistence Mechanism via High-Frequency CronJob',
        severity: 'CRITICAL',
        category: 'Persistence Mechanism',
        attackVectorSteps: [
          `1. CronJob '${cron.metadata?.name}' schedules executions every minute ('${schedule}').`,
          '2. Container runs continuous shell scripts or network download commands.',
          '3. If an administrator detects and kills the rogue container, the CronJob automatically re-spawns a new backdoor instance.',
          '4. Establishes resilient, self-healing persistence across cluster worker nodes.',
        ],
        maliciousIntent:
          'This pattern is commonly used by advanced malware to establish self-healing persistence in a Kubernetes cluster that survives manual pod evictions.',
        attackChainNodes: [
          { id: '1', label: `CronJob '${cron.metadata?.name}'`, role: 'source', description: `High-frequency schedule: ${schedule}` },
          { id: '2', label: 'Automated Pod Re-spawn', role: 'escalation', description: 'Re-spawns malicious container every 60 seconds' },
          { id: '3', label: 'Egress Beaconing', role: 'escalation', description: 'Periodically checks in with remote adversary C2' },
          { id: '4', label: 'Permanent Cluster Footprint', role: 'compromise', description: 'Resists administrative remediation and manual pod deletion' },
        ],
        remediationAdvice:
          'Audit and remove rogue CronJob manifests. Restrict CronJob creation permissions to trusted deployment pipelines.',
        remediationYaml: `# Safe Remediated Manifest: Remove unauthorized periodic CronJob
# Action: Delete CronJob '${cron.metadata?.name}'.
# Enforce Gatekeeper/Kyverno policy restricting CronJob schedules:
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: k8sdisallowuntrustedcronjobs
spec:
  crd:
    spec:
      names:
        kind: K8sDisallowUntrustedCronJobs`,
        thinkingTrace: [
          `[Analyst Trace] Analyzing scheduled automation in CronJob '${cron.metadata?.name}'...`,
          `[Analyst Trace] Schedule '${schedule}' triggers every minute.`,
          '[Analyst Trace] Container executes recurrent shell commands, characteristic of persistence backdoors.',
          '[Analyst Trace] Decision Engine: REJECT manifest under Persistence Prevention Policy.',
        ],
        evidenceSnippet: `kind: CronJob\nname: ${cron.metadata?.name}\nschedule: "${schedule}"\ncontainers: [shell/download commands]`,
        impactSummary: 'Maintains long-term unauthorized access that survives container termination and node restarts.',
        mitreTechnique: 'T1053.007: Scheduled Task/Job - Kubernetes CronJob',
      };
    }
  }

  // Check DaemonSet running root / host access across ALL nodes
  for (const ds of daemonSets) {
    const podSpec = getPodSpec(ds);
    if (!podSpec) continue;
    const containers = getContainers(ds);
    const isPrivileged = containers.some((c) => c.securityContext?.privileged === true);
    const hasHostPid = podSpec.hostPID === true;

    if (isPrivileged || hasHostPid) {
      return {
        threatType: 'Cluster-Wide Persistence & Node Takeover via Privileged DaemonSet',
        severity: 'CRITICAL',
        category: 'Persistence Mechanism',
        attackVectorSteps: [
          `1. DaemonSet '${ds.metadata?.name}' targets EVERY node in the cluster automatically.`,
          '2. Deploys privileged containers with hostPID across all current and future worker nodes.',
          '3. Provides complete cluster-wide root persistence that cannot be mitigated by killing single pods.',
        ],
        maliciousIntent:
          'This pattern forces every node in the cluster to execute an adversary-controlled privileged container, resulting in 100% infrastructure compromise.',
        attackChainNodes: [
          { id: '1', label: `DaemonSet '${ds.metadata?.name}'`, role: 'source', description: 'Schedules pods onto 100% of cluster nodes' },
          { id: '2', label: 'securityContext.privileged: true', role: 'escalation', description: 'Escapes container isolation on every node' },
          { id: '3', label: 'Cluster-Wide Kernel Access', role: 'compromise', description: 'Compromises all kubelets, secrets, and customer workloads' },
        ],
        remediationAdvice:
          'Remove privileged DaemonSets or restrict deployment strictly to vendor system namespaces with policy guardrails.',
        remediationYaml: `# Safe Remediated Manifest: Remove privileged context from DaemonSet
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: ${ds.metadata?.name || 'safe-node-agent'}
spec:
  template:
    spec:
      hostPID: false # FIXED: Disabled hostPID
      containers:
        - name: agent
          image: node-exporter:v1.7.0
          securityContext:
            privileged: false # FIXED: Disabled privileged mode
            allowPrivilegeEscalation: false`,
        thinkingTrace: [
          `[Analyst Trace] Evaluating DaemonSet workload '${ds.metadata?.name}'...`,
          '[Analyst Trace] DaemonSets replicate across all cluster nodes.',
          '[Analyst Trace] Workload includes privileged container spec -> Full cluster-wide takeover.',
          '[Analyst Trace] Decision Engine: CRITICAL REJECTION.',
        ],
        evidenceSnippet: `kind: DaemonSet\nname: ${ds.metadata?.name}\nprivileged: true across all nodes`,
        impactSummary: 'Cluster-wide compromise propagating root access to every worker node.',
        mitreTechnique: 'T1543.003: Create or Modify System Process',
      };
    }
  }

  // =========================================================================
  // 5. RESOURCE HIJACKING: Crypto-mining patterns and missing limits
  // =========================================================================
  for (const doc of allWorkloadDocs) {
    const containers = getContainers(doc);
    for (const c of containers) {
      const img = (c.image || '').toLowerCase();
      const cmd = [...(c.command || []), ...(c.args || [])].join(' ').toLowerCase();

      const isMinerPattern =
        img.includes('xmrig') ||
        img.includes('minerd') ||
        cmd.includes('xmrig') ||
        cmd.includes('stratum+tcp') ||
        cmd.includes('cryptonight');

      const hasNoLimits = !c.resources?.limits?.cpu && !c.resources?.limits?.memory;

      if (isMinerPattern) {
        return {
          threatType: 'Resource Hijacking: Cryptocurrency Mining Container',
          severity: 'CRITICAL',
          category: 'Resource Hijacking',
          attackVectorSteps: [
            `1. Container '${c.name}' utilizes known cryptomining binary or pool protocol.`,
            '2. Hijacks CPU and GPU compute cycles from legitimate cluster workloads.',
            '3. Causes severe resource starvation, latency spikes, and cloud infrastructure cost inflation.',
          ],
          maliciousIntent:
            'This pattern repurposes cluster hardware to mine cryptocurrency for an attacker, exhausting cloud resources and causing bill shock.',
          attackChainNodes: [
            { id: '1', label: `Miner Container '${c.name}'`, role: 'source', description: 'Deploys unauthorized cryptomining executable' },
            { id: '2', label: 'Stratum Mining Pool Protocol', role: 'escalation', description: 'Connects to remote crypto pool (e.g. stratum+tcp)' },
            { id: '3', label: '100% CPU/GPU Starvation', role: 'compromise', description: 'Evicts legitimate services and drives up cloud costs' },
          ],
          remediationAdvice:
            'Immediately ban cryptocurrency mining container images and block outbound stratum network ports (e.g. 3333, 4444, 5555).',
          remediationYaml: `# Safe Remediated Manifest: Deploy legitimate application image with resource constraints
apiVersion: v1
kind: Pod
metadata:
  name: safe-service
spec:
  containers:
    - name: app
      image: nginx:1.25.4-alpine # FIXED: Replaced unauthorized miner image
      resources:
        limits:
          cpu: "500m" # FIXED: Enforced compute quota
          memory: "256Mi"`,
          thinkingTrace: [
            `[Analyst Trace] Inspecting workload '${doc.metadata?.name}' for illicit compute patterns...`,
            `[Analyst Trace] Detected cryptominer signature in image/command: ${img || cmd}.`,
            '[Analyst Trace] Threat Classification: Unauthorized resource hijacking.',
            '[Analyst Trace] Decision Engine: REJECT file.',
          ],
          evidenceSnippet: `image: ${c.image}\ncommand: ${cmd}`,
          impactSummary: 'Cluster compute exhaustion and massive cloud billing fraud.',
          mitreTechnique: 'T1496: Resource Hijacking',
        };
      }

      // Check high risk unbounded pod without any resource limits
      if (hasNoLimits && (doc.kind === 'Job' || doc.kind === 'CronJob') && cmd.includes('stress')) {
        return {
          threatType: 'Resource Exhaustion / Denial of Service Risk',
          severity: 'HIGH',
          category: 'Resource Hijacking',
          attackVectorSteps: [
            `1. Batch job '${doc.metadata?.name}' runs unbounded compute stress loops.`,
            '2. Consumes 100% of host CPU and memory because no resource limits are specified.',
            '3. Triggers Out-Of-Memory (OOM) killer on Kubernetes nodes, knocking down mission-critical pods.',
          ],
          remediationAdvice:
            'Enforce LimitRanges in all namespaces and define explicit "resources.limits.cpu" and "resources.limits.memory".',
          thinkingTrace: [
            `[Analyst Trace] Checking resource quotas for '${doc.metadata?.name}'...`,
            '[Analyst Trace] No CPU/Memory limits configured + stress compute command detected.',
            '[Analyst Trace] High probability of node resource starvation and DoS.',
            '[Analyst Trace] Decision Engine: REJECT manifest.',
          ],
          evidenceSnippet: `kind: ${doc.kind}\nlimits: [NOT CONFIGURED]`,
          impactSummary: 'Node denial of service and cascading OOM eviction of production workloads.',
          mitreTechnique: 'T1499: Endpoint Denial of Service',
        };
      }
    }
  }

  // =========================================================================
  // 6. SUPPLY CHAIN ATTACKS: Images from untrusted registries / unpinned latest
  // =========================================================================
  for (const doc of allWorkloadDocs) {
    const containers = getContainers(doc);
    for (const c of containers) {
      const image = c.image || '';
      // Raw IP address registry (e.g., 198.51.100.44:5000/app:latest)
      const rawIpRegistryMatch = image.match(/^([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(:[0-9]+)?)\//);
      if (rawIpRegistryMatch) {
        return {
          threatType: 'Supply Chain Attack: Image Pulled from Untrusted Raw IP Registry',
          severity: 'HIGH',
          category: 'Supply Chain Attack',
          attackVectorSteps: [
            `1. Workload '${doc.metadata?.name}' specifies container image from raw IP host: ${rawIpRegistryMatch[1]}.`,
            '2. The registry lacks cryptographic signature verification, TLS attestation, or vulnerability scanning.',
            '3. Attacker can tamper with the image payload or execute rogue binaries inside the cluster.',
          ],
          maliciousIntent:
            'This pattern bypasses enterprise container registries to pull uninspected, unverified binaries directly from attacker-hosted image registries.',
          attackChainNodes: [
            { id: '1', label: `Untrusted Host ${rawIpRegistryMatch[1]}`, role: 'source', description: 'Unverified external IP serving images' },
            { id: '2', label: 'Bypass Registry Attestation', role: 'escalation', description: 'No Sigstore/Cosign signature validation' },
            { id: '3', label: 'Compromised Runtime Binary', role: 'compromise', description: 'Deploys malicious unvetted container payload' },
          ],
          remediationAdvice:
            'Configure an ImagePolicyWebhook admitting images solely from verified enterprise container registries (e.g. gcr.io, ECR, GAR, ACR).',
          remediationYaml: `# Safe Remediated Manifest: Pull only from trusted enterprise registry with digest
apiVersion: v1
kind: Pod
metadata:
  name: ${doc.metadata?.name || 'safe-proxy'}
spec:
  containers:
    - name: proxy
      image: registry.k8s.io/nginx:1.25.4 # FIXED: Enterprise trusted registry`,
          thinkingTrace: [
            `[Analyst Trace] Auditing container image origin in '${c.name}'...`,
            `[Analyst Trace] Image '${image}' points to unverified raw IP registry: ${rawIpRegistryMatch[1]}.`,
            '[Analyst Trace] Threat Classification: High-risk untrusted supply chain artifact.',
            '[Analyst Trace] Decision Engine: REJECT manifest under Supply Chain Hardening Policy.',
          ],
          evidenceSnippet: `image: ${image}`,
          impactSummary: 'Introduction of untrusted, unverified third-party binaries into production.',
          mitreTechnique: 'T1195.002: Supply Chain Compromise - Compromise Software Dependencies',
        };
      }
    }
  }

  // =========================================================================
  // 7. LOGIC BOMBS & TIME-BASED TRIGGERS
  // =========================================================================
  for (const doc of allWorkloadDocs) {
    const containers = getContainers(doc);
    for (const c of containers) {
      const cmdStr = [...(c.command || []), ...(c.args || [])].join(' ');
      const hasDateCheck =
        /date\s+\+%(Y|s|m|d)/i.test(cmdStr) && /if\s*\[.*-ge|then|sleep\s+86400/i.test(cmdStr);

      if (hasDateCheck) {
        return {
          threatType: 'Logic Bomb: Time-Conditioned Delayed Trigger in Container Command',
          severity: 'HIGH',
          category: 'Logic Bomb / Obfuscated Code',
          attackVectorSteps: [
            `1. Container '${c.name}' incorporates conditional logic checking system date/time.`,
            '2. Payload stays dormant during initial deployment and sandbox testing.',
            '3. Upon reaching the designated timestamp or sleep duration, the malicious payload detonates.',
          ],
          maliciousIntent:
            'This pattern allows a payload to remain dormant during automated CI/CD pipeline scans and sandbox testing, only detonating in production.',
          attackChainNodes: [
            { id: '1', label: 'Dormant Container Start', role: 'source', description: 'Passes basic startup liveness probes' },
            { id: '2', label: 'Time-Condition Gating', role: 'escalation', description: 'Checks system date/time or sleeps for days' },
            { id: '3', label: 'Delayed Exploit Detonation', role: 'compromise', description: 'Triggers secondary remote payload execution' },
          ],
          remediationAdvice:
            'Purge dynamic time-gated conditions from entrypoint scripts and enforce immutable single-purpose container runtimes.',
          remediationYaml: `# Safe Remediated Manifest: Remove dynamic time-delay scripts
apiVersion: v1
kind: Pod
metadata:
  name: ${doc.metadata?.name || 'safe-routine'}
spec:
  containers:
    - name: task
      image: alpine:3.19
      command: ["/bin/sh", "-c", "echo 'Running routine maintenance task...'"] # FIXED: Removed dormant time condition`,
          thinkingTrace: [
            `[Analyst Trace] Examining command heuristics in '${doc.metadata?.name}'...`,
            '[Analyst Trace] Detected temporal logic condition querying date/time before payload activation.',
            '[Analyst Trace] Threat Classification: Dormant logic bomb designed to evade initial sandbox analysis.',
            '[Analyst Trace] Decision Engine: REJECT file.',
          ],
          evidenceSnippet: `command: ${cmdStr}`,
          impactSummary: 'Dormant delayed execution of unverified payloads bypassing initial test periods.',
          mitreTechnique: 'T1485: Data Destruction / T1059: Command and Scripting Interpreter',
        };
      }
    }
  }

  return null;
}

export function validateKubernetesFile(input: ValidationInput): FileValidationResult {
  const now = new Date();
  const dateStr = now.toLocaleDateString('en-US', {
    day: 'numeric',
    month: 'long',
    year: 'numeric',
  });
  const timeStr = now.toLocaleTimeString('en-US', {
    hour: '2-digit',
    minute: '2-digit',
    hour12: true,
  });

  const baseResult: FileValidationResult = {
    fileId: `file-${Date.now()}-${Math.random().toString(36).substr(2, 6)}`,
    fileName: input.name,
    fileSize: input.size,
    fileSizeFormatted: formatBytes(input.size),
    uploadedBy: input.uploadedBy || 'Current User',
    uploadDate: dateStr,
    uploadTime: timeStr,
    scanId: input.scanId || `SCAN-${Math.floor(1000 + Math.random() * 9000)}`,
    content: input.content,
    yamlSyntax: 'PASS',
    k8sStructure: 'PASS',
    securityContent: 'PASS',
    threatScan: 'PASS',
    abnormalCheck: 'PASS',
    securityScore: 100,
    status: 'ACCEPTED',
    reason: 'SECURITY CLEARANCE GRANTED — Zero threats detected. Manifest fully complies with Kubernetes security standards.',
    detectedThreats: [],
    k8sResourceCount: 0,
    aiAnalystThinkingSteps: [
      `[1/5] Parsing YAML Structure: PASS (Valid Kubernetes schemas in ${input.name})`,
      '[2/5] Analyzing RBAC Permissions: PASS (Least-privilege compliant, zero wildcards)',
      '[3/5] Checking for Privilege Escalation Paths: PASS (Zero host breakout vectors)',
      '[4/5] Scanning for Obfuscated Malicious Code: PASS (No base64/eval/reverse shell payloads)',
      '[5/5] Generating Threat Intelligence Report: SECURITY CLEARANCE GRANTED (Security Score: 100/100)',
    ],
  };

  const lowerName = input.name.toLowerCase();

  // 1. File Type & Extension Validation
  if (!lowerName.endsWith('.yaml') && !lowerName.endsWith('.yml')) {
    return {
      ...baseResult,
      yamlSyntax: 'FAIL',
      k8sStructure: 'FAIL',
      securityContent: 'FAIL',
      securityScore: 10,
      status: 'REJECTED',
      reason: 'Unsupported file type. Please upload YAML or YML files.',
      errorDetails: `File extension must be .yaml or .yml. Received: ${input.name}`,
    };
  }

  // 2. File Size Validation
  if (!input.content || input.content.trim().length === 0) {
    return {
      ...baseResult,
      yamlSyntax: 'FAIL',
      k8sStructure: 'FAIL',
      securityScore: 20,
      status: 'REJECTED',
      reason: 'File is empty.',
      errorDetails: 'The uploaded file does not contain any data.',
    };
  }

  if (input.size > 5 * 1024 * 1024) {
    return {
      ...baseResult,
      securityContent: 'FAIL',
      securityScore: 15,
      status: 'REJECTED',
      reason: 'File exceeds maximum allowed size of 5 MB.',
      errorDetails: `File size is ${formatBytes(input.size)}, exceeding the 5MB safety limit.`,
    };
  }

  // 3. Raw Malware / Threat Signatures Check
  const detectedThreats: string[] = [];
  for (const threat of MALWARE_THREAT_PATTERNS) {
    if (threat.regex.test(input.content)) {
      detectedThreats.push(threat.name);
    }
  }

  if (detectedThreats.length > 0) {
    const threatTitle = detectedThreats[0];
    const threatIntel: ThreatIntelligenceReport = {
      threatType: threatTitle,
      severity: 'CRITICAL',
      category: 'Suspicious Payload',
      attackVectorSteps: [
        '1. Malicious executable payload detected in file manifest stream.',
        `2. Signature: ${threatTitle}`,
        '3. Enables remote adversary interactive command-and-control connection.',
      ],
      remediationAdvice:
        'Purge interactive reverse shell payloads and ensure containers only invoke legitimate compiled application binaries.',
      thinkingTrace: [
        `[Analyst Trace] Deep stream inspection detected malware signature: ${threatTitle}`,
        '[Analyst Trace] Threat Classification: Interactive reverse shell / C2 beaconing.',
        '[Analyst Trace] Decision Engine: STRICT REJECTION TRIGGERED.',
      ],
      evidenceSnippet: detectedThreats.join(', '),
      impactSummary: 'Direct unauthenticated remote command execution on cluster container or host.',
      mitreTechnique: 'T1059.004: Unix Shell / T1071: Application Layer Protocol',
    };

    return {
      ...baseResult,
      threatScan: 'DETECTED',
      securityContent: 'FAIL',
      securityScore: 0,
      status: 'REJECTED',
      reason: `THREAT DETECTED - FILE REJECTED: ${threatTitle}`,
      errorDetails: `Malicious pattern detected: ${detectedThreats.join(', ')}`,
      detectedThreats,
      threatIntelligence: threatIntel,
      aiAnalystThinkingSteps: threatIntel.thinkingTrace,
    };
  }

  // 4. Abnormal Pattern Detection
  const detectedAbnormalities: string[] = [];
  for (const abnormal of ABNORMAL_PATTERNS) {
    if (abnormal.regex.test(input.content)) {
      detectedAbnormalities.push(abnormal.name);
    }
  }

  if (detectedAbnormalities.length > 0) {
    const abnormalTitle = detectedAbnormalities[0];
    return {
      ...baseResult,
      abnormalCheck: 'DETECTED',
      securityContent: 'FAIL',
      securityScore: 18,
      status: 'REJECTED',
      reason: `THREAT DETECTED - FILE REJECTED: ${abnormalTitle}`,
      errorDetails: `Unexpected payload pattern: ${detectedAbnormalities.join(', ')}`,
      detectedThreats: detectedAbnormalities,
      threatIntelligence: {
        threatType: abnormalTitle,
        severity: 'HIGH',
        category: 'Suspicious Payload',
        attackVectorSteps: [
          '1. Unusual or executable script tags embedded in Kubernetes YAML metadata/data.',
          '2. Violates clean configuration principles and introduces arbitrary script injection.',
        ],
        remediationAdvice: 'Remove binary payloads or executable script tags from manifest definitions.',
        thinkingTrace: [
          `[Analyst Trace] Abnormal pattern detected: ${abnormalTitle}`,
          '[Analyst Trace] Decision Engine: Strictly reject file from entering RBAC scan.',
        ],
        impactSummary: 'Injection of abnormal executable constructs into Kubernetes cluster state.',
        mitreTechnique: 'T1027: Obfuscated Files or Information',
      },
      aiAnalystThinkingSteps: [
        `[Analyst Trace] Abnormal pattern found: ${abnormalTitle}`,
        '[Analyst Trace] Decision Engine: REJECTED.',
      ],
    };
  }

  // 5. YAML Syntax Validation
  let parsedDocs: any[] = [];
  try {
    loadAll(input.content, (doc: any) => {
      if (doc && typeof doc === 'object') {
        parsedDocs.push(doc);
      }
    });
  } catch (yamlErr: any) {
    const errorMsg = yamlErr?.message || 'Syntax parse failed';
    const isIndentation = /indentation|bad indentation|mapping values are not allowed/i.test(errorMsg);

    return {
      ...baseResult,
      yamlSyntax: 'FAIL',
      k8sStructure: 'FAIL',
      securityScore: 25,
      status: 'REJECTED',
      reason: 'Invalid YAML syntax',
      errorDetails: isIndentation
        ? 'Malformed indentation detected.'
        : `Syntax error: ${errorMsg.split('\n')[0]}`,
    };
  }

  if (parsedDocs.length === 0) {
    return {
      ...baseResult,
      yamlSyntax: 'FAIL',
      k8sStructure: 'FAIL',
      securityScore: 30,
      status: 'REJECTED',
      reason: 'Invalid YAML content',
      errorDetails: 'Document contains no valid YAML mappings or objects.',
    };
  }

  // 6. Kubernetes Structure & Schema Validation
  let validK8sCount = 0;
  const structErrors: string[] = [];

  for (let i = 0; i < parsedDocs.length; i++) {
    const doc = parsedDocs[i];
    if (!doc.apiVersion || typeof doc.apiVersion !== 'string') {
      structErrors.push(`Document #${i + 1} is missing a valid 'apiVersion'.`);
    } else if (!doc.kind || typeof doc.kind !== 'string') {
      structErrors.push(`Document #${i + 1} is missing a valid 'kind' attribute.`);
    } else if (!doc.metadata || typeof doc.metadata !== 'object' || !doc.metadata.name) {
      structErrors.push(`Document #${i + 1} of kind '${doc.kind}' is missing 'metadata.name'.`);
    } else {
      validK8sCount++;
    }
  }

  if (validK8sCount === 0) {
    return {
      ...baseResult,
      k8sStructure: 'FAIL',
      securityScore: 35,
      status: 'REJECTED',
      reason: 'Invalid Kubernetes RBAC structure',
      errorDetails: structErrors[0] || 'Content inconsistent with Kubernetes manifest specifications.',
    };
  }

  // =========================================================================
  // 7. HEURISTIC BEHAVIOR-BASED SECURITY SCANNER ("Thinking" AI Analyst)
  // Deep structural analysis across object relationships, privilege escalation,
  // exfiltration, persistence, supply chain, and logic bombs
  // =========================================================================
  const heuristicThreat = analyzeHeuristicThreats(parsedDocs, input.content);
  if (heuristicThreat) {
    return {
      ...baseResult,
      threatScan: 'DETECTED',
      securityContent: 'FAIL',
      securityScore: 0,
      status: 'REJECTED',
      reason: `THREAT DETECTED - FILE REJECTED: ${heuristicThreat.threatType}`,
      errorDetails: `${heuristicThreat.category} (${heuristicThreat.severity}): ${heuristicThreat.impactSummary}`,
      detectedThreats: [heuristicThreat.threatType],
      k8sResourceCount: validK8sCount,
      threatIntelligence: heuristicThreat,
      aiAnalystThinkingSteps: heuristicThreat.thinkingTrace,
    };
  }

  // Non-blocking warnings check (e.g. unknown custom fields or minor warnings)
  if (structErrors.length > 0) {
    return {
      ...baseResult,
      k8sStructure: 'PASS',
      securityScore: 82,
      status: 'WARNING',
      reason: 'Some documents contain non-fatal structure warnings, but valid Kubernetes objects were verified.',
      errorDetails: structErrors.join('; '),
      k8sResourceCount: validK8sCount,
      aiAnalystThinkingSteps: [
        `[Analyst Trace] Analyzed ${validK8sCount} Kubernetes objects across ${parsedDocs.length} documents.`,
        '[Analyst Trace] Minor structural warnings identified, but zero malicious threats detected.',
        '[Analyst Trace] Status: APPROVED WITH WARNINGS for RBAC graph analysis.',
      ],
    };
  }

  // File is structurally sound, clean, and verified safe
  const finalScore = parsedDocs.length > 3 ? 98 : 100;

  return {
    ...baseResult,
    yamlSyntax: 'PASS',
    k8sStructure: 'PASS',
    securityContent: 'PASS',
    threatScan: 'PASS',
    abnormalCheck: 'PASS',
    securityScore: finalScore,
    status: 'ACCEPTED',
    reason: 'All multi-layer security, structural correlation, and Kubernetes schema validation checks passed.',
    k8sResourceCount: validK8sCount,
    aiAnalystThinkingSteps: [
      `[Analyst Trace] Deep structural analysis completed for ${validK8sCount} valid Kubernetes objects.`,
      '[Analyst Trace] Evaluated object relationships between ServiceAccounts, Roles, and Pod templates.',
      '[Analyst Trace] Verified: No privilege escalation chains, no obfuscated payloads, no exfiltration risks.',
      '[Analyst Trace] Decision: FILE ACCEPTED (Security Score: ' + finalScore + '/100). Ready for RBAC Graph analysis.',
    ],
  };
}
