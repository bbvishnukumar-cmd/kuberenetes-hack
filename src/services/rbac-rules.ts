import { dump } from 'js-yaml';
import { Finding, RuleDefinition } from '../types/rbac';
import { ParsedK8sResource } from './k8s-parser';

export const RULE_DEFINITIONS: Record<string, RuleDefinition> = {
  'RBAC-001': {
    ruleId: 'RBAC-001',
    name: 'Cluster-admin binding',
    description: 'A ServiceAccount or identity has been granted cluster-admin privileges, granting unrestricted superuser control over the entire cluster.',
    severity: 'CRITICAL',
    category: 'Privilege Escalation',
    cisReference: 'CIS Kubernetes Benchmark 5.1.1',
    mitreReference: 'MITRE ATT&CK T1078 - Valid Accounts',
    recommendation: 'Remove cluster-admin binding. Replace with a custom ClusterRole or Role restricted to only the necessary namespaces and resources.',
  },
  'RBAC-002': {
    ruleId: 'RBAC-002',
    name: 'Wildcard verbs in RBAC rule',
    description: 'Rule uses wildcard "*" in verbs list, effectively granting full administrative execution capabilities (get, list, watch, create, update, patch, delete, deletecollection).',
    severity: 'HIGH',
    category: 'Excessive Permissions',
    cisReference: 'CIS Kubernetes Benchmark 5.1.3',
    mitreReference: 'MITRE ATT&CK T1068 - Exploitation for Privilege Escalation',
    recommendation: 'Explicitly specify only required verbs (e.g. ["get", "list", "watch"]). Avoid "*" wildcards in production roles.',
  },
  'RBAC-003': {
    ruleId: 'RBAC-003',
    name: 'Wildcard resources in RBAC rule',
    description: 'Rule grants permissions over all resources ("*") in apiGroups, exposing secrets, pods, nodes, and cluster configuration to unintended tampering.',
    severity: 'HIGH',
    category: 'Excessive Permissions',
    cisReference: 'CIS Kubernetes Benchmark 5.1.3',
    mitreReference: 'MITRE ATT&CK T1613 - Container and Resource Discovery',
    recommendation: 'Specify exact resources needed (e.g. ["configmaps", "services"]). Do not use wildcard resource targets.',
  },
  'RBAC-004': {
    ruleId: 'RBAC-004',
    name: 'Broad secret read access',
    description: 'Permission grants get, list, or watch on Secrets. An identity with this permission can extract database credentials, TLS certificates, and API tokens across the namespace.',
    severity: 'HIGH',
    category: 'Resource Exposure',
    cisReference: 'CIS Kubernetes Benchmark 5.1.2',
    mitreReference: 'MITRE ATT&CK T1552 - Unsecured Credentials',
    recommendation: 'Use resourceNames to restrict secret access to specific named secrets, or utilize External Secrets Operator / Vault rather than granting broad secret read access.',
  },
  'RBAC-005': {
    ruleId: 'RBAC-005',
    name: 'Pod exec permission granted',
    description: 'Role grants create or wildcard access to "pods/exec" subresource. This allows an identity to spawn interactive shell sessions inside running containers, bypassing perimeter controls.',
    severity: 'HIGH',
    category: 'Privilege Escalation',
    cisReference: 'CIS Kubernetes Benchmark 5.1.4',
    mitreReference: 'MITRE ATT&CK T1609 - Container Administration Command',
    recommendation: 'Restrict pods/exec privileges exclusively to authorized human SREs via ephemeral just-in-time access. Do not grant pods/exec to automated ServiceAccounts.',
  },
  'RBAC-006': {
    ruleId: 'RBAC-006',
    name: 'Excessive cluster-wide permissions',
    description: 'A ClusterRoleBinding grants write capabilities (create, update, patch, delete) cluster-wide instead of being scoped to an isolated namespace via RoleBinding.',
    severity: 'HIGH',
    category: 'Excessive Permissions',
    cisReference: 'CIS Kubernetes Benchmark 5.1.1',
    mitreReference: 'MITRE ATT&CK T1078 - Cloud Accounts',
    recommendation: 'Scope permissions using namespace-bound RoleBindings instead of cluster-wide ClusterRoleBindings whenever possible.',
  },
  'RBAC-007': {
    ruleId: 'RBAC-007',
    name: 'Default ServiceAccount usage',
    description: 'Workload pod or deployment runs with the "default" ServiceAccount, which may inherit broad permissions or be accessible to any workload in the namespace.',
    severity: 'MEDIUM',
    category: 'Identity Security',
    cisReference: 'CIS Kubernetes Benchmark 5.1.5',
    mitreReference: 'MITRE ATT&CK T1078.004 - Cloud Accounts',
    recommendation: 'Create a dedicated, least-privilege ServiceAccount for each microservice with automountServiceAccountToken: false unless explicitly needed.',
  },
  'RBAC-008': {
    ruleId: 'RBAC-008',
    name: 'Privileged container execution',
    description: 'Container defines securityContext.privileged: true, giving containerized process access to all host devices and disabling root kernel containment.',
    severity: 'CRITICAL',
    category: 'Pod Security',
    cisReference: 'CIS Kubernetes Benchmark 5.2.1',
    mitreReference: 'MITRE ATT&CK T1611 - Escape to Host',
    recommendation: 'Set securityContext.privileged: false. Drop ALL capabilities and selectively add only specific POSIX capabilities if strictly needed.',
  },
  'RBAC-009': {
    ruleId: 'RBAC-009',
    name: 'Host network namespace enabled',
    description: 'Pod sets hostNetwork: true, allowing containers to sniff host network traffic, loopback interfaces, and access localhost-bound services.',
    severity: 'HIGH',
    category: 'Pod Security',
    cisReference: 'CIS Kubernetes Benchmark 5.2.4',
    mitreReference: 'MITRE ATT&CK T1611 - Escape to Host',
    recommendation: 'Remove hostNetwork: true from Pod spec. Use standard Kubernetes service routing and ingress.',
  },
  'RBAC-010': {
    ruleId: 'RBAC-010',
    name: 'Host PID namespace sharing',
    description: 'Pod sets hostPID: true, allowing containers to view and interact with processes running outside the container on the host node, facilitating container escapes.',
    severity: 'HIGH',
    category: 'Pod Security',
    cisReference: 'CIS Kubernetes Benchmark 5.2.2',
    mitreReference: 'MITRE ATT&CK T1611 - Escape to Host',
    recommendation: 'Set hostPID: false. Do not share the host process ID namespace with container workloads.',
  },
  'RBAC-011': {
    ruleId: 'RBAC-011',
    name: 'Host filesystem access via hostPath volume',
    description: 'Workload mounts a hostPath volume, providing access to host filesystem directories like /var/run/docker.sock, /etc, or root files.',
    severity: 'HIGH',
    category: 'Pod Security',
    cisReference: 'CIS Kubernetes Benchmark 5.2.3',
    mitreReference: 'MITRE ATT&CK T1611 - Escape to Host',
    recommendation: 'Avoid hostPath volumes. Use PersistentVolumeClaims with CSI drivers or emptyDir volumes.',
  },
  'RBAC-012': {
    ruleId: 'RBAC-012',
    name: 'Excessive RBAC management permissions',
    description: 'Role grants create, update, or bind rights over roles, rolebindings, or clusterrolebindings, which allows an identity to escalate its own permissions.',
    severity: 'HIGH',
    category: 'Privilege Escalation',
    cisReference: 'CIS Kubernetes Benchmark 5.1.1',
    mitreReference: 'MITRE ATT&CK T1068 - Exploitation for Privilege Escalation',
    recommendation: 'Revoke permissions to modify RBAC resources (roles, rolebindings) from workload ServiceAccounts.',
  },
};

export function executeRbacRules(resources: ParsedK8sResource[], scanId: string): Finding[] {
  const findings: Finding[] = [];
  let findingCounter = 1;

  const clusterRoleBindings = resources.filter((r) => r.kind.toLowerCase() === 'clusterrolebinding');
  const roleBindings = resources.filter((r) => r.kind.toLowerCase() === 'rolebinding');
  const roles = resources.filter((r) => r.kind.toLowerCase() === 'role');
  const clusterRoles = resources.filter((r) => r.kind.toLowerCase() === 'clusterrole');
  const pods = resources.filter((r) => r.kind.toLowerCase() === 'pod');
  const deployments = resources.filter((r) => r.kind.toLowerCase() === 'deployment');

  // Helper to dump yaml safely
  const toCleanYaml = (obj: any) => {
    try {
      return dump(obj, { indent: 2 });
    } catch {
      return JSON.stringify(obj, null, 2);
    }
  };

  // RBAC-001: Cluster-admin binding
  clusterRoleBindings.forEach((crb) => {
    if (crb.roleRef && crb.roleRef.name === 'cluster-admin') {
      const subjectNames = (crb.subjects || []).map((s) => `${s.kind}/${s.name}`).join(', ') || 'Unknown Subject';
      const firstSubject = crb.subjects?.[0];
      const identityName = firstSubject ? firstSubject.name : 'Unknown';
      const identityNamespace = firstSubject?.namespace || crb.metadata.namespace || 'default';

      findings.push({
        id: `finding-${scanId}-${findingCounter++}`,
        scanId,
        ruleId: 'RBAC-001',
        title: 'Cluster-admin binding',
        description: `ClusterRoleBinding '${crb.metadata.name}' grants 'cluster-admin' privileges to subject(s): ${subjectNames}.`,
        severity: 'CRITICAL',
        category: 'Privilege Escalation',
        resourceKind: crb.kind,
        resourceName: crb.metadata.name,
        namespace: crb.metadata.namespace || 'cluster-wide',
        identity: identityName,
        permission: 'cluster-admin (Full Superuser)',
        status: 'Open',
        riskExplanation: 'Any workload or service account bound to cluster-admin possesses unrestricted control over all namespaces, secrets, nodes, and cluster control plane APIs. If this identity is compromised, an attacker gains complete cluster takeover.',
        recommendation: RULE_DEFINITIONS['RBAC-001'].recommendation,
        cisReference: RULE_DEFINITIONS['RBAC-001'].cisReference,
        mitreReference: RULE_DEFINITIONS['RBAC-001'].mitreReference,
        attackPath: [
          `Workload (${identityNamespace})`,
          `ServiceAccount (${identityName})`,
          `ClusterRoleBinding (${crb.metadata.name})`,
          `ClusterRole (cluster-admin)`,
          `Cluster Control Plane (Full Takeover)`,
        ],
        blastRadius: {
          resourceSensitivity: 95,
          permissionScope: 100,
          namespaceCriticality: 90,
          privilegeEscalation: 98,
          overallScore: 96,
        },
        currentYaml: toCleanYaml({
          apiVersion: crb.apiVersion,
          kind: crb.kind,
          metadata: crb.metadata,
          subjects: crb.subjects,
          roleRef: crb.roleRef,
        }),
        suggestedYaml: `# REMEDIATED: Replaced cluster-wide cluster-admin with scoped namespace RoleBinding
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: ${crb.metadata.name}-scoped
  namespace: ${identityNamespace}
subjects:
${(crb.subjects || []).map((s) => `  - kind: ${s.kind}\n    name: ${s.name}\n    namespace: ${s.namespace || identityNamespace}`).join('\n')}
roleRef:
  kind: Role
  name: ${identityName}-least-privilege-role
  apiGroup: rbac.authorization.k8s.io`,
        reasoning: [
          'Downgraded from ClusterRoleBinding to namespace-scoped RoleBinding',
          'Removed superuser cluster-admin reference',
          'Scoped authorization to specific functional namespace only',
        ],
        potentialImpact: 'Workload will lose global cluster privileges; verify it only requires local namespace access.',
        createdAt: new Date().toISOString(),
      });
    }
  });

  // Check Role & ClusterRole rules for RBAC-002, RBAC-003, RBAC-004, RBAC-005, RBAC-012
  const allRoles = [
    ...roles.map((r) => ({ ...r, isClusterScoped: false })),
    ...clusterRoles.map((r) => ({ ...r, isClusterScoped: true })),
  ];

  allRoles.forEach((role) => {
    const rules = role.rules || [];

    rules.forEach((rule, ruleIdx) => {
      const verbs = rule.verbs || [];
      const resourcesList = rule.resources || [];

      // RBAC-002: Wildcard verbs
      if (verbs.includes('*')) {
        findings.push({
          id: `finding-${scanId}-${findingCounter++}`,
          scanId,
          ruleId: 'RBAC-002',
          title: 'Wildcard verbs in RBAC rule',
          description: `${role.kind} '${role.metadata.name}' grants wildcard verb '*' on resources: [${resourcesList.join(', ')}].`,
          severity: 'HIGH',
          category: 'Excessive Permissions',
          resourceKind: role.kind,
          resourceName: role.metadata.name,
          namespace: role.metadata.namespace || (role.isClusterScoped ? 'cluster-wide' : 'default'),
          identity: role.metadata.name,
          permission: `verbs: ['*'] on [${resourcesList.slice(0, 3).join(', ')}]`,
          status: 'Open',
          riskExplanation: 'Using "*" permits destructive verbs (delete, patch, update, deletecollection) as well as administrative binding verbs. Attackers can modify or destroy critical operational data.',
          recommendation: RULE_DEFINITIONS['RBAC-002'].recommendation,
          cisReference: RULE_DEFINITIONS['RBAC-002'].cisReference,
          mitreReference: RULE_DEFINITIONS['RBAC-002'].mitreReference,
          attackPath: [
            `${role.kind} (${role.metadata.name})`,
            `RBAC Rule #${ruleIdx + 1} with verbs: ['*']`,
            `Target Resources: [${resourcesList.slice(0, 3).join(', ')}]`,
            `Arbitrary API Modification / Resource Deletion`,
          ],
          blastRadius: {
            resourceSensitivity: 80,
            permissionScope: 90,
            namespaceCriticality: role.isClusterScoped ? 95 : 65,
            privilegeEscalation: 75,
            overallScore: 78,
          },
          currentYaml: toCleanYaml({
            apiVersion: role.apiVersion,
            kind: role.kind,
            metadata: role.metadata,
            rules: [rule],
          }),
          suggestedYaml: `# REMEDIATED: Replaced wildcard verbs with read-only least privilege
apiVersion: ${role.apiVersion || 'rbac.authorization.k8s.io/v1'}
kind: ${role.kind}
metadata:
  name: ${role.metadata.name}
  namespace: ${role.metadata.namespace || 'default'}
rules:
  - apiGroups: ${JSON.stringify(rule.apiGroups || [''])}
    resources: ${JSON.stringify(rule.resources || [])}
    verbs: ["get", "list", "watch"]`,
          reasoning: [
            'Removed wildcard verb "*"',
            'Restricted verbs to safe inspection actions ("get", "list", "watch")',
            'Eliminates unauthorized deletion and alteration attack vectors',
          ],
          potentialImpact: 'Prevents workloads using this role from executing write or delete operations.',
          createdAt: new Date().toISOString(),
        });
      }

      // RBAC-003: Wildcard resources
      if (resourcesList.includes('*')) {
        findings.push({
          id: `finding-${scanId}-${findingCounter++}`,
          scanId,
          ruleId: 'RBAC-003',
          title: 'Wildcard resources in RBAC rule',
          description: `${role.kind} '${role.metadata.name}' grants access to all resources ('*') with verbs: [${verbs.join(', ')}].`,
          severity: 'HIGH',
          category: 'Excessive Permissions',
          resourceKind: role.kind,
          resourceName: role.metadata.name,
          namespace: role.metadata.namespace || (role.isClusterScoped ? 'cluster-wide' : 'default'),
          identity: role.metadata.name,
          permission: `resources: ['*'] with verbs [${verbs.slice(0, 3).join(', ')}]`,
          status: 'Open',
          riskExplanation: 'Wildcard resource specification exposes sensitive core objects including secrets, token reviews, webhooks, and storage classes.',
          recommendation: RULE_DEFINITIONS['RBAC-003'].recommendation,
          cisReference: RULE_DEFINITIONS['RBAC-003'].cisReference,
          mitreReference: RULE_DEFINITIONS['RBAC-003'].mitreReference,
          attackPath: [
            `${role.kind} (${role.metadata.name})`,
            `Wildcard resource access ('*')`,
            `Access to sensitive resources (Secrets, CRDs, Pods)`,
            `Data Exfiltration & Service Disruption`,
          ],
          blastRadius: {
            resourceSensitivity: 85,
            permissionScope: 92,
            namespaceCriticality: role.isClusterScoped ? 90 : 70,
            privilegeEscalation: 70,
            overallScore: 82,
          },
          currentYaml: toCleanYaml({
            apiVersion: role.apiVersion,
            kind: role.kind,
            metadata: role.metadata,
            rules: [rule],
          }),
          suggestedYaml: `# REMEDIATED: Replaced wildcard resources with specific operational targets
apiVersion: ${role.apiVersion || 'rbac.authorization.k8s.io/v1'}
kind: ${role.kind}
metadata:
  name: ${role.metadata.name}
  namespace: ${role.metadata.namespace || 'default'}
rules:
  - apiGroups: [""]
    resources: ["configmaps", "services"]
    verbs: ${JSON.stringify(verbs.filter((v: string) => v !== '*'))}`,
          reasoning: [
            'Replaced wildcard resource ("*") with explicit entities ("configmaps", "services")',
            'Excludes sensitive objects like secrets, pods/exec, and nodes',
          ],
          potentialImpact: 'Any component accessing other resources will require explicit permissions.',
          createdAt: new Date().toISOString(),
        });
      }

      // RBAC-004: Broad secret access
      const hasSecrets = resourcesList.some((res) => res.toLowerCase() === 'secrets' || res === '*');
      const hasReadSecretVerbs = verbs.some((v) => ['get', 'list', 'watch', '*'].includes(v));
      if (hasSecrets && hasReadSecretVerbs) {
        findings.push({
          id: `finding-${scanId}-${findingCounter++}`,
          scanId,
          ruleId: 'RBAC-004',
          title: 'Broad secret read access',
          description: `${role.kind} '${role.metadata.name}' allows reading all Secrets in ${role.isClusterScoped ? 'the entire cluster' : `namespace '${role.metadata.namespace}'`}.`,
          severity: 'HIGH',
          category: 'Resource Exposure',
          resourceKind: role.kind,
          resourceName: role.metadata.name,
          namespace: role.metadata.namespace || (role.isClusterScoped ? 'cluster-wide' : 'default'),
          identity: role.metadata.name,
          permission: `secrets [${verbs.join(', ')}]`,
          status: 'Open',
          riskExplanation: 'Unrestricted secret reading exposes confidential application passwords, JWT signing keys, TLS private keys, and cloud provider access credentials to any caller.',
          recommendation: RULE_DEFINITIONS['RBAC-004'].recommendation,
          cisReference: RULE_DEFINITIONS['RBAC-004'].cisReference,
          mitreReference: RULE_DEFINITIONS['RBAC-004'].mitreReference,
          attackPath: [
            `${role.kind} (${role.metadata.name})`,
            `Read access to 'secrets'`,
            `Credential Harvesting (Database passwords, API tokens)`,
            `Lateral Movement across Infrastructure`,
          ],
          blastRadius: {
            resourceSensitivity: 92,
            permissionScope: 80,
            namespaceCriticality: 85,
            privilegeEscalation: 82,
            overallScore: 85,
          },
          currentYaml: toCleanYaml({
            apiVersion: role.apiVersion,
            kind: role.kind,
            metadata: role.metadata,
            rules: [rule],
          }),
          suggestedYaml: `# REMEDIATED: Restricted secret access to specific named secret resource
apiVersion: ${role.apiVersion || 'rbac.authorization.k8s.io/v1'}
kind: ${role.kind}
metadata:
  name: ${role.metadata.name}
  namespace: ${role.metadata.namespace || 'default'}
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    resourceNames: ["app-specific-config-secret"]
    verbs: ["get"]`,
          reasoning: [
            'Constrained access using resourceNames filter',
            'Removed "list" and "watch" verbs to block bulk credential discovery',
          ],
          potentialImpact: 'Workloads can only retrieve the designated secret key.',
          createdAt: new Date().toISOString(),
        });
      }

      // RBAC-005: Pod exec permission
      const hasExec = resourcesList.some((res) => res.toLowerCase() === 'pods/exec' || res === '*');
      const hasExecVerb = verbs.some((v) => ['create', '*', 'get'].includes(v));
      if (hasExec && hasExecVerb) {
        findings.push({
          id: `finding-${scanId}-${findingCounter++}`,
          scanId,
          ruleId: 'RBAC-005',
          title: 'Pod exec permission granted',
          description: `${role.kind} '${role.metadata.name}' permits interactive terminal execution ('pods/exec') on pods.`,
          severity: 'HIGH',
          category: 'Privilege Escalation',
          resourceKind: role.kind,
          resourceName: role.metadata.name,
          namespace: role.metadata.namespace || (role.isClusterScoped ? 'cluster-wide' : 'default'),
          identity: role.metadata.name,
          permission: 'pods/exec create',
          status: 'Open',
          riskExplanation: 'Executing commands inside pods allows attackers who compromise this identity to run arbitrary binaries, dump memory, access mounted secrets, and pivot to adjacent microservices.',
          recommendation: RULE_DEFINITIONS['RBAC-005'].recommendation,
          cisReference: RULE_DEFINITIONS['RBAC-005'].cisReference,
          mitreReference: RULE_DEFINITIONS['RBAC-005'].mitreReference,
          attackPath: [
            `${role.kind} (${role.metadata.name})`,
            `Permission to create 'pods/exec'`,
            `Interactive Remote Code Execution inside Workloads`,
            `Lateral Network Pivoting`,
          ],
          blastRadius: {
            resourceSensitivity: 88,
            permissionScope: 85,
            namespaceCriticality: 80,
            privilegeEscalation: 90,
            overallScore: 86,
          },
          currentYaml: toCleanYaml({
            apiVersion: role.apiVersion,
            kind: role.kind,
            metadata: role.metadata,
            rules: [rule],
          }),
          suggestedYaml: `# REMEDIATED: Replaced interactive pods/exec with safe log inspection
apiVersion: ${role.apiVersion || 'rbac.authorization.k8s.io/v1'}
kind: ${role.kind}
metadata:
  name: ${role.metadata.name}
  namespace: ${role.metadata.namespace || 'default'}
rules:
  - apiGroups: [""]
    resources: ["pods/log"]
    verbs: ["get"]`,
          reasoning: [
            'Removed "pods/exec" capability',
            'Substituted read-only container logs "pods/log" for debugging purposes',
          ],
          potentialImpact: 'Automated processes can no longer execute commands inside pods directly.',
          createdAt: new Date().toISOString(),
        });
      }

      // RBAC-012: Excessive RBAC management permissions
      const hasRbacManagement = resourcesList.some((res) => ['roles', 'rolebindings', 'clusterroles', 'clusterrolebindings'].includes(res.toLowerCase()));
      const hasEscalatingVerbs = verbs.some((v) => ['create', 'update', 'patch', 'bind', 'escalate', '*'].includes(v));
      if (hasRbacManagement && hasEscalatingVerbs) {
        findings.push({
          id: `finding-${scanId}-${findingCounter++}`,
          scanId,
          ruleId: 'RBAC-012',
          title: 'Excessive RBAC management permissions',
          description: `${role.kind} '${role.metadata.name}' can create/modify RBAC bindings or roles, allowing privilege escalation.`,
          severity: 'HIGH',
          category: 'Privilege Escalation',
          resourceKind: role.kind,
          resourceName: role.metadata.name,
          namespace: role.metadata.namespace || 'default',
          identity: role.metadata.name,
          permission: `RBAC modification: [${resourcesList.join(', ')}] [${verbs.join(', ')}]`,
          status: 'Open',
          riskExplanation: 'An identity that can create or edit RoleBindings can grant itself cluster-admin or any other role, achieving complete privilege escalation.',
          recommendation: RULE_DEFINITIONS['RBAC-012'].recommendation,
          cisReference: RULE_DEFINITIONS['RBAC-012'].cisReference,
          mitreReference: RULE_DEFINITIONS['RBAC-012'].mitreReference,
          attackPath: [
            `${role.kind} (${role.metadata.name})`,
            `create/update on RoleBindings`,
            `Bind own ServiceAccount to high-privilege Role`,
            `Arbitrary Privilege Escalation`,
          ],
          blastRadius: {
            resourceSensitivity: 94,
            permissionScope: 90,
            namespaceCriticality: 88,
            privilegeEscalation: 96,
            overallScore: 92,
          },
          currentYaml: toCleanYaml({
            apiVersion: role.apiVersion,
            kind: role.kind,
            metadata: role.metadata,
            rules: [rule],
          }),
          suggestedYaml: `# REMEDIATED: Removed RBAC modification rights
apiVersion: ${role.apiVersion || 'rbac.authorization.k8s.io/v1'}
kind: ${role.kind}
metadata:
  name: ${role.metadata.name}
  namespace: ${role.metadata.namespace || 'default'}
rules:
  - apiGroups: ["apps"]
    resources: ["deployments"]
    verbs: ["get", "list", "watch"]`,
          reasoning: [
            'Revoked access to rbac.authorization.k8s.io resources',
            'Precludes self-binding to higher authorization levels',
          ],
          potentialImpact: 'Workload cannot manipulate RBAC objects.',
          createdAt: new Date().toISOString(),
        });
      }
    });
  });

  // RBAC-006: Excessive cluster-wide permissions
  clusterRoleBindings.forEach((crb) => {
    if (crb.roleRef && crb.roleRef.name !== 'cluster-admin') {
      const referencedCR = clusterRoles.find((cr) => cr.metadata.name === crb.roleRef?.name);
      if (referencedCR) {
        const hasBroadVerbs = (referencedCR.rules || []).some((r: any) =>
          (r.verbs || []).some((v: string) => ['create', 'update', 'delete', 'patch', '*'].includes(v))
        );
        if (hasBroadVerbs) {
          findings.push({
            id: `finding-${scanId}-${findingCounter++}`,
            scanId,
            ruleId: 'RBAC-006',
            title: 'Excessive cluster-wide permissions',
            description: `ClusterRoleBinding '${crb.metadata.name}' binds '${referencedCR.metadata.name}' with mutating permissions across all namespaces.`,
            severity: 'HIGH',
            category: 'Excessive Permissions',
            resourceKind: crb.kind,
            resourceName: crb.metadata.name,
            namespace: 'cluster-wide',
            identity: crb.subjects?.[0]?.name || 'ServiceAccount',
            permission: `ClusterRole/${referencedCR.metadata.name} across all namespaces`,
            status: 'Open',
            riskExplanation: 'Binding write/delete permissions cluster-wide breaks namespace isolation boundaries, enabling a fault or breach in one tenant to compromise the entire cluster.',
            recommendation: RULE_DEFINITIONS['RBAC-006'].recommendation,
            cisReference: RULE_DEFINITIONS['RBAC-006'].cisReference,
            mitreReference: RULE_DEFINITIONS['RBAC-006'].mitreReference,
            attackPath: [
              `ClusterRoleBinding (${crb.metadata.name})`,
              `ClusterRole (${referencedCR.metadata.name})`,
              `Cluster-wide write authorization`,
              `Multi-tenant boundary compromise`,
            ],
            blastRadius: {
              resourceSensitivity: 80,
              permissionScope: 88,
              namespaceCriticality: 90,
              privilegeEscalation: 75,
              overallScore: 83,
            },
            currentYaml: toCleanYaml(crb),
            suggestedYaml: `# REMEDIATED: Replaced with namespace-scoped RoleBinding
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: ${crb.metadata.name}-scoped
  namespace: default
subjects:
${(crb.subjects || []).map((s) => `  - kind: ${s.kind}\n    name: ${s.name}\n    namespace: ${s.namespace || 'default'}`).join('\n')}
roleRef:
  kind: ClusterRole
  name: ${crb.roleRef.name}
  apiGroup: rbac.authorization.k8s.io`,
            reasoning: [
              'Converts global ClusterRoleBinding into a namespace-confined RoleBinding',
              'Preserves necessary workload functionality without exposing the rest of the cluster',
            ],
            potentialImpact: 'Permissions will apply only within the target namespace.',
            createdAt: new Date().toISOString(),
          });
        }
      }
    }
  });

  // Pod & Deployment security inspection: RBAC-007, RBAC-008, RBAC-009, RBAC-010, RBAC-011
  const workloads = [...pods, ...deployments];

  workloads.forEach((w) => {
    const podSpec = w.kind.toLowerCase() === 'deployment' ? w.spec?.template?.spec : w.spec;
    if (!podSpec) return;

    const saName = podSpec.serviceAccountName || podSpec.serviceAccount || 'default';
    const containers = [...(podSpec.containers || []), ...(podSpec.initContainers || [])];

    // RBAC-007: Default ServiceAccount usage
    if (saName === 'default') {
      findings.push({
        id: `finding-${scanId}-${findingCounter++}`,
        scanId,
        ruleId: 'RBAC-007',
        title: 'Default ServiceAccount usage',
        description: `${w.kind} '${w.metadata.name}' executes with the 'default' ServiceAccount in namespace '${w.metadata.namespace}'.`,
        severity: 'MEDIUM',
        category: 'Identity Security',
        resourceKind: w.kind,
        resourceName: w.metadata.name,
        namespace: w.metadata.namespace || 'default',
        identity: 'default',
        permission: 'Default namespace token',
        status: 'Open',
        riskExplanation: 'Using the default ServiceAccount creates an identity collision where all unassigned workloads share the same API credentials. Any privilege granted to one pod is automatically shared by all others.',
        recommendation: RULE_DEFINITIONS['RBAC-007'].recommendation,
        cisReference: RULE_DEFINITIONS['RBAC-007'].cisReference,
        mitreReference: RULE_DEFINITIONS['RBAC-007'].mitreReference,
        attackPath: [
          `${w.kind} (${w.metadata.name})`,
          `Shared Identity (ServiceAccount/default)`,
          `Namespace Token Inheritance`,
          `Cross-workload Identity Impersonation`,
        ],
        blastRadius: {
          resourceSensitivity: 50,
          permissionScope: 55,
          namespaceCriticality: 60,
          privilegeEscalation: 50,
          overallScore: 54,
        },
        currentYaml: toCleanYaml(w),
        suggestedYaml: `# REMEDIATED: Specify dedicated ServiceAccount
${toCleanYaml({
  ...w,
  spec: w.kind.toLowerCase() === 'deployment' 
    ? {
        ...w.spec,
        template: {
          ...w.spec?.template,
          spec: {
            ...podSpec,
            serviceAccountName: `${w.metadata.name}-sa`,
            automountServiceAccountToken: false,
          }
        }
      }
    : {
        ...podSpec,
        serviceAccountName: `${w.metadata.name}-sa`,
        automountServiceAccountToken: false,
      }
})}`,
        reasoning: [
          'Created isolated identity for the workload',
          'Disabled automatic token mounting (automountServiceAccountToken: false) to prevent credential leakage',
        ],
        potentialImpact: 'Workload must be paired with its own ServiceAccount declaration.',
        createdAt: new Date().toISOString(),
      });
    }

    // RBAC-008: Privileged container
    const privilegedContainer = containers.find((c) => c.securityContext?.privileged === true);
    if (privilegedContainer) {
      findings.push({
        id: `finding-${scanId}-${findingCounter++}`,
        scanId,
        ruleId: 'RBAC-008',
        title: 'Privileged container execution',
        description: `${w.kind} '${w.metadata.name}' container '${privilegedContainer.name}' runs with securityContext.privileged: true.`,
        severity: 'CRITICAL',
        category: 'Pod Security',
        resourceKind: w.kind,
        resourceName: w.metadata.name,
        namespace: w.metadata.namespace || 'default',
        identity: saName,
        permission: 'Host Kernel / Device Root Access',
        status: 'Open',
        riskExplanation: 'A privileged container has access to all host kernel devices, can bypass cgroups and AppArmor/SELinux profiles, and can easily break out of the container to compromise the underlying node.',
        recommendation: RULE_DEFINITIONS['RBAC-008'].recommendation,
        cisReference: RULE_DEFINITIONS['RBAC-008'].cisReference,
        mitreReference: RULE_DEFINITIONS['RBAC-008'].mitreReference,
        attackPath: [
          `${w.kind} (${w.metadata.name})`,
          `Container (${privilegedContainer.name}) with privileged: true`,
          `Host Device / Kernel Access (/dev, /sys, /proc)`,
          `Container Escape to Underlying Node Kernel`,
        ],
        blastRadius: {
          resourceSensitivity: 100,
          permissionScope: 98,
          namespaceCriticality: 95,
          privilegeEscalation: 100,
          overallScore: 98,
        },
        currentYaml: toCleanYaml(w),
        suggestedYaml: `# REMEDIATED: Disabled privileged execution and enforced least-privilege securityContext
securityContext:
  privileged: false
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  runAsNonRoot: true
  capabilities:
    drop:
      - ALL`,
        reasoning: [
          'Set privileged: false to restore container isolation',
          'Enforced allowPrivilegeEscalation: false',
          'Dropped all Linux POSIX capabilities',
        ],
        potentialImpact: 'Container cannot perform raw device I/O or kernel module operations.',
        createdAt: new Date().toISOString(),
      });
    }

    // RBAC-009: Host network
    if (podSpec.hostNetwork === true) {
      findings.push({
        id: `finding-${scanId}-${findingCounter++}`,
        scanId,
        ruleId: 'RBAC-009',
        title: 'Host network namespace enabled',
        description: `${w.kind} '${w.metadata.name}' runs with hostNetwork: true, sharing the host networking namespace.`,
        severity: 'HIGH',
        category: 'Pod Security',
        resourceKind: w.kind,
        resourceName: w.metadata.name,
        namespace: w.metadata.namespace || 'default',
        identity: saName,
        permission: 'Host Network Interfaces',
        status: 'Open',
        riskExplanation: 'The container can bind to host ports, sniff loopback traffic of other processes on the host node, and bypass Kubernetes NetworkPolicies.',
        recommendation: RULE_DEFINITIONS['RBAC-009'].recommendation,
        cisReference: RULE_DEFINITIONS['RBAC-009'].cisReference,
        mitreReference: RULE_DEFINITIONS['RBAC-009'].mitreReference,
        attackPath: [
          `${w.kind} (${w.metadata.name})`,
          `hostNetwork: true`,
          `Host Interface Sniffing (127.0.0.1, eth0)`,
          `Bypass of NetworkPolicies & Ingress Controls`,
        ],
        blastRadius: {
          resourceSensitivity: 85,
          permissionScope: 82,
          namespaceCriticality: 80,
          privilegeEscalation: 84,
          overallScore: 83,
        },
        currentYaml: toCleanYaml(w),
        suggestedYaml: `# REMEDIATED: Removed hostNetwork and use standard container networking
spec:
  hostNetwork: false`,
        reasoning: [
          'Restores pod SDN network isolation',
          'Ensures NetworkPolicies apply correctly to incoming and outgoing traffic',
        ],
        potentialImpact: 'Workload cannot directly bind to node host ports.',
        createdAt: new Date().toISOString(),
      });
    }

    // RBAC-010: Host PID
    if (podSpec.hostPID === true) {
      findings.push({
        id: `finding-${scanId}-${findingCounter++}`,
        scanId,
        ruleId: 'RBAC-010',
        title: 'Host PID namespace sharing',
        description: `${w.kind} '${w.metadata.name}' runs with hostPID: true, exposing all host node processes.`,
        severity: 'HIGH',
        category: 'Pod Security',
        resourceKind: w.kind,
        resourceName: w.metadata.name,
        namespace: w.metadata.namespace || 'default',
        identity: saName,
        permission: 'Host Process Space',
        status: 'Open',
        riskExplanation: 'Access to the host PID namespace lets a container inspect environment variables, read file descriptors, and send signals (e.g. SIGKILL) to processes outside the container.',
        recommendation: RULE_DEFINITIONS['RBAC-010'].recommendation,
        cisReference: RULE_DEFINITIONS['RBAC-010'].cisReference,
        mitreReference: RULE_DEFINITIONS['RBAC-010'].mitreReference,
        attackPath: [
          `${w.kind} (${w.metadata.name})`,
          `hostPID: true`,
          `Process Table Inspection (/proc)`,
          `Inter-process Signal Injection & Container Escape`,
        ],
        blastRadius: {
          resourceSensitivity: 90,
          permissionScope: 85,
          namespaceCriticality: 82,
          privilegeEscalation: 88,
          overallScore: 86,
        },
        currentYaml: toCleanYaml(w),
        suggestedYaml: `# REMEDIATED: Disabled hostPID
spec:
  hostPID: false`,
        reasoning: ['Isolates process space to within the container namespace'],
        potentialImpact: 'Container cannot monitor or trace host processes.',
        createdAt: new Date().toISOString(),
      });
    }

    // RBAC-011: Host filesystem access via hostPath volume
    const volumes = podSpec.volumes || [];
    const hostPathVolume = volumes.find((v: any) => v.hostPath);
    if (hostPathVolume) {
      findings.push({
        id: `finding-${scanId}-${findingCounter++}`,
        scanId,
        ruleId: 'RBAC-011',
        title: 'Host filesystem access via hostPath volume',
        description: `${w.kind} '${w.metadata.name}' mounts hostPath '${hostPathVolume.hostPath.path}' into volume '${hostPathVolume.name}'.`,
        severity: 'HIGH',
        category: 'Pod Security',
        resourceKind: w.kind,
        resourceName: w.metadata.name,
        namespace: w.metadata.namespace || 'default',
        identity: saName,
        permission: `Host filesystem: ${hostPathVolume.hostPath.path}`,
        status: 'Open',
        riskExplanation: 'Mounting sensitive host paths (such as the docker socket, /etc, or root) allows containers to read host secrets, alter host binaries, or create unauthorized root users.',
        recommendation: RULE_DEFINITIONS['RBAC-011'].recommendation,
        cisReference: RULE_DEFINITIONS['RBAC-011'].cisReference,
        mitreReference: RULE_DEFINITIONS['RBAC-011'].mitreReference,
        attackPath: [
          `${w.kind} (${w.metadata.name})`,
          `Volume (${hostPathVolume.name}) -> ${hostPathVolume.hostPath.path}`,
          `Host Disk Read/Write Access`,
          `Node Takeover / Host Persistence`,
        ],
        blastRadius: {
          resourceSensitivity: 94,
          permissionScope: 88,
          namespaceCriticality: 85,
          privilegeEscalation: 92,
          overallScore: 90,
        },
        currentYaml: toCleanYaml(w),
        suggestedYaml: `# REMEDIATED: Replaced hostPath volume with emptyDir or PVC
volumes:
  - name: ${hostPathVolume.name}
    emptyDir: {}`,
        reasoning: [
          'Eliminated dangerous host filesystem bind mount',
          'Safely swapped with isolated emptyDir volume',
        ],
        potentialImpact: 'Workload cannot read or modify the underlying host node filesystem.',
        createdAt: new Date().toISOString(),
      });
    }
  });

  return findings;
}

export function calculateSecurityScore(findings: Finding[]): number {
  let score = 100;

  findings.forEach((f) => {
    if (f.status === 'Resolved' || f.status === 'Ignored') return;

    switch (f.severity) {
      case 'CRITICAL':
        score -= 20;
        break;
      case 'HIGH':
        score -= 10;
        break;
      case 'MEDIUM':
        score -= 5;
        break;
      case 'LOW':
        score -= 2;
        break;
      default:
        break;
    }
  });

  return Math.max(0, Math.min(100, score));
}
