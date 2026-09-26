import { AttackGraphData, ExploitationStep, Finding, Severity } from '../types/rbac';
import { ParsedK8sResource } from './k8s-parser';

export function buildAttackGraph(resources: ParsedK8sResource[], findings: Finding[]): {
  graph: AttackGraphData;
  steps: ExploitationStep[];
  criticalPathCount: number;
} {
  const nodesMap = new Map<string, any>();
  const edgesMap = new Map<string, any>();

  let xWorkload = 80;
  let xIdentity = 360;
  let xBinding = 640;
  let xRole = 920;
  let xTarget = 1200;

  let yWorkload = 60;
  let yIdentity = 60;
  let yBinding = 60;
  let yRole = 60;
  let yTarget = 60;

  // Track critical subjects and roles from findings
  const criticalFindings = findings.filter((f) => f.severity === 'CRITICAL' || f.severity === 'HIGH');
  const criticalIdentities = new Set<string>();
  const criticalBindings = new Set<string>();

  criticalFindings.forEach((f) => {
    if (f.identity) criticalIdentities.add(f.identity.toLowerCase());
    if (f.resourceKind.toLowerCase().includes('binding')) {
      criticalBindings.add(f.resourceName.toLowerCase());
    }
  });

  // 1. Process Workloads (Pod, Deployment)
  const workloads = resources.filter((r) => ['pod', 'deployment'].includes(r.kind.toLowerCase()));
  workloads.forEach((w) => {
    const id = `workload-${w.metadata.name}`;
    const podSpec = w.kind.toLowerCase() === 'deployment' ? w.spec?.template?.spec : w.spec;
    const saName = podSpec?.serviceAccountName || podSpec?.serviceAccount || 'default';
    const isPrivileged = (podSpec?.containers || []).some((c: any) => c.securityContext?.privileged === true);
    const isCritical = isPrivileged || criticalIdentities.has(saName.toLowerCase());

    nodesMap.set(id, {
      id,
      type: 'default',
      position: { x: xWorkload, y: yWorkload },
      data: {
        label: `${w.kind}: ${w.metadata.name}`,
        name: w.metadata.name,
        kind: w.kind,
        namespace: w.metadata.namespace,
        severity: isCritical ? ('CRITICAL' as Severity) : ('LOW' as Severity),
        isPrivileged,
        risk: isPrivileged ? 'Privileged Container Access' : 'Normal Workload',
        permissions: isPrivileged ? ['HOST_ROOT_DEVICES', 'SYS_ADMIN'] : ['STANDARD_POD'],
      },
    });
    yWorkload += 140;

    // Connect Workload to ServiceAccount
    const saId = `sa-${saName}`;
    const edgeId = `edge-${id}-to-${saId}`;
    edgesMap.set(edgeId, {
      id: edgeId,
      source: id,
      target: saId,
      label: 'uses identity',
      animated: isCritical,
      data: { isCriticalPath: isCritical },
      style: {
        stroke: isCritical ? '#EF4444' : '#263244',
        strokeWidth: isCritical ? 2.5 : 1.5,
      },
    });
  });

  // 2. Process ServiceAccounts
  const serviceAccounts = resources.filter((r) => r.kind.toLowerCase() === 'serviceaccount');
  // Include inferred SAs from workloads
  const allSaNames = new Set(serviceAccounts.map((sa) => sa.metadata.name));
  workloads.forEach((w) => {
    const podSpec = w.kind.toLowerCase() === 'deployment' ? w.spec?.template?.spec : w.spec;
    const saName = podSpec?.serviceAccountName || podSpec?.serviceAccount || 'default';
    allSaNames.add(saName);
  });

  allSaNames.forEach((saName) => {
    const id = `sa-${saName}`;
    const isCritical = criticalIdentities.has(saName.toLowerCase());

    nodesMap.set(id, {
      id,
      type: 'default',
      position: { x: xIdentity, y: yIdentity },
      data: {
        label: `ServiceAccount: ${saName}`,
        name: saName,
        kind: 'ServiceAccount',
        namespace: 'default',
        severity: isCritical ? ('CRITICAL' as Severity) : ('LOW' as Severity),
        risk: isCritical ? 'Privilege Escalation Vector' : 'Standard Service Identity',
        permissions: isCritical ? ['AUTOMOUNT_TOKEN', 'BOUND_PRIVILEGES'] : ['DEFAULT_TOKEN'],
      },
    });
    yIdentity += 130;
  });

  // 3. Process Bindings (RoleBinding, ClusterRoleBinding)
  const bindings = resources.filter((r) => ['rolebinding', 'clusterrolebinding'].includes(r.kind.toLowerCase()));
  bindings.forEach((b) => {
    const id = `binding-${b.metadata.name}`;
    const isCluster = b.kind.toLowerCase() === 'clusterrolebinding';
    const isClusterAdmin = b.roleRef?.name === 'cluster-admin';
    const isCritical = isClusterAdmin || criticalBindings.has(b.metadata.name.toLowerCase());

    nodesMap.set(id, {
      id,
      type: 'default',
      position: { x: xBinding, y: yBinding },
      data: {
        label: `${b.kind}: ${b.metadata.name}`,
        name: b.metadata.name,
        kind: b.kind,
        namespace: isCluster ? 'cluster-wide' : b.metadata.namespace,
        severity: isCritical ? ('CRITICAL' as Severity) : isCluster ? ('HIGH' as Severity) : ('MEDIUM' as Severity),
        risk: isClusterAdmin ? 'Grants Cluster-Admin Superuser' : isCluster ? 'Cluster-Wide Scope' : 'Namespace Scoped',
        permissions: [b.roleRef?.name || 'unknown-role'],
      },
    });
    yBinding += 140;

    // Connect SA to Binding
    (b.subjects || []).forEach((subj: any) => {
      const saId = `sa-${subj.name}`;
      if (nodesMap.has(saId)) {
        const edgeId = `edge-${saId}-to-${id}`;
        edgesMap.set(edgeId, {
          id: edgeId,
          source: saId,
          target: id,
          label: 'bound by',
          animated: isCritical,
          data: { isCriticalPath: isCritical },
          style: {
            stroke: isCritical ? '#EF4444' : '#263244',
            strokeWidth: isCritical ? 2.5 : 1.5,
          },
        });
      }
    });

    // Connect Binding to Role
    if (b.roleRef) {
      const roleId = `role-${b.roleRef.name}`;
      const edgeId = `edge-${id}-to-${roleId}`;
      edgesMap.set(edgeId, {
        id: edgeId,
        source: id,
        target: roleId,
        label: 'references',
        animated: isCritical,
        data: { isCriticalPath: isCritical },
        style: {
          stroke: isCritical ? '#EF4444' : '#263244',
          strokeWidth: isCritical ? 2.5 : 1.5,
        },
      });
    }
  });

  // 4. Process Roles and ClusterRoles
  const roles = resources.filter((r) => ['role', 'clusterrole'].includes(r.kind.toLowerCase()));
  // Also guarantee cluster-admin node exists if referenced
  const allRoleNames = new Set(roles.map((r) => r.metadata.name));
  bindings.forEach((b) => {
    if (b.roleRef?.name) allRoleNames.add(b.roleRef.name);
  });

  allRoleNames.forEach((roleName) => {
    const id = `role-${roleName}`;
    const roleObj = roles.find((r) => r.metadata.name === roleName);
    const isClusterAdmin = roleName === 'cluster-admin';
    const isCritical = isClusterAdmin || criticalFindings.some((f) => f.resourceName === roleName);

    const rules = roleObj?.rules || [];
    const verbsSummary = rules.flatMap((r: any) => r.verbs || []);
    const resourcesSummary = rules.flatMap((r: any) => r.resources || []);

    nodesMap.set(id, {
      id,
      type: 'default',
      position: { x: xRole, y: yRole },
      data: {
        label: `${isClusterAdmin ? 'ClusterRole' : roleObj?.kind || 'Role'}: ${roleName}`,
        name: roleName,
        kind: isClusterAdmin ? 'ClusterRole' : roleObj?.kind || 'Role',
        namespace: isClusterAdmin ? 'cluster-wide' : roleObj?.metadata?.namespace || 'default',
        severity: isCritical ? ('CRITICAL' as Severity) : ('LOW' as Severity),
        risk: isClusterAdmin ? 'Full Superuser API Authority' : isCritical ? 'Dangerous Permissions' : 'Scoped Authorization',
        permissions: isClusterAdmin ? ['* (ALL VERBS & RESOURCES)'] : verbsSummary.slice(0, 4),
      },
    });
    yRole += 140;

    // Connect Role to Target Resource
    const targetId = isClusterAdmin ? 'target-cluster-control-plane' : `target-${resourcesSummary[0] || 'k8s-api'}`;
    const edgeId = `edge-${id}-to-${targetId}`;
    edgesMap.set(edgeId, {
      id: edgeId,
      source: id,
      target: targetId,
      label: 'grants authority',
      animated: isCritical,
      data: { isCriticalPath: isCritical },
      style: {
        stroke: isCritical ? '#EF4444' : '#263244',
        strokeWidth: isCritical ? 2.5 : 1.5,
      },
    });
  });

  // 5. Target Nodes (Sensitive Resources / Control Plane)
  nodesMap.set('target-cluster-control-plane', {
    id: 'target-cluster-control-plane',
    type: 'default',
    position: { x: xTarget, y: 100 },
    data: {
      label: 'Target: Cluster Control Plane',
      name: 'Cluster Control Plane',
      kind: 'Sensitive Resource',
      namespace: 'cluster-wide',
      severity: 'CRITICAL',
      isPrivileged: true,
      risk: 'Complete Cluster Takeover / Unrestricted Superuser',
      permissions: ['ALL_NAMESPACES', 'ETCD_CONTROL', 'NODE_DRAIN', 'SECRETS_DUMP'],
    },
  });

  nodesMap.set('target-secrets', {
    id: 'target-secrets',
    type: 'default',
    position: { x: xTarget, y: 260 },
    data: {
      label: 'Target: Namespace Secrets & TLS',
      name: 'Kubernetes Secrets',
      kind: 'Sensitive Resource',
      namespace: 'production/payments',
      severity: 'HIGH',
      risk: 'Confidential API keys, DB credentials, and TLS certificates',
      permissions: ['READ_ALL_SECRETS', 'TOKEN_EXTRACTION'],
    },
  });

  nodesMap.set('target-pods/exec', {
    id: 'target-pods/exec',
    type: 'default',
    position: { x: xTarget, y: 420 },
    data: {
      label: 'Target: Pod Interactive Exec',
      name: 'pods/exec',
      kind: 'Sensitive Resource',
      namespace: 'all workloads',
      severity: 'HIGH',
      risk: 'Arbitrary container shell injection and pivot',
      permissions: ['REMOTE_SHELL', 'PROCESS_INJECTION'],
    },
  });

  // Build exploitation simulation steps
  const steps: ExploitationStep[] = [
    {
      step: 1,
      title: 'Initial Workload Compromise',
      nodeId: Array.from(nodesMap.keys()).find((k) => k.startsWith('workload-')) || 'workload-payment-pod',
      action: 'Adversary discovers remote code execution (RCE) or container breakout in application layer.',
      privilegeGained: 'Shell execution within container boundary.',
      impact: 'Attacker gains access to local filesystem and default mounted service account token.',
    },
    {
      step: 2,
      title: 'ServiceAccount Credential Extraction',
      nodeId: Array.from(nodesMap.keys()).find((k) => k.startsWith('sa-')) || 'sa-payment-sa',
      action: 'Extracts JWT bearer token from /var/run/secrets/kubernetes.io/serviceaccount/token.',
      privilegeGained: 'Authenticated Kubernetes API identity as ServiceAccount.',
      impact: 'Permits authenticating to the Kubernetes API server from inside or outside the cluster.',
    },
    {
      step: 3,
      title: 'RBAC Binding Discovery',
      nodeId: Array.from(nodesMap.keys()).find((k) => k.startsWith('binding-')) || 'binding-payment-admin',
      action: 'Queries "kubectl auth can-i" or lists RBAC bindings associated with the identity.',
      privilegeGained: 'Discovers binding to privileged Role or ClusterRole.',
      impact: 'Identifies unconstrained cluster-admin or wildcard authorization vectors.',
    },
    {
      step: 4,
      title: 'Privilege Escalation Execution',
      nodeId: Array.from(nodesMap.keys()).find((k) => k.startsWith('role-')) || 'role-cluster-admin',
      action: 'Uses granted permissions to interact with API server without security gate inspection.',
      privilegeGained: 'Elevated or superuser capabilities across the API hierarchy.',
      impact: 'Bypasses namespace boundaries and executes privileged API requests.',
    },
    {
      step: 5,
      title: 'Full Cluster Compromise',
      nodeId: 'target-cluster-control-plane',
      action: 'Accesses etcd secrets, deploys malicious daemonsets, drains nodes, or extracts cloud provider IAM tokens.',
      privilegeGained: 'Complete administrative control over cluster and underlying cloud infrastructure.',
      impact: 'Total compromise of confidentiality, integrity, and availability.',
    },
  ];

  const criticalPathCount = Array.from(edgesMap.values()).filter((e) => e.data?.isCriticalPath).length;

  return {
    graph: {
      nodes: Array.from(nodesMap.values()),
      edges: Array.from(edgesMap.values()),
    },
    steps,
    criticalPathCount,
  };
}
