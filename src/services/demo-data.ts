import { ComplianceControl, Finding, ResourceCounts, Scan } from '../types/rbac';

export const DEMO_YAML_MANIFEST = `---
apiVersion: v1
kind: Namespace
metadata:
  name: payments
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: payment-sa
  namespace: payments
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: payment-admin
subjects:
  - kind: ServiceAccount
    name: payment-sa
    namespace: payments
roleRef:
  kind: ClusterRole
  name: cluster-admin
  apiGroup: rbac.authorization.k8s.io
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: payment-service
  namespace: payments
spec:
  replicas: 2
  selector:
    matchLabels:
      app: payment-api
  template:
    metadata:
      labels:
        app: payment-api
    spec:
      serviceAccountName: payment-sa
      containers:
        - name: payment-api
          image: internal.registry/payments/api:v2.4
          securityContext:
            privileged: true
          ports:
            - containerPort: 8080
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: dev-role
  namespace: development
rules:
  - apiGroups: ["*"]
    resources: ["*"]
    verbs: ["*"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: secret-reader
  namespace: payments
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: pod-debugger-role
  namespace: default
rules:
  - apiGroups: [""]
    resources: ["pods/exec"]
    verbs: ["create", "get"]
---
apiVersion: v1
kind: Pod
metadata:
  name: network-sniffer-pod
  namespace: monitoring
spec:
  serviceAccountName: default
  hostNetwork: true
  hostPID: true
  volumes:
    - name: host-root
      hostPath:
        path: /
  containers:
    - name: sniffer
      image: alpine:latest
      command: ["sleep", "3600"]
`;

export const VULNERABILITY_PRESETS = [
  {
    id: 'preset-cluster-admin',
    name: 'Cluster-Admin Binding',
    badge: 'CRITICAL',
    badgeColor: 'text-[#EF4444] bg-[#EF4444]/10 border-[#EF4444]/30',
    description: 'ServiceAccount bound directly to superuser cluster-admin',
    yaml: `apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: payment-admin
subjects:
  - kind: ServiceAccount
    name: payment-sa
    namespace: payments
roleRef:
  kind: ClusterRole
  name: cluster-admin
  apiGroup: rbac.authorization.k8s.io
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: payment-sa
  namespace: payments
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: payment-service
  namespace: payments
spec:
  selector:
    matchLabels:
      app: payment-api
  template:
    metadata:
      labels:
        app: payment-api
    spec:
      serviceAccountName: payment-sa
      containers:
        - name: payment-api
          image: nginx:alpine`,
  },
  {
    id: 'preset-wildcards',
    name: 'Wildcard Permissions',
    badge: 'HIGH',
    badgeColor: 'text-[#F59E0B] bg-[#F59E0B]/10 border-[#F59E0B]/30',
    description: 'Role with unrestricted wildcard verbs & resources ("*")',
    yaml: `apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: dev-role
  namespace: development
rules:
  - apiGroups: ["*"]
    resources: ["*"]
    verbs: ["*"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: dev-binding
  namespace: development
subjects:
  - kind: ServiceAccount
    name: developer-sa
    namespace: development
roleRef:
  kind: Role
  name: dev-role
  apiGroup: rbac.authorization.k8s.io`,
  },
  {
    id: 'preset-privileged-pod',
    name: 'Privileged Pod & Escape',
    badge: 'CRITICAL',
    badgeColor: 'text-[#EF4444] bg-[#EF4444]/10 border-[#EF4444]/30',
    description: 'Container with privileged: true, hostNetwork and hostPID',
    yaml: `apiVersion: v1
kind: Pod
metadata:
  name: maintenance-agent
  namespace: default
spec:
  hostNetwork: true
  hostPID: true
  containers:
    - name: agent
      image: alpine:latest
      securityContext:
        privileged: true
      volumeMounts:
        - mountPath: /host
          name: host-vol
  volumes:
    - name: host-vol
      hostPath:
        path: /var/run/docker.sock`,
  },
  {
    id: 'preset-secrets',
    name: 'Broad Secrets Access',
    badge: 'HIGH',
    badgeColor: 'text-[#F59E0B] bg-[#F59E0B]/10 border-[#F59E0B]/30',
    description: 'Role granting get, list, watch on all secrets',
    yaml: `apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: secret-reader
  namespace: payments
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: secret-reader-binding
  namespace: payments
subjects:
  - kind: ServiceAccount
    name: backup-sa
    namespace: payments
roleRef:
  kind: Role
  name: secret-reader
  apiGroup: rbac.authorization.k8s.io`,
  },
  {
    id: 'preset-pod-exec',
    name: 'Pod Exec Access',
    badge: 'HIGH',
    badgeColor: 'text-[#F59E0B] bg-[#F59E0B]/10 border-[#F59E0B]/30',
    description: 'Role granting pods/exec interactive command injection',
    yaml: `apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: pod-debugger-role
  namespace: default
rules:
  - apiGroups: [""]
    resources: ["pods/exec"]
    verbs: ["create", "get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: debugger-binding
  namespace: default
subjects:
  - kind: ServiceAccount
    name: monitoring-sa
    namespace: default
roleRef:
  kind: Role
  name: pod-debugger-role
  apiGroup: rbac.authorization.k8s.io`,
  },
];

export const DEMO_RESOURCE_COUNTS: ResourceCounts = {
  pods: 4,
  deployments: 2,
  serviceAccounts: 6,
  roles: 8,
  clusterRoles: 5,
  roleBindings: 9,
  clusterRoleBindings: 3,
  secrets: 4,
  namespaces: 4,
  total: 41,
};

export const INITIAL_DEMO_FINDINGS: Finding[] = [
  {
    id: 'finding-demo-1',
    scanId: 'scan-demo-102',
    ruleId: 'RBAC-001',
    title: 'Cluster-admin binding',
    description: "ClusterRoleBinding 'payment-admin' grants unrestricted 'cluster-admin' privileges to ServiceAccount 'payment-sa' in namespace 'payments'.",
    severity: 'CRITICAL',
    category: 'Privilege Escalation',
    resourceKind: 'ClusterRoleBinding',
    resourceName: 'payment-admin',
    namespace: 'payments',
    identity: 'payment-sa',
    permission: 'cluster-admin (Full Superuser)',
    status: 'Open',
    riskExplanation: 'Any workload or service account bound to cluster-admin possesses unrestricted control over all namespaces, secrets, nodes, and cluster control plane APIs. If this identity is compromised, an attacker gains complete cluster takeover.',
    recommendation: 'Remove cluster-admin binding. Replace with a custom Role restricted strictly to the payments namespace.',
    cisReference: 'CIS Kubernetes Benchmark 5.1.1',
    mitreReference: 'MITRE ATT&CK T1078 - Valid Accounts',
    attackPath: [
      'Workload (payments/payment-service)',
      'ServiceAccount (payment-sa)',
      'ClusterRoleBinding (payment-admin)',
      'ClusterRole (cluster-admin)',
      'Cluster Control Plane (Full Takeover)',
    ],
    blastRadius: {
      resourceSensitivity: 95,
      permissionScope: 100,
      namespaceCriticality: 90,
      privilegeEscalation: 98,
      overallScore: 96,
    },
    currentYaml: `apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: payment-admin
subjects:
  - kind: ServiceAccount
    name: payment-sa
    namespace: payments
roleRef:
  kind: ClusterRole
  name: cluster-admin
  apiGroup: rbac.authorization.k8s.io`,
    suggestedYaml: `# REMEDIATED: Replaced cluster-wide cluster-admin with scoped namespace RoleBinding
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: payment-admin-scoped
  namespace: payments
subjects:
  - kind: ServiceAccount
    name: payment-sa
    namespace: payments
roleRef:
  kind: Role
  name: payment-processor-role
  apiGroup: rbac.authorization.k8s.io`,
    reasoning: [
      'Downgraded from ClusterRoleBinding to namespace-scoped RoleBinding',
      'Removed superuser cluster-admin reference',
      'Scoped authorization strictly to the payments namespace',
    ],
    potentialImpact: 'Workload loses global cluster-wide privileges; normal payments processing remains uninterrupted.',
    createdAt: '2026-09-25T09:42:00Z',
  },
  {
    id: 'finding-demo-2',
    scanId: 'scan-demo-102',
    ruleId: 'RBAC-008',
    title: 'Privileged container execution',
    description: "Deployment 'payment-service' container 'payment-api' executes with securityContext.privileged: true.",
    severity: 'CRITICAL',
    category: 'Pod Security',
    resourceKind: 'Deployment',
    resourceName: 'payment-service',
    namespace: 'payments',
    identity: 'payment-sa',
    permission: 'Host Kernel / Device Root Access',
    status: 'Open',
    riskExplanation: 'A privileged container has access to all host kernel devices, can bypass cgroups and AppArmor/SELinux profiles, and can easily break out of the container to compromise the underlying node.',
    recommendation: 'Set securityContext.privileged: false. Drop ALL capabilities and selectively add only specific POSIX capabilities if strictly needed.',
    cisReference: 'CIS Kubernetes Benchmark 5.2.1',
    mitreReference: 'MITRE ATT&CK T1611 - Escape to Host',
    attackPath: [
      'Deployment (payment-service)',
      'Container (payment-api) with privileged: true',
      'Host Device / Kernel Access (/dev, /sys)',
      'Container Escape to Underlying Node Kernel',
    ],
    blastRadius: {
      resourceSensitivity: 100,
      permissionScope: 98,
      namespaceCriticality: 95,
      privilegeEscalation: 100,
      overallScore: 98,
    },
    currentYaml: `spec:
  template:
    spec:
      serviceAccountName: payment-sa
      containers:
        - name: payment-api
          image: internal.registry/payments/api:v2.4
          securityContext:
            privileged: true`,
    suggestedYaml: `# REMEDIATED: Disabled privileged execution and enforced non-root execution
spec:
  template:
    spec:
      serviceAccountName: payment-sa
      containers:
        - name: payment-api
          image: internal.registry/payments/api:v2.4
          securityContext:
            privileged: false
            allowPrivilegeEscalation: false
            runAsNonRoot: true
            readOnlyRootFilesystem: true
            capabilities:
              drop:
                - ALL`,
    reasoning: [
      'Disabled privileged container flag to restore container isolation',
      'Enforced non-root execution and read-only root filesystem',
      'Dropped all kernel capabilities',
    ],
    potentialImpact: 'Container cannot execute kernel device operations or escape to the host node.',
    createdAt: '2026-09-25T09:42:00Z',
  },
  {
    id: 'finding-demo-3',
    scanId: 'scan-demo-102',
    ruleId: 'RBAC-002',
    title: 'Wildcard verbs in RBAC rule',
    description: "Role 'dev-role' in namespace 'development' grants wildcard verb '*' across resources.",
    severity: 'HIGH',
    category: 'Excessive Permissions',
    resourceKind: 'Role',
    resourceName: 'dev-role',
    namespace: 'development',
    identity: 'developer-sa',
    permission: "verbs: ['*'] on all resources",
    status: 'Open',
    riskExplanation: 'Using "*" permits destructive verbs (delete, patch, update, deletecollection) as well as administrative binding verbs. Attackers can modify or destroy critical operational data.',
    recommendation: 'Explicitly specify only required verbs (e.g. ["get", "list", "watch"]). Avoid "*" wildcards in production roles.',
    cisReference: 'CIS Kubernetes Benchmark 5.1.3',
    mitreReference: 'MITRE ATT&CK T1068 - Exploitation for Privilege Escalation',
    attackPath: [
      'Role (dev-role)',
      "RBAC Rule with verbs: ['*']",
      'Target Resources: All API endpoints',
      'Arbitrary Resource Tampering & Deletion',
    ],
    blastRadius: {
      resourceSensitivity: 80,
      permissionScope: 90,
      namespaceCriticality: 70,
      privilegeEscalation: 75,
      overallScore: 78,
    },
    currentYaml: `apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: dev-role
  namespace: development
rules:
  - apiGroups: ["*"]
    resources: ["*"]
    verbs: ["*"]`,
    suggestedYaml: `# REMEDIATED: Replaced wildcard verbs with read-only verbs
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: dev-role
  namespace: development
rules:
  - apiGroups: [""]
    resources: ["configmaps", "services", "pods"]
    verbs: ["get", "list", "watch"]`,
    reasoning: [
      'Eliminated dangerous wildcard verb "*"',
      'Restricted actions to read-only ("get", "list", "watch")',
      'Replaced wildcard resource with specific development assets',
    ],
    potentialImpact: 'Developers can inspect resources but cannot arbitrarily delete cluster assets.',
    createdAt: '2026-09-25T09:42:00Z',
  },
  {
    id: 'finding-demo-4',
    scanId: 'scan-demo-102',
    ruleId: 'RBAC-004',
    title: 'Broad secret read access',
    description: "Role 'secret-reader' permits reading all Secrets across the 'payments' namespace.",
    severity: 'HIGH',
    category: 'Resource Exposure',
    resourceKind: 'Role',
    resourceName: 'secret-reader',
    namespace: 'payments',
    identity: 'backup-sa',
    permission: 'secrets [get, list, watch]',
    status: 'Open',
    riskExplanation: 'Unrestricted secret reading exposes confidential application passwords, JWT signing keys, TLS private keys, and cloud provider access credentials to any caller.',
    recommendation: 'Use resourceNames to restrict secret access to specific named secrets, or utilize External Secrets Operator / Vault rather than granting broad secret read access.',
    cisReference: 'CIS Kubernetes Benchmark 5.1.2',
    mitreReference: 'MITRE ATT&CK T1552 - Unsecured Credentials',
    attackPath: [
      'Role (secret-reader)',
      "Read access to 'secrets'",
      'Credential Harvesting (DB Passwords, TLS keys)',
      'Lateral Movement across payments microservices',
    ],
    blastRadius: {
      resourceSensitivity: 92,
      permissionScope: 80,
      namespaceCriticality: 85,
      privilegeEscalation: 82,
      overallScore: 85,
    },
    currentYaml: `apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: secret-reader
  namespace: payments
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["get", "list", "watch"]`,
    suggestedYaml: `# REMEDIATED: Restricted access to single designated secret
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: secret-reader
  namespace: payments
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    resourceNames: ["payments-db-credentials"]
    verbs: ["get"]`,
    reasoning: [
      'Constrained access to single authorized secret name',
      'Revoked list and watch permissions to prevent secret harvesting',
    ],
    potentialImpact: 'Workload can only query its designated credential secret.',
    createdAt: '2026-09-25T09:42:00Z',
  },
  {
    id: 'finding-demo-5',
    scanId: 'scan-demo-102',
    ruleId: 'RBAC-005',
    title: 'Pod exec permission granted',
    description: "Role 'pod-debugger-role' grants create access to 'pods/exec', allowing interactive remote code execution.",
    severity: 'HIGH',
    category: 'Privilege Escalation',
    resourceKind: 'Role',
    resourceName: 'pod-debugger-role',
    namespace: 'default',
    identity: 'monitoring-sa',
    permission: 'pods/exec create',
    status: 'Open',
    riskExplanation: 'Executing commands inside pods allows attackers who compromise this identity to run arbitrary binaries, dump memory, access mounted secrets, and pivot to adjacent microservices.',
    recommendation: 'Restrict pods/exec privileges exclusively to authorized human SREs via ephemeral just-in-time access. Do not grant pods/exec to automated ServiceAccounts.',
    cisReference: 'CIS Kubernetes Benchmark 5.1.4',
    mitreReference: 'MITRE ATT&CK T1609 - Container Administration Command',
    attackPath: [
      'Role (pod-debugger-role)',
      "create 'pods/exec'",
      'Interactive Shell Injection inside running pods',
      'In-pod Credential and Memory Extraction',
    ],
    blastRadius: {
      resourceSensitivity: 88,
      permissionScope: 85,
      namespaceCriticality: 80,
      privilegeEscalation: 90,
      overallScore: 86,
    },
    currentYaml: `apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: pod-debugger-role
  namespace: default
rules:
  - apiGroups: [""]
    resources: ["pods/exec"]
    verbs: ["create", "get"]`,
    suggestedYaml: `# REMEDIATED: Replaced pods/exec with read-only logs access
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: pod-debugger-role
  namespace: default
rules:
  - apiGroups: [""]
    resources: ["pods/log"]
    verbs: ["get"]`,
    reasoning: [
      'Revoked pods/exec terminal injection',
      'Provided safe, non-interactive pods/log viewing permissions',
    ],
    potentialImpact: 'Automated debugger cannot attach an interactive shell to pods.',
    createdAt: '2026-09-25T09:42:00Z',
  },
  {
    id: 'finding-demo-6',
    scanId: 'scan-demo-102',
    ruleId: 'RBAC-011',
    title: 'Host filesystem access via hostPath volume',
    description: "Pod 'network-sniffer-pod' mounts root filesystem hostPath '/' into volume 'host-root'.",
    severity: 'HIGH',
    category: 'Pod Security',
    resourceKind: 'Pod',
    resourceName: 'network-sniffer-pod',
    namespace: 'monitoring',
    identity: 'default',
    permission: 'Host filesystem: /',
    status: 'Open',
    riskExplanation: 'Mounting sensitive host paths (such as the docker socket, /etc, or root) allows containers to read host secrets, alter host binaries, or create unauthorized root users.',
    recommendation: 'Avoid hostPath volumes. Use PersistentVolumeClaims with CSI drivers or emptyDir volumes.',
    cisReference: 'CIS Kubernetes Benchmark 5.2.3',
    mitreReference: 'MITRE ATT&CK T1611 - Escape to Host',
    attackPath: [
      'Pod (network-sniffer-pod)',
      'hostPath volume (/)',
      'Host Node Root Filesystem Exposure',
      'Host Node Persistence and SSH Key Theft',
    ],
    blastRadius: {
      resourceSensitivity: 94,
      permissionScope: 88,
      namespaceCriticality: 85,
      privilegeEscalation: 92,
      overallScore: 90,
    },
    currentYaml: `volumes:
  - name: host-root
    hostPath:
      path: /`,
    suggestedYaml: `# REMEDIATED: Replaced hostPath mount with ephemeral emptyDir
volumes:
  - name: host-root
    emptyDir: {}`,
    reasoning: [
      'Removed root hostPath access',
      'Replaced with isolated emptyDir volume',
    ],
    potentialImpact: 'Workload cannot read host node files.',
    createdAt: '2026-09-25T09:42:00Z',
  },
  {
    id: 'finding-demo-7',
    scanId: 'scan-demo-102',
    ruleId: 'RBAC-007',
    title: 'Default ServiceAccount usage',
    description: "Pod 'network-sniffer-pod' executes with the unconstrained 'default' ServiceAccount in namespace 'monitoring'.",
    severity: 'MEDIUM',
    category: 'Identity Security',
    resourceKind: 'Pod',
    resourceName: 'network-sniffer-pod',
    namespace: 'monitoring',
    identity: 'default',
    permission: 'Default namespace token',
    status: 'Open',
    riskExplanation: 'Using the default ServiceAccount creates an identity collision where all unassigned workloads share the same API credentials. Any privilege granted to one pod is automatically shared by all others.',
    recommendation: 'Create a dedicated, least-privilege ServiceAccount for each microservice with automountServiceAccountToken: false unless explicitly needed.',
    cisReference: 'CIS Kubernetes Benchmark 5.1.5',
    mitreReference: 'MITRE ATT&CK T1078.004 - Cloud Accounts',
    attackPath: [
      'Pod (network-sniffer-pod)',
      'Shared Identity (ServiceAccount/default)',
      'Namespace Token Inheritance',
      'Cross-workload Impersonation',
    ],
    blastRadius: {
      resourceSensitivity: 50,
      permissionScope: 55,
      namespaceCriticality: 60,
      privilegeEscalation: 50,
      overallScore: 54,
    },
    currentYaml: `spec:
  serviceAccountName: default`,
    suggestedYaml: `# REMEDIATED: Explicit dedicated ServiceAccount with token automount disabled
spec:
  serviceAccountName: sniffer-dedicated-sa
  automountServiceAccountToken: false`,
    reasoning: [
      'Replaced shared default SA with dedicated workload SA',
      'Disabled automountServiceAccountToken',
    ],
    potentialImpact: 'Workload requires dedicated ServiceAccount creation.',
    createdAt: '2026-09-25T09:42:00Z',
  },
];

export const INITIAL_DEMO_SCAN: Scan = {
  id: 'scan-demo-102',
  timestamp: 'Today, 09:42 PM',
  cluster: 'production-demo',
  k8sVersion: 'v1.30.2',
  score: 68,
  previousScore: 62,
  filesCount: 4,
  rawYaml: DEMO_YAML_MANIFEST,
  resourceCounts: DEMO_RESOURCE_COUNTS,
  findings: INITIAL_DEMO_FINDINGS,
  status: 'Completed',
};

export const DEMO_SCORE_TREND = [
  { day: 'Day 1', score: 54 },
  { day: 'Day 2', score: 56 },
  { day: 'Day 3', score: 58 },
  { day: 'Day 4', score: 58 },
  { day: 'Day 5', score: 62 },
  { day: 'Day 6', score: 60 },
  { day: 'Day 7', score: 65 },
  { day: 'Day 8', score: 63 },
  { day: 'Day 9', score: 64 },
  { day: 'Day 10', score: 66 },
  { day: 'Day 11', score: 65 },
  { day: 'Day 12', score: 67 },
  { day: 'Day 13', score: 62 },
  { day: 'Day 14', score: 68 },
];

export const COMPLIANCE_CONTROLS: ComplianceControl[] = [
  {
    framework: 'CIS Kubernetes Benchmark',
    controlId: 'CIS 5.1.1',
    title: 'Ensure that the cluster-admin role is only used where strictly required',
    section: '5.1 RBAC and Service Accounts',
    description: 'The cluster-admin superuser role grants unrestricted API access. It should never be bound to regular ServiceAccounts.',
    findingsCount: 1,
    status: 'Failed',
    associatedRules: ['RBAC-001', 'RBAC-006'],
  },
  {
    framework: 'CIS Kubernetes Benchmark',
    controlId: 'CIS 5.1.2',
    title: 'Minimize access to secrets',
    section: '5.1 RBAC and Service Accounts',
    description: 'Ensure role definitions do not grant broad access to Secret objects.',
    findingsCount: 1,
    status: 'Warning',
    associatedRules: ['RBAC-004'],
  },
  {
    framework: 'CIS Kubernetes Benchmark',
    controlId: 'CIS 5.1.3',
    title: 'Minimize wildcard use in Roles and ClusterRoles',
    section: '5.1 RBAC and Service Accounts',
    description: 'Do not use wildcards in verbs or resources to avoid unintentionally granting escalating permissions.',
    findingsCount: 1,
    status: 'Warning',
    associatedRules: ['RBAC-002', 'RBAC-003'],
  },
  {
    framework: 'CIS Kubernetes Benchmark',
    controlId: 'CIS 5.1.4',
    title: 'Minimize access to create pods and pods/exec',
    section: '5.1 RBAC and Service Accounts',
    description: 'The pods/exec subresource enables command execution inside containers, which must be strictly controlled.',
    findingsCount: 1,
    status: 'Warning',
    associatedRules: ['RBAC-005'],
  },
  {
    framework: 'CIS Kubernetes Benchmark',
    controlId: 'CIS 5.1.5',
    title: 'Ensure that default service accounts are not actively used',
    section: '5.1 RBAC and Service Accounts',
    description: 'Workloads should not execute with default ServiceAccount credentials.',
    findingsCount: 1,
    status: 'Warning',
    associatedRules: ['RBAC-007'],
  },
  {
    framework: 'CIS Kubernetes Benchmark',
    controlId: 'CIS 5.2.1',
    title: 'Minimize the admission of privileged containers',
    section: '5.2 Pod Security Standards',
    description: 'Privileged containers can easily escape to the host node root environment.',
    findingsCount: 1,
    status: 'Failed',
    associatedRules: ['RBAC-008'],
  },
  {
    framework: 'MITRE ATT&CK for Containers',
    controlId: 'T1078',
    title: 'Valid Accounts: Cloud and Container Accounts',
    section: 'Initial Access & Privilege Escalation',
    description: 'Adversaries may compromise service account tokens to gain API access with pre-existing privileges.',
    findingsCount: 1,
    status: 'Failed',
    associatedRules: ['RBAC-001', 'RBAC-007'],
  },
  {
    framework: 'MITRE ATT&CK for Containers',
    controlId: 'T1611',
    title: 'Escape to Host',
    section: 'Privilege Escalation',
    description: 'Adversaries break out of container boundaries to gain execution context on the host operating system.',
    findingsCount: 2,
    status: 'Failed',
    associatedRules: ['RBAC-008', 'RBAC-009', 'RBAC-010', 'RBAC-011'],
  },
  {
    framework: 'MITRE ATT&CK for Containers',
    controlId: 'T1609',
    title: 'Container Administration Command',
    section: 'Execution',
    description: 'Adversaries execute commands inside existing containers using pods/exec API endpoints.',
    findingsCount: 1,
    status: 'Warning',
    associatedRules: ['RBAC-005'],
  },
  {
    framework: 'NSA/CISA Kubernetes Hardening',
    controlId: 'NSA-RBAC-01',
    title: 'Disable Service Account Token Automounting',
    section: 'Authentication and Authorization',
    description: 'Prevent default credential injection unless explicitly required by the workload application code.',
    findingsCount: 1,
    status: 'Warning',
    associatedRules: ['RBAC-007'],
  },
  {
    framework: 'NSA/CISA Kubernetes Hardening',
    controlId: 'NSA-POD-01',
    title: 'Enforce Non-Root and Non-Privileged Execution',
    section: 'Pod Security Hardening',
    description: 'Containers must drop root capabilities, prohibit host namespaces, and run without privileged flags.',
    findingsCount: 2,
    status: 'Failed',
    associatedRules: ['RBAC-008', 'RBAC-009', 'RBAC-010', 'RBAC-011'],
  },
];
