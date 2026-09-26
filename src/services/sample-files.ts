export interface SampleK8sFile {
  name: string;
  size: number;
  content: string;
  description: string;
}

export const SAMPLE_MULTI_FILES: SampleK8sFile[] = [
  {
    name: 'roles.yaml',
    size: 24576, // ~24 KB
    description: 'Application, database and development Roles',
    content: `apiVersion: rbac.authorization.k8s.io/v1
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
`,
  },
  {
    name: 'clusterroles.yaml',
    size: 18432, // ~18 KB
    description: 'Cluster-wide roles including cluster-admin reference',
    content: `apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: cluster-admin
rules:
  - apiGroups: ["*"]
    resources: ["*"]
    verbs: ["*"]
  - nonResourceURLs: ["*"]
    verbs: ["*"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: global-node-viewer
rules:
  - apiGroups: [""]
    resources: ["nodes", "nodes/status"]
    verbs: ["get", "list", "watch"]
`,
  },
  {
    name: 'rolebindings.yaml',
    size: 12288, // ~12 KB
    description: 'Namespace-scoped bindings for services and devs',
    content: `apiVersion: rbac.authorization.k8s.io/v1
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
  apiGroup: rbac.authorization.k8s.io
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
  apiGroup: rbac.authorization.k8s.io
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
  apiGroup: rbac.authorization.k8s.io
`,
  },
  {
    name: 'clusterrolebindings.yaml',
    size: 16384, // ~16 KB
    description: 'ClusterRoleBindings including critical payment-admin binding',
    content: `apiVersion: rbac.authorization.k8s.io/v1
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
`,
  },
  {
    name: 'serviceaccounts.yaml',
    size: 9216, // ~9 KB
    description: 'Workload identity declarations',
    content: `apiVersion: v1
kind: ServiceAccount
metadata:
  name: payment-sa
  namespace: payments
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: developer-sa
  namespace: development
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: monitoring-sa
  namespace: default
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: backup-sa
  namespace: payments
`,
  },
  {
    name: 'namespaces.yaml',
    size: 7168, // ~7 KB
    description: 'Multi-tenant namespace boundaries',
    content: `apiVersion: v1
kind: Namespace
metadata:
  name: payments
---
apiVersion: v1
kind: Namespace
metadata:
  name: development
---
apiVersion: v1
kind: Namespace
metadata:
  name: monitoring
---
apiVersion: v1
kind: Namespace
metadata:
  name: default
`,
  },
  {
    name: 'workloads.yaml',
    size: 14336, // ~14 KB
    description: 'Pods and Deployments referencing identities',
    content: `apiVersion: apps/v1
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
`,
  },
];
