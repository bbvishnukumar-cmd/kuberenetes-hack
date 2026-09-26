import test from 'node:test';
import assert from 'node:assert/strict';
import { parseK8sYaml } from '../src/services/k8s-parser';
import { calculateSecurityScore, executeRbacRules } from '../src/services/rbac-rules';

test('critical cluster-admin binding is detected and reduces the score', () => {
  const parsed = parseK8sYaml(`
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: unsafe-admin
subjects:
  - kind: ServiceAccount
    name: app
    namespace: default
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
`);
  assert.equal(parsed.success, true);
  const findings = executeRbacRules(parsed.resources, 'test');
  assert.equal(findings.some((finding) => finding.ruleId === 'RBAC-001' && finding.severity === 'CRITICAL'), true);
  assert.equal(calculateSecurityScore(findings), 80);
});

test('invalid YAML remains a parser failure', () => {
  const parsed = parseK8sYaml('kind: Role\nmetadata: [');
  assert.equal(parsed.success, false);
  assert.match(parsed.errors?.[0] ?? '', /Invalid YAML syntax/);
});

test('wildcard RBAC permissions remain a high-risk finding', () => {
  const parsed = parseK8sYaml(`
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: broad-role
  namespace: default
rules:
  - apiGroups: [""]
    resources: ["pods"]
    verbs: ["*"]
`);
  assert.equal(parsed.success, true);
  const findings = executeRbacRules(parsed.resources, 'test');
  assert.equal(findings.some((finding) => finding.ruleId === 'RBAC-002' && finding.severity === 'HIGH'), true);
  assert.equal(calculateSecurityScore(findings), 90);
});
