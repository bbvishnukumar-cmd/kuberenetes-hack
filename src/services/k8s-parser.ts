import { loadAll } from 'js-yaml';
import { ResourceCounts } from '../types/rbac';

export interface ParsedK8sResource {
  apiVersion?: string;
  kind: string;
  metadata: {
    name: string;
    namespace?: string;
    labels?: Record<string, string>;
    annotations?: Record<string, string>;
    [key: string]: any;
  };
  spec?: any;
  rules?: Array<{
    apiGroups?: string[];
    resources?: string[];
    verbs?: string[];
    resourceNames?: string[];
    nonResourceURLs?: string[];
  }>;
  roleRef?: {
    apiGroup?: string;
    kind: string;
    name: string;
  };
  subjects?: Array<{
    kind: string;
    name: string;
    namespace?: string;
    apiGroup?: string;
  }>;
  [key: string]: any;
}

export interface ParseResult {
  success: boolean;
  resources: ParsedK8sResource[];
  counts: ResourceCounts;
  rawYaml: string;
  errors?: string[];
}

export function parseK8sYaml(yamlText: string): ParseResult {
  const trimmed = yamlText.trim();
  if (!trimmed) {
    return {
      success: false,
      resources: [],
      counts: {
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
      rawYaml: yamlText,
      errors: ['YAML content is empty. Please provide one or more Kubernetes resource manifests.'],
    };
  }

  const resources: ParsedK8sResource[] = [];
  const errors: string[] = [];

  try {
    loadAll(yamlText, (doc: any) => {
      if (doc && typeof doc === 'object') {
        if (!doc.kind) {
          errors.push(`Found document without a valid 'kind' field.`);
          return;
        }
        if (!doc.metadata || !doc.metadata.name) {
          errors.push(`Resource of kind '${doc.kind}' is missing 'metadata.name'.`);
          return;
        }

        const normalized: ParsedK8sResource = {
          apiVersion: doc.apiVersion || 'v1',
          kind: doc.kind,
          metadata: {
            name: doc.metadata.name,
            namespace: doc.metadata.namespace || 'default',
            labels: doc.metadata.labels || {},
            annotations: doc.metadata.annotations || {},
            ...doc.metadata,
          },
          spec: doc.spec || {},
          rules: doc.rules || [],
          roleRef: doc.roleRef,
          subjects: doc.subjects || [],
          ...doc,
        };

        resources.push(normalized);
      }
    });
  } catch (err: any) {
    const errorMsg = err?.message || 'Unable to parse YAML';
    return {
      success: false,
      resources: [],
      counts: {
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
      rawYaml: yamlText,
      errors: [`Invalid YAML syntax: ${errorMsg}`],
    };
  }

  if (resources.length === 0) {
    return {
      success: false,
      resources: [],
      counts: {
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
      rawYaml: yamlText,
      errors: errors.length > 0 ? errors : ['No valid Kubernetes objects found in the provided YAML.'],
    };
  }

  const counts: ResourceCounts = {
    pods: 0,
    deployments: 0,
    serviceAccounts: 0,
    roles: 0,
    clusterRoles: 0,
    roleBindings: 0,
    clusterRoleBindings: 0,
    secrets: 0,
    namespaces: 0,
    total: resources.length,
  };

  resources.forEach((r) => {
    const k = r.kind.toLowerCase();
    if (k === 'pod') counts.pods++;
    else if (k === 'deployment') counts.deployments++;
    else if (k === 'serviceaccount') counts.serviceAccounts++;
    else if (k === 'role') counts.roles++;
    else if (k === 'clusterrole') counts.clusterRoles++;
    else if (k === 'rolebinding') counts.roleBindings++;
    else if (k === 'clusterrolebinding') counts.clusterRoleBindings++;
    else if (k === 'secret') counts.secrets++;
    else if (k === 'namespace') counts.namespaces++;
  });

  return {
    success: true,
    resources,
    counts,
    rawYaml: yamlText,
    errors: errors.length > 0 ? errors : undefined,
  };
}
