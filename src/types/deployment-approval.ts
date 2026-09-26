export type DeploymentApprovalStatus =
  | 'unavailable'
  | 'pending'
  | 'approved'
  | 'rejected'
  | 'security-blocked'
  | 'deploying'
  | 'completed';

export interface DeploymentApproval {
  pullRequestNumber?: number;
  pullRequestTitle?: string;
  developer?: string;
  securityScore?: number;
  ruleRisk?: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'NONE';
  mlRisk?: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  securityGate?: 'PASSED' | 'BLOCKED' | 'UNAVAILABLE';
  approvalStatus: DeploymentApprovalStatus;
  approvedBy?: string;
  approvedAt?: string;
  reminderCount?: number;
  deploymentStatus?: string;
}
