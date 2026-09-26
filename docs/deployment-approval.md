# Protected production deployment

This project now has a GitHub Actions approval path that is deliberately fail-closed. The deterministic RBAC engine remains the source of the rule findings and security score. A Random Forest result is additional evidence; it is never substituted for the rule engine.

## One-time GitHub configuration

1. Protect `main` (or change the workflow branch deliberately): require pull requests and the `Security Checks` status check; restrict who can push; and protect `.github/**`, `scripts/**`, scanner code, and deployment configuration with TL/security CODEOWNERS.
2. Create a GitHub Environment named `production`. Add the TL user/team as a required reviewer, enable **Prevent self-review**, restrict deployment branches to the protected release branch, and do not grant employees environment-admin access. GitHub Environment approval is the authority; labels and comments are informational only.
3. Add production-only secrets to that Environment, never repository-wide secrets. At minimum set `PRODUCTION_DEPLOY_COMMAND` to a reviewed, non-interactive deployment command, for example `kubectl apply -f k8s/`. Put kubeconfig/cloud credentials in separate production Environment secrets referenced by that command or use OIDC. Do not put credentials in a PR, workflow variable, browser code, or this repository.
4. Configure repository variable `RBAC_SECURITY_SCORE_THRESHOLD` (0–100; default 80).
5. Configure repository variable `RBAC_ML_PREDICT_COMMAND` to invoke the existing real, pre-trained Random Forest inference integration. The command receives `RBAC_SCAN_INPUT` (the preliminary scanner JSON) and **must** write `RBAC_ML_OUTPUT` as JSON such as `{"risk":"LOW","modelName":"rbac-rf","modelVersion":"2026.09"}`. It must use a separately held-out test dataset during model evaluation and a persisted trained model during inference. Never train inside a PR workflow or emit a guessed risk.

Until a real predictor is configured, `Security Checks` blocks deployment with an explicit ML-analysis failure. That is intentional: this checkout has no Random Forest model or dataset to run.

## What each workflow does

- `security-check.yml` runs lint, build, tests, deterministic manifest scanning, the configured ML inference adapter, SARIF generation, and the gate. It has no production Environment and no deployment credentials. Critical findings, malformed YAML, missing/invalid ML output, missing SARIF, test/build failure, scanner failure, or a score below the threshold block the flow.
- `deployment.yml` starts only after a completed PR Security Checks workflow. Before requesting any approval, its trusted default-branch code fetches changed PR manifests as data and re-runs deterministic scanning, ML inference, SARIF generation, and the gate; it does not trust a PR-produced scan artifact. It updates one marked PR comment and uses `deployment-pending` only as a display label. If the gate passed, its `production` job waits for GitHub Environment approval before it can read production secrets. It re-checks that the PR is still open and at the scanned SHA before deployment.
- `approval-reminder.yml` runs at minutes 17 and 47 each hour (avoiding the busy top of the hour). It reads pending GitHub Environment deployments, then updates the single marked PR comment with a reminder count. It does nothing after approval, rejection, failure, or PR closure because there is no longer a pending production deployment.

GitHub Environment reviewer records are the auditable approval/rejection record. The final workflow comment mirrors the reviewer when GitHub exposes it through the workflow approval-history API.

## Scanner outputs and source locations

`scripts/scan-rbac.ts` writes canonical JSON and SARIF. It derives rule risk from actual scanner findings and retains the source file per finding. The current parser does not expose verified YAML line/column offsets, so SARIF and PR comments intentionally omit regions instead of inventing line numbers.

## End-to-end verification

1. Open a PR that changes a safe Kubernetes YAML file and ensure the real ML command emits valid output. Confirm `Security Checks` passes, a SARIF upload appears, and exactly one approval comment/`deployment-pending` label is created.
2. Verify `production` is waiting in Actions. Confirm that neither the PR job nor employee accounts can view Environment secrets or approve their own run.
3. Wait for a scheduled reminder or run **Deployment Approval Reminder** manually. Confirm the same comment is updated, not duplicated.
4. Reject the protected Environment approval. Confirm the deploy job is cancelled/rejected, the reminder no longer updates, and the comment/label records rejection.
5. Repeat with approval. Confirm only then does the job access `PRODUCTION_DEPLOY_COMMAND`, the comment records completion, and the pending label becomes approved.
6. Test invalid YAML, a cluster-admin/privileged-container manifest, score below threshold, ML command failure, SARIF upload failure, and application test failure. Each must leave deployment blocked with no pending Production approval. Also close a pending PR and confirm reminders stop.
