# SecureFlow

SecureFlow is a full-stack DevSecOps security platform that scans repositories, explains vulnerabilities with AI, proposes fixes, opens remediation pull requests, reacts to GitHub webhooks, scores repository security posture, and ships with a production-oriented container stack.

## What It Does

- scans repositories with SAST, secret, dependency, container, and optional DAST tooling
- stores scan jobs, reports, AI explanations, remediation PRs, and score history in MongoDB
- uses Redis and BullMQ for asynchronous scan orchestration
- explains findings in plain language with cached AI insights
- creates conservative remediation pull requests for supported fixes
- reacts to GitHub `push` and `pull_request` webhooks
- updates GitHub commit statuses and PR comments
- computes a security score and score trend for each repository
- provides JWT authentication with role-based access
- exports vulnerability reports as downloadable PDF files
- runs locally or through Docker Compose with Nginx in front

## Stack

- Frontend: React + Vite
- Backend: Node.js + Express
- Database: MongoDB
- Queue: Redis + BullMQ
- Git integration: GitHub REST APIs + webhooks
- Scanners: Semgrep, Gitleaks, pip-audit, Trivy, optional OWASP ZAP

## Project Structure

- `Frontend/` React dashboard
- `Backend/` Express API, queue worker, models, services, auth, and webhooks
- `docker-compose.yml` multi-service runtime
- `nginx/` reverse proxy config
- `.github/workflows/` CI workflow examples
- `examples/github-actions/` webhook forwarding example

## Core Features

### 1. Authentication and Roles

SecureFlow uses JWT-based authentication.

Roles:

- `admin`
- `developer`
- `viewer`

Behavior:

- registration creates `developer` accounts
- bootstrap admin creation is supported from env vars
- protected routes require a bearer token
- scan creation and remediation PR creation are restricted to `admin` and `developer`

Auth endpoints:

- `POST /api/auth/register`
- `POST /api/auth/login`
- `GET /api/auth/me`

### 2. Repository Scanning

Manual scan endpoint:

- `POST /api/scans`

The scan engine currently orchestrates:

- Semgrep for SAST
- Gitleaks for exposed secrets
- `npm audit` or `pip-audit` for dependency findings
- Trivy for container and filesystem vulnerabilities
- OWASP ZAP baseline for DAST in full scans when a target URL is provided

Results are stored in `VulnerabilityReport` documents with:

- normalized findings
- tool run summaries
- AI explanations
- security score metadata

### 3. AI Vulnerability Explanations

Each finding may include:

- `ai.summary`
- `ai.whyItMatters`
- `ai.potentialImpact`
- `ai.remediationSteps`
- `ai.secureCodingTips`

AI responses are cached in MongoDB via `AiInsightCache` to reduce repeated API calls and cost.

If OpenAI is not configured or returns invalid output, SecureFlow falls back to heuristic remediation guidance.

### 4. Automated Remediation Pull Requests

Endpoint:

- `POST /api/reports/:reportId/findings/:findingId/remediation-pr`

Preview mode:

- `POST /api/reports/:reportId/findings/:findingId/remediation-pr?preview=true`

Current safe auto-fix support is intentionally conservative:

- hardcoded secret replacement for supported Gitleaks findings
- Python dependency upgrades when `pip-audit` provides fix versions
- limited AI-generated line edits when the fix is small and safe enough to apply

If a fix is ambiguous or unsafe, the remediation request is recorded as unsupported instead of forcing a patch.

### 5. GitHub Webhooks and Feedback

Webhook endpoint:

- `POST /api/webhook`

Supported GitHub events:

- `push`
- `pull_request` with `opened`, `synchronize`, and `reopened`

Webhook behavior:

- validates `X-Hub-Signature-256`
- clones the repo and enqueues a scan
- sends GitHub commit status updates during scan execution
- posts a summary comment on pull requests after completion

### 6. Security Score and Analytics

SecureFlow computes a score for each completed report.

Current weighted model:

- `critical * 5`
- `high * 3`
- `medium * 1`
- `low * 0.5`
- extra penalties for secrets and dependency findings

Stored score data includes:

- numeric score
- weighted risk
- risk level
- contributing factors
- badge metadata

Analytics endpoint:

- `GET /api/repositories/:repositoryId/analytics`

### 7. Report Export

PDF export endpoint:

- `GET /api/reports/:reportId/download.pdf`

## Local Development

### Prerequisites

- Node.js 22+
- MongoDB
- Redis
- Python available on PATH for local scanner execution
- optional local tools for richer scans:
  - `gitleaks`
  - `trivy`
  - Docker for ZAP

### Environment Files

Backend env example:

- [Backend/.env.example](C:/Users/lenov/Desktop/CyberSecurity/SecureFlow/Backend/.env.example)

Frontend env example:

- [Frontend/.env.example](C:/Users/lenov/Desktop/CyberSecurity/SecureFlow/Frontend/.env.example)

Recommended setup:

1. Copy `Backend/.env.example` to `Backend/.env`
2. Copy `Frontend/.env.example` to `Frontend/.env`
3. Fill in the values you need

### Start Locally

Infrastructure only:

```bash
docker compose up -d mongodb redis
```

Backend:

```bash
cd Backend
npm install
npm run dev
```

Frontend:

```bash
cd Frontend
npm install
npm run dev
```

Default local ports:

- backend: `http://localhost:5050`
- frontend: `http://localhost:5173`
- MongoDB host port: `27018`
- Redis host port: `6380`

## Important Environment Variables

### Backend

Basic app/runtime:

- `APP_NAME`
- `NODE_ENV`
- `PORT`
- `CLIENT_URL`
- `TRUST_PROXY`
- `MONGODB_URI`
- `REDIS_HOST`
- `REDIS_PORT`
- `SCAN_QUEUE_NAME`
- `REPOSITORY_WORKSPACE`

Tooling:

- `PYTHON_PATH`
- `SEMGREP_COMMAND`
- `SEMGREP_ARGS`
- `PIP_AUDIT_COMMAND`
- `PIP_AUDIT_ARGS`
- `GITLEAKS_PATH`
- `TRIVY_PATH`
- `DOCKER_PATH`

AI:

- `AI_INSIGHTS_ENABLED`
- `AI_PROVIDER`
- `OPENAI_API_KEY`
- `OPENAI_MODEL`
- `OPENAI_CHAT_COMPLETIONS_URL`

GitHub:

- `GITHUB_TOKEN`
- `GITHUB_API_BASE_URL`
- `GITHUB_FIX_BRANCH_PREFIX`
- `GITHUB_WEBHOOK_SECRET`

Authentication:

- `JWT_SECRET`
- `JWT_EXPIRES_IN_HOURS`
- `BOOTSTRAP_ADMIN_NAME`
- `BOOTSTRAP_ADMIN_EMAIL`
- `BOOTSTRAP_ADMIN_PASSWORD`

### Frontend

- `VITE_API_BASE_URL`

## Docker and Production

Production-oriented files:

- [Backend/Dockerfile](C:/Users/lenov/Desktop/CyberSecurity/SecureFlow/Backend/Dockerfile)
- [Frontend/Dockerfile](C:/Users/lenov/Desktop/CyberSecurity/SecureFlow/Frontend/Dockerfile)
- [docker-compose.yml](C:/Users/lenov/Desktop/CyberSecurity/SecureFlow/docker-compose.yml)
- [nginx.conf](C:/Users/lenov/Desktop/CyberSecurity/SecureFlow/nginx/nginx.conf)

The Docker stack includes:

- backend
- frontend
- nginx reverse proxy
- MongoDB
- Redis

Container notes:

- Docker Compose overrides Windows-specific tool paths with Linux-safe values
- the backend image installs `python3`, `semgrep`, `pip-audit`, `gitleaks`, and `trivy`
- DAST with ZAP still depends on Docker availability at runtime

Start the full stack:

```bash
docker compose up -d --build
```

## CI/CD

Included workflow:

- [ci.yml](C:/Users/lenov/Desktop/CyberSecurity/SecureFlow/.github/workflows/ci.yml)

It currently:

- installs backend dependencies
- runs backend tests
- installs frontend dependencies
- builds the frontend
- builds Docker images

Example GitHub Actions webhook forwarder:

- [secureflow-webhook.yml](C:/Users/lenov/Desktop/CyberSecurity/SecureFlow/examples/github-actions/secureflow-webhook.yml)

## API Summary

Public:

- `GET /api/health`
- `POST /api/webhook`
- `POST /api/auth/register`
- `POST /api/auth/login`

Authenticated:

- `GET /api/auth/me`
- `GET /api/dashboard`
- `POST /api/scans`
- `GET /api/reports`
- `GET /api/reports/:reportId`
- `GET /api/reports/:reportId/download.pdf`
- `POST /api/reports/:reportId/findings/:findingId/remediation-pr`
- `GET /api/repositories/:repositoryId/analytics`
- `GET /api/scan-jobs`
- `GET /api/scan-jobs/:scanJobId`

## Verification Commands

Backend tests:

```bash
cd Backend
npm test
```

Frontend production build:

```bash
cd Frontend
npm run build
```

Docker Compose render:

```bash
docker compose config
```

Container scanner checks:

```bash
docker run --rm secureflow-backend gitleaks version
docker run --rm secureflow-backend trivy --version
```

## Operational Notes

- rotate any GitHub token that has ever been committed, echoed, or exposed in logs
- use a strong `JWT_SECRET` in production
- keep `BOOTSTRAP_ADMIN_PASSWORD` only long enough to create the initial admin account
- for local Vite development, restart the frontend when proxy config changes
- for real GitHub webhooks, use a public URL or tunnel instead of localhost

## Current Status

SecureFlow now includes:

- repository scanning
- AI explanation and remediation guidance
- automated remediation PR creation
- GitHub webhook automation
- security scoring and analytics
- JWT auth and role protection
- PDF report export
- containerization and CI groundwork

This is a solid capstone-level implementation, with the main remaining work being deployment-specific hardening, real secret management, and live infrastructure validation in your target cloud environment.
