# SecurityHub Community Edition

## Overview

SecurityHub Community Edition is a self-hosted vulnerability management and reporting platform for security teams and penetration testers. Built on Django and React, it covers the vulnerability lifecycle from scanner import through professional report generation.

This is a single-tenant deployment: all data lives in one shared workspace with no multi-tenant isolation. Authorization uses Django's standard `is_staff` / `is_superuser` distinction — there is no granular role-based access control.

---

## Features

### Vulnerability Management

- Searchable vulnerability database with CVE, CWE, and CVSS classifications
- Multi-project support: manage findings across independent security assessments
- Status tracking from discovery through remediation, with retest cycle support
- Triage workflow: mark findings as false positive, suppressed, or verified; record risk acceptance with a reason
- Bulk project delete via a single `DELETE` request with a JSON array of IDs
- Login with either username or email address

### Finding Details

- **SAST tracking**: source file, source line, sink file, sink line, and tainted-flow flag (populated by the SARIF parser)
- **Container and Kubernetes context**: cluster, namespace, workload, image, and image-digest fields (populated by the Trivy parser)
- **SCA / dependency intelligence**: package name, version, type, CPE, installed version, and vulnerable version ranges (populated by Trivy and SARIF parsers)
- **Compliance mapping**: NIST 800-53, OWASP MASVS, DISA STIG, and arbitrary compliance-framework fields
- **MITRE ATT&CK**: tactic and technique storage per finding
- **Network context**: IP addresses, hostnames, ports, services, protocols, and endpoints captured from scanner output

### Scanner Integration

12 built-in parsers covering the most common commercial and open-source tools:

| Parser | Tool |
|--------|------|
| Nessus | Tenable Nessus (`.nessus` XML and CSV) |
| Burp Suite | Burp Suite Pro XML export |
| Nmap | Nmap XML (`-oX`) |
| Acunetix | Acunetix XML export |
| OWASP ZAP | ZAP XML report |
| Nuclei | Nuclei JSON output |
| OpenVAS | OpenVAS XML report |
| Qualys | Qualys XML export |
| Nexpose | Rapid7 Nexpose XML |
| AppSpider | Rapid7 AppSpider XML |
| SARIF | SARIF 2.1.0 (any SAST tool) |
| Trivy | Trivy JSON (containers, filesystems) |

All scanner output is normalized into a single internal schema.

### Reporting

- PDF reports via WeasyPrint
- DOCX reports via docxtpl with custom templates
- Versioned template system with restore support
- Dynamic content injection: POC images, severity charts, descriptions, and remediation recommendations
- Scoped short-lived JWT issued at report generation time for secure server-side image fetching

### Project Management

- Full project lifecycle management with start/end dates and status tracking
- Scope management per project; Nmap XML scope auto-import endpoint
- Project status auto-progression as finding statuses change

### Vulnerability Library and Reference Data

- VulnDB: read-only vulnerability template library synced on demand from a configurable GitHub source — speeds up manual finding entry
- Project types and report standards use the same GitHub-sync pattern
- CWE reference data synced via admin action; source URL configurable via `CWE_DATA_GITHUB_URL`

### API and Documentation

- Full REST API with OpenAPI/Swagger documentation at `/api/docs/` and `/api/redoc/`
- JWT authentication via httpOnly cookies with configurable token lifetimes
- Rate limiting, input validation, and audit logging

---

## What Community Edition Does Not Include

- Multi-tenant data isolation (no Organization model)
- Customer-facing portal
- Granular role-based access control
- Threat-intelligence enrichment (CISA KEV/EPSS/NVD live feeds)
- CPE catalog sync (NVD API)
- Asset management module

These are enterprise-tier features absent from this codebase.

---

## Quick Start

### Prerequisites

- Docker and Docker Compose
- Git

### Installation

```bash
# Automated install (detects OS, installs Docker, prompts for configuration):
bash install.sh

# — or manually —
cp env.example .env        # single config template for all deployment modes
nano .env                  # fill in REQUIRED fields (SECRET_KEY, domain, passwords)
docker-compose up -d
docker-compose logs -f
```

The application will be available at:

| Service | URL |
|---------|-----|
| Frontend | http://localhost:3000 |
| API | http://localhost:3000/api |
| API Documentation | http://localhost:3000/api/docs |

> **Production note**: Review `env.example` and [docs/INSTALLATION.md](docs/INSTALLATION.md) before deploying. Several security-sensitive settings (SECRET_KEY, ALLOWED_HOST, CORS, HTTPS cookie flags) must be configured correctly.

**CORS**: The backend reads `CORS_ALLOWED_ORIGINS` (comma-separated list of origins). Set it in `.env`, for example: `CORS_ALLOWED_ORIGINS=https://app.example.com`. See `env.example` for all available options.

---

## Architecture

### Backend

- **Framework**: Django 4.2 with Django REST Framework
- **Database**: PostgreSQL (SQLite fallback for local development)
- **Cache**: In-memory by default; Redis recommended when running more than one worker (`REDIS_URL`)
- **Auth**: JWT via httpOnly cookies (SimpleJWT); lifetimes configurable

### Frontend

- **Framework**: React 18 with TypeScript
- **Build tool**: Vite
- **UI**: Tailwind CSS
- **State**: Zustand for global state; TanStack Query for server-state caching

### Infrastructure

- **Containerization**: Docker with multi-stage builds
- **Orchestration**: Docker Compose
- **Web server**: Nginx (reverse proxy and static file serving)

---

## Development

### Backend

```bash
poetry install
poetry shell

python securityhub/manage.py migrate

# First-time setup: creates superuser, default project types, and report standards
python securityhub/manage.py first_setup

python securityhub/manage.py runserver
```

### Frontend

```bash
cd frontend
npm install
npm start           # dev server on port 5173
npm run build       # production build
```

### Running Tests

```bash
# Backend
pytest

# Frontend
cd frontend && npm test
```

---

## Docker

```bash
export DOCKER_BUILDKIT=1
export COMPOSE_DOCKER_CLI_BUILD=1

docker-compose build
docker-compose up -d
docker-compose logs -f
docker-compose down
```

---

## Security

If you discover a vulnerability, do not open a public issue. Report it privately via [GitHub's private security advisory feature](../../security/advisories/new). Include steps to reproduce and allow time for the issue to be addressed before disclosure.

See [SECURITY.md](SECURITY.md) for the full security policy.

---

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## License

MIT License — see [LICENSE.md](LICENSE.md) for details.

---

## Acknowledgments

- [Django](https://www.djangoproject.com/) and [Django REST Framework](https://www.django-rest-framework.org/)
- [React](https://react.dev/)
- [Tailwind CSS](https://tailwindcss.com/)
- [WeasyPrint](https://weasyprint.org/) for PDF generation
- [Heroicons](https://heroicons.com/)

---

[![Python Version](https://img.shields.io/badge/Python-3.9+-brightgreen)](https://www.python.org/downloads/release/python-391/)
[![NodeJS Version](https://img.shields.io/badge/NodeJS-18+-brightgreen)](https://nodejs.org/en/download/package-manager)
[![Docker](https://img.shields.io/badge/Docker-Ready-blue)](https://www.docker.com/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE.md)

---

**SecurityHub Community Edition** — Self-Hosted Vulnerability Management Platform
Maintainer: WisePoo | [Issues](../../issues) | [Documentation](docs/)
