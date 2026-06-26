# SecurityHub

## 🎯 What is SecurityHub?

**SecurityHub Community Edition** is a self-hosted vulnerability management and reporting platform for security teams and penetration testers. Built with Django and React, it streamlines the vulnerability lifecycle from scanner import through professional report generation.

This is a single-tenant deployment: all data lives in one shared workspace (no organizations/customer isolation), with a simple admin/staff permission model (no granular RBAC).

## 🚀 What Does SecurityHub Do?

### **Vulnerability Lifecycle Management**
- **Centralized Vulnerability Database**: Searchable database of vulnerabilities with CVE, CWE, and CVSS classifications
- **Multi-Project Support**: Manage vulnerabilities across multiple security assessment projects
- **Status Tracking**: Track vulnerability status from discovery through remediation, with retest support

### **Scanner Integration**
- **12 Built-in Scanner Parsers**: Import vulnerability data from Nessus, Burp Suite, Nmap, Acunetix, OWASP ZAP, Nuclei, OpenVAS, Qualys, Nexpose, AppSpider, SARIF, and Trivy
- **Automated Data Normalization**: Convert diverse scanner formats into a unified, standardized schema

### **Professional Reporting**
- **Multi-Format Reports**: Generate PDF and DOCX reports
- **Template Customization**: Design your own report templates using DOCX or HTML/CSS with dynamic content injection
- **Dynamic Content**: Populate reports with POC images, severity charts, vulnerability descriptions, and remediation recommendations
- **Version Control**: Track and restore template versions

### **Vulnerability Library & Reference Data**
- **VulnDB**: A read-only vulnerability template library, synced from a GitHub-hosted JSON source (admin-triggered) — speeds up manually adding common findings
- **Project Types / Report Standards**: Same GitHub-sync pattern for configurable reference lists
- **CWE Reference Data**: On-demand CWE catalog sync via admin action, source configurable via `CWE_DATA_GITHUB_URL`

## ✨ What Makes SecurityHub Special?

### **1. Multi-Scanner Support**
SecurityHub ships with parsers for 12 scanners covering the most common commercial and open-source tools — Nessus, Qualys, Burp Suite, Nmap, Nuclei, OWASP ZAP, OpenVAS, Acunetix, Nexpose, AppSpider, Trivy, and SARIF. All output is normalized into a single internal schema.

### **2. Flexible Template System**
- Create custom report templates in familiar formats (DOCX, HTML/CSS)
- Version control templates with restore support
- Dynamically inject content, images, severity charts, and metadata into generated reports

### **3. Modern, Extensible Architecture**
- **API-First Design**: Full REST API with OpenAPI/Swagger documentation
- **Modern Tech Stack**: Django 4.2+, React 18, TypeScript, PostgreSQL
- **Docker-Ready**: Complete containerization with Docker Compose
- **Configurable**: Upload limits, pagination, rate limits, JWT lifetimes, password policy, cache backend, and branding are all environment-configurable — see [env.example](env.example)

### **4. Open Source & Self-Hosted**
- **Open Source**: Full source code access for customization and security audits
- **Self-Hosted**: Complete control over your data and infrastructure
- **No Vendor Lock-in**

### What Community Edition does *not* include
This is a single-tenant build: there's no Organization/multi-tenant data isolation, no customer-facing portal, and no granular role/capability-based access control — authorization is a simple staff/admin distinction (Django's `is_staff`/`is_superuser`). There's no threat-intelligence enrichment engine (CISA KEV/EPSS/NVD feeds) or asset-management module. If you need any of that, those are enterprise-tier features not present in this codebase.

<br/>

[![Python Version](https://img.shields.io/badge/Python-3.9+-brightgreen)](https://www.python.org/downloads/release/python-391/)
[![NodeJS Version](https://img.shields.io/badge/NodeJS-18+-brightgreen)](https://nodejs.org/en/download/package-manager)
[![Docker](https://img.shields.io/badge/Docker-Ready-blue)](https://www.docker.com/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE.md)

## 🚀 Quick Start

### Prerequisites

- Docker and Docker Compose
- Git

### Installation

```bash
# Automated install (detects OS, installs Docker, prompts for config):
bash install.sh

# — or manually —
cp env.example .env        # single config template for all deployment modes
nano .env                  # fill in REQUIRED fields (SECRET_KEY, domain, passwords)
docker-compose up -d
docker-compose logs -f
```

**CORS**: The backend reads `CORS_ALLOWED_ORIGINS` (comma-separated list of origins). Set it in `.env`, e.g. `CORS_ALLOWED_ORIGINS=https://app.example.com`. See `env.example` for all available options.

The application will be available at:
- **Frontend**: http://localhost:3000
- **API**: http://localhost:3000/api
- **API Docs**: http://localhost:3000/api/docs

> [!WARNING]
> Review `env.example` and the [Installation Guide](docs/INSTALLATION.md) before deploying to production — several security-sensitive settings (SECRET_KEY, ALLOWED_HOST, CORS, HTTPS cookie flags) must be set correctly.

## 📋 Features

### Vulnerability Management
- **Centralized Database**: Maintain a comprehensive vulnerability database
- **Multi-Project Support**: Manage vulnerabilities across multiple projects
- **Status Tracking**: Track vulnerability status from discovery to remediation
- **Retest Management**: Track retest cycles per vulnerability instance

### Reporting
- **PDF Reports**: Generate professional PDF reports (via WeasyPrint)
- **DOCX Reports**: Create Word document reports with custom templates
- **Custom Templates**: Design your own report templates in DOCX or HTML/CSS
- **Dynamic Content**: Inject POC images, severity charts, descriptions, and recommendations

### Project Management
- **Project Organisation**: Manage all security projects in one place
- **Schedule Management**: Track project start/end dates
- **Scope Management**: Define and manage assessment scope per project

### Security Features
- **API Security**: JWT authentication via httpOnly cookies, rate limiting, input validation
- **Audit Logging**: Audit trail of key operations
- **XSS/XXE Hardening**: `bleach` sanitization on rich-text fields, `defusedxml` for all XML parsing

## 🏗️ Architecture

### Backend
- **Framework**: Django 4.2+ with Django REST Framework
- **Database**: PostgreSQL (SQLite fallback for local dev)
- **Cache**: In-memory by default; optionally Redis via `REDIS_URL` (recommended for multi-worker deployments)
- **API**: RESTful API with OpenAPI/Swagger documentation

### Frontend
- **Framework**: React 18 with TypeScript
- **Build Tool**: Vite
- **UI**: Tailwind CSS
- **State Management**: Zustand
- **Server State**: TanStack Query (React Query v5)

### Infrastructure
- **Containerization**: Docker with multi-stage builds
- **Orchestration**: Docker Compose
- **Web Server**: Nginx (reverse proxy + static file serving)
- **CI/CD**: GitHub Actions

## 📚 Documentation

- [Installation Guide](docs/INSTALLATION.md)
- [API Documentation](docs/API.md)
- [Contributing Guidelines](CONTRIBUTING.md)
- [Security Policy](SECURITY.md)

## 🛠️ Development

### Backend Development

```bash
# Install dependencies
poetry install

# Activate virtual environment
poetry shell

# Run migrations
python securityhub/manage.py migrate

# First-time setup (creates superuser, default project types, report standards)
python securityhub/manage.py first_setup

# Run development server
python securityhub/manage.py runserver
```

### Frontend Development

```bash
cd frontend

# Install dependencies
npm install

# Start development server (port 5173)
npm start

# Build for production
npm run build
```

### Running Tests

```bash
# Backend tests
pytest

# Frontend tests
cd frontend && npm test
```

## 🐳 Docker

### Build & Run

```bash
# Enable BuildKit for faster builds
export DOCKER_BUILDKIT=1
export COMPOSE_DOCKER_CLI_BUILD=1

# Build all images
docker-compose build

# Build a specific service
docker-compose build securityhub
docker-compose build nginx

# Start all services
docker-compose up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down

# Stop and remove volumes
docker-compose down -v
```

## 🔒 Security

SecurityHub takes security seriously. If you discover a security vulnerability, please:

1. **Do not** open a public issue
2. Report it privately via [GitHub's private security advisory feature](../../security/advisories/new) for this repository
3. Include steps to reproduce the vulnerability
4. Allow time for the issue to be addressed before disclosure

See [SECURITY.md](SECURITY.md) for our security policy.

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

1. Create a feature branch (`git checkout -b feature/amazing-feature`)
2. Make your changes
3. Write/update tests
4. Commit your changes (`git commit -m 'Add amazing feature'`)

## 📝 License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details.

## 🙏 Acknowledgments

- Built with [Django](https://www.djangoproject.com/)
- Frontend powered by [React](https://react.dev/)
- Styled with [Tailwind CSS](https://tailwindcss.com/)
- Icons from [Heroicons](https://heroicons.com/)
- PDF generation via [WeasyPrint](https://weasyprint.org/)

## 📞 Support

- **Documentation**: [docs/](docs/)
- **Issues**: [GitHub Issues](../../issues)
- **Maintainer**: WisePoo

## ✅ What's Implemented

- **Authentication** — JWT auth via httpOnly cookies, simple staff/admin permission model
- **Vulnerability Management** — full CRUD, status tracking, retest support, multi-project
- **Project Management** — project lifecycle, scope management
- **Scanner Integration** — 12 built-in parsers (Nessus, Burp Suite, Nmap, Acunetix, ZAP, Nuclei, OpenVAS, Qualys, Nexpose, AppSpider, SARIF, Trivy)
- **Reporting** — PDF and DOCX generation with a versioned template system and dynamic severity charts
- **Vulnerability Library / Project Types / Report Standards** — read-only reference data, synced on-demand from a configurable GitHub source
- **API** — full REST API with OpenAPI/Swagger docs
- **Docker Deployment** — full containerization with Docker Compose

This is a single-tenant, single-workspace deployment — see [What Community Edition does *not* include](#what-community-edition-does-not-include) above for the enterprise features intentionally left out of this build.

---

**SecurityHub Community Edition** — Self-Hosted Vulnerability Management Platform
