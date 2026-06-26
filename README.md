# SecurityHub

## 🎯 What is SecurityHub?

**SecurityHub Community Edition** is a self-hosted vulnerability management and reporting platform for security teams and penetration testers. Built with Django and React, it streamlines the vulnerability lifecycle from scanner import through professional report generation.

This is a single-tenant deployment: all data lives in one shared workspace (no organizations/customer isolation), with a simple admin/staff permission model (no granular RBAC).

## 🚀 What Does SecurityHub Do?

### **Vulnerability Lifecycle Management**
- **Centralized Vulnerability Database**: Searchable database of vulnerabilities with CVE, CWE, and CVSS classifications
- **Multi-Project Support**: Manage vulnerabilities across multiple security assessment projects
- **Status Tracking**: Track vulnerability status from discovery through remediation, with retest support

### **Universal Scanner Integration**
- **100+ Scanner Parser Support**: Import vulnerability data from a wide range of scanners, including Nessus, Burp Suite, Nmap, Acunetix, OWASP ZAP, Nuclei, OpenVAS, Qualys, Nexpose, AppSpider, and many more
- **Automated Data Normalization**: Convert diverse scanner formats into a unified, standardized schema
- **Custom Parsers**: Define your own mapping-driven parser for scanners not supported out of the box

### **Professional Reporting**
- **Multi-Format Reports**: Generate PDF, DOCX, and Excel reports
- **Template Customization**: Design your own report templates using DOCX or HTML/CSS with dynamic content injection
- **Dynamic Content**: Populate reports with POC images, vulnerability descriptions, and remediation recommendations
- **Version Control**: Track template versions and usage

### **Vulnerability Library & Reference Data**
- **VulnDB**: A read-only vulnerability template library, synced from a GitHub-hosted JSON source (admin-triggered) — speeds up manually adding common findings
- **Project Types / Report Standards**: Same GitHub-sync pattern for configurable reference lists
- **CWE Reference Data**: Periodically refreshed CWE catalog, source configurable via `CWE_DATA_GITHUB_URL`

## ✨ What Makes SecurityHub Special?

### **1. Broad Scanner Compatibility**
SecurityHub supports **100+ security scanners** out of the box. Whether you're using commercial tools like Nessus and Qualys, open-source tools like Nmap and Nuclei, or specialized scanners, SecurityHub can ingest and normalize the data automatically.

### **2. Flexible Template System**
- Create custom report templates in familiar formats (DOCX, HTML/CSS)
- Version control templates and track usage
- Dynamically inject content, images, charts, and metadata

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

<br/><br/>

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
- **Frontend**: http://localhost
- **API**: http://localhost/api
- **API Docs**: http://localhost/api/docs

> [!Warning]
> Please ensure to review the documentation for Security Configuration for ENV and other Installation methods.

## 📋 Features

### Vulnerability Management
- **Centralized Database**: Maintain a comprehensive vulnerability database
- **Multi-Project Support**: Manage vulnerabilities across multiple projects
- **Status Tracking**: Track vulnerability status from discovery to remediation
- **Retest Management**: Schedule and manage retest cycles

### Reporting
- **PDF Reports**: Generate professional PDF reports
- **DOCX Reports**: Create Word document reports with custom templates
- **Excel Export**: Export vulnerability data to Excel
- **Custom Templates**: Design your own report templates in DOCX or HTML/CSS
- **Dynamic Content**: Add POC images, descriptions, and recommendations dynamically

### Project Management
- **Project Organization**: Manage all security projects in one place
- **Schedule Management**: Track project start/end dates

### Security Features
- **API Security**: JWT authentication (httpOnly cookies), rate limiting, input validation
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
- **HTTP Client**: Axios with React Query

### Infrastructure
- **Containerization**: Docker with multi-stage builds
- **Orchestration**: Docker Compose
- **Web Server**: Nginx (reverse proxy)
- **CI/CD**: GitHub Actions

## 📚 Documentation

- [Installation Guide](docs/INSTALLATION.md)
- [API Documentation](docs/API.md)
- [Docker Guide](DOCKER_BUILD_GUIDE.md)
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

# Create superuser
python securityhub/manage.py createsuperuser

# Run development server
python securityhub/manage.py runserver
```

### Frontend Development

```bash
cd frontend

# Install dependencies
npm install

# Start development server
npm start

# Build for production
npm run build
```

### Running Tests

```bash
# Backend tests
python securityhub/manage.py test

# Frontend tests
cd frontend && npm test
```

## 🐳 Docker

### Build Images

```bash
# Enable BuildKit for faster builds
export DOCKER_BUILDKIT=1
export COMPOSE_DOCKER_CLI_BUILD=1

# Build all images
docker-compose build

# Build specific service
docker-compose build securityhub-api
docker-compose build securityhub-frontend
```

### Run Services

```bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down

# Stop and remove volumes
docker-compose down -v
```

See [DOCKER_BUILD_GUIDE.md](DOCKER_BUILD_GUIDE.md) for detailed Docker documentation.

## 🔒 Security

SecurityHub takes security seriously. If you discover a security vulnerability, please:

1. **Do not** open a public issue
2. Report it privately via [GitHub's private security advisory feature](../../security/advisories/new) for this repository
3. Include steps to reproduce the vulnerability
4. Allow time for the issue to be addressed before disclosure

See [SECURITY.md](SECURITY.md) for our security policy.

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Development Setup

1. Create a feature branch (`git checkout -b feature/amazing-feature`)
2. Make your changes
3. Write/update tests
4. Commit your changes (`git commit -m 'Add amazing feature'`)

## 📝 License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details.

## 🙏 Acknowledgments

- Built with [Django](https://www.djangoproject.com/)
- Frontend powered by [React](https://react.dev/)
- UI components from [Material Tailwind](https://www.material-tailwind.com/)
- Icons from [Heroicons](https://heroicons.com/)

## 📞 Support

- **Documentation**: [docs/](docs/)
- **Maintainer**: WisePoo

## ✅ What's Implemented

- **Authentication** — JWT auth via httpOnly cookies, simple staff/admin permission model
- **Vulnerability Management** — full CRUD, status tracking, retest support, multi-project
- **Project Management** — project lifecycle, scope management
- **Scanner Integration** — 100+ scanner parsers (Nessus, Burp, Nmap, Acunetix, ZAP, Nuclei, OpenVAS, Qualys, etc.), plus a custom mapping-driven parser builder
- **Reporting** — PDF, DOCX, and Excel generation with a versioned template system (components, schema validation, charts)
- **Vulnerability Library / Project Types / Report Standards** — read-only reference data, synced from a configurable GitHub source
- **API** — full REST API with OpenAPI/Swagger docs
- **Docker Deployment** — full containerization with Docker Compose

This is a single-tenant, single-workspace deployment — see [What Community Edition does *not* include](#what-community-edition-does-not-include) above for the enterprise features intentionally left out of this build.

**SecurityHub Community Edition** — Security Vulnerability Management Platform
