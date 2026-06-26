[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE.md)
[![Docker](https://img.shields.io/badge/Docker-Ready-blue)](https://www.docker.com/)

# SecurityHub Community Edition

Self-hosted vulnerability management and reporting platform for security teams.

---

## What it does

SecurityHub gives security teams a single place to import scanner findings, track them through remediation, and generate client-ready reports — on infrastructure they control.

---

## Features

**Vulnerability tracking**
- Manage findings across multiple projects with full status tracking and retest cycles
- Triage findings as false positive, suppressed, or verified; document risk acceptance decisions
- Capture SAST source/sink data, container and Kubernetes metadata, dependency information, compliance mappings, and MITRE ATT&CK details alongside each finding

**Scanner import — 12 parsers included**

Nessus · Burp Suite · Nmap · Acunetix · OWASP ZAP · Nuclei · OpenVAS · Qualys · Nexpose · AppSpider · SARIF · Trivy

**Reporting**
- Generate PDF and DOCX reports from fully customizable templates
- Version-control templates and restore previous versions
- Inject charts, screenshots, and structured finding data dynamically

**Project management**
- Track scope, schedule, and status per project
- Import scope directly from Nmap XML output

**Reference data**
- Built-in vulnerability template library to speed up manual finding entry
- CWE reference data, project types, and report standards — all configurable

---

## Quick start

Requires Docker and Docker Compose.

```bash
git clone https://github.com/Gastordia/SecurityHub-Community.git
cd SecurityHub-Community
bash install.sh
```

The installer detects your operating system, installs Docker if needed, and walks through configuration interactively.

**Manual setup:**

```bash
cp env.example .env      # copy the config template
nano .env                # set SECRET_KEY, domain, and credentials
docker-compose up -d
```

Once running, the application is available at:

| | URL |
|---|---|
| HTTP | http://localhost:3000 |
| HTTPS | https://localhost:8443 |
| API docs | https://localhost:8443/api/docs |

For production, point your domain's DNS at the host and set `ALLOWED_HOST`, `CORS_ALLOWED_ORIGINS`, and `CSRF_TRUSTED_ORIGINS` in `.env`. See [docs/INSTALLATION.md](docs/INSTALLATION.md) for the full guide.

---

## Development setup

**Backend:**

```bash
poetry install && poetry shell
python securityhub/manage.py migrate
python securityhub/manage.py first_setup
python securityhub/manage.py runserver
```

**Frontend:**

```bash
cd frontend
npm install
npm start        # dev server on :5173
```

**Tests:**

```bash
pytest                       # backend
cd frontend && npm test      # frontend
```

---

## Security

Report vulnerabilities privately via [GitHub Security Advisories](../../security/advisories/new). Do not open a public issue. See [SECURITY.md](SECURITY.md) for the full policy.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT — see [LICENSE.md](LICENSE.md).
