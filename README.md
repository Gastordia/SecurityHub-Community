[![CI](https://github.com/Gastordia/SecurityHub-Community/actions/workflows/ci.yml/badge.svg)](https://github.com/Gastordia/SecurityHub-Community/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE.md)
[![Docker](https://img.shields.io/badge/Docker-Ready-blue)](https://www.docker.com/)
[![Python](https://img.shields.io/badge/Python-3.10%2B-blue)](pyproject.toml)
[![React](https://img.shields.io/badge/Frontend-React%20%2B%20TypeScript-61DAFB)](frontend)

# SecurityHub Community Edition

SecurityHub is a self-hosted vulnerability management and reporting platform for small security teams, consultants, and internal AppSec groups.

It gives you one place to:
- import scanner output
- track findings through triage and remediation
- manage projects and retests
- generate PDF and DOCX reports on infrastructure you control

This repository includes the backend API, the frontend, Docker deployment files, parser implementations, and the reporting engine.

## Who this is for

SecurityHub is a practical fit if you want:
- a self-hosted alternative to keeping findings in spreadsheets and slide decks
- a place to normalize output from several scanners
- customizable reporting without sending client data to a third-party SaaS

It is probably not the right fit if you want:
- a hosted service
- a minimal single-binary install
- a polished scanner orchestration platform with agent deployment

## What works today

Core capabilities in this repo:
- multi-project vulnerability tracking with status history and retest flows
- import support for `Nessus`, `Burp Suite`, `Nmap`, `Acunetix`, `OWASP ZAP`, `Nuclei`, `OpenVAS`, `Qualys`, `Nexpose`, `AppSpider`, `SARIF`, and `Trivy`
- PDF and DOCX report generation from customizable templates
- project scope import from Nmap XML
- built-in vulnerability reference data, CWE data, project types, and report standards
- OpenAPI schema generation with `drf-spectacular`

If you need a parser that is not included yet, see [docs/writing-a-parser.md](docs/writing-a-parser.md).

## Architecture

```mermaid
flowchart LR
    User(["Security engineer"]) -->|HTTPS| Nginx
    Nginx --> Frontend["React + TypeScript SPA"]
    Nginx --> API["Django REST API"]
    API --> DB[("PostgreSQL")]
    API --> Cache[("Redis cache")]
    API --> Parsers["Scanner parsers"]
    API --> Reports["DOCX / PDF report engine"]
```

Main components:
- Backend: Django + Django REST Framework
- Frontend: React + TypeScript + Vite
- Database: PostgreSQL in production, SQLite fallback for local dev only
- Cache: in-memory by default, Redis recommended for multi-worker deployments
- Deployment: Docker Compose with `nginx`, `securityhub`, and `postgres`

For the full application walkthrough, see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Quick Start

### Recommended path: Docker Compose

Prerequisites:
- Docker
- Docker Compose

Clone the repo and run the installer:

```bash
git clone https://github.com/Gastordia/SecurityHub-Community.git
cd SecurityHub-Community
bash install.sh
```

What the installer does:
- detects the OS
- installs Docker if needed
- creates `.env`
- prompts for ports, secrets, database credentials, and admin bootstrap values
- starts the stack

### Manual Docker setup

If you do not want the interactive installer:

```bash
git clone https://github.com/Gastordia/SecurityHub-Community.git
cd SecurityHub-Community
cp env.example .env
```

Edit `.env` and set these values before first start:
- `SECRET_KEY`
- `ALLOWED_HOST`
- `CORS_ALLOWED_ORIGINS`
- `CSRF_TRUSTED_ORIGINS`
- `POSTGRES_PASSWORD`
- `REDIS_PASSWORD`
- `FRONTEND_URL`
- `SETUP_EMAIL`
- `SETUP_PASSWORD` or leave the documented default and change it immediately after login

Then start the stack:

```bash
docker compose up -d
```

Default URLs with the default port mapping:

| Service | URL |
|---|---|
| Frontend HTTP | http://localhost:3000 |
| Frontend HTTPS | https://localhost:8443 |
| API docs | https://localhost:8443/api/docs/ |
| OpenAPI schema endpoint | https://localhost:8443/api/schema/ |

Notes:
- `/api/docs/` requires authentication on a running instance
- the repo also contains a static schema snapshot at [openapi-schema.yaml](openapi-schema.yaml)
- PostgreSQL is required for production use

## First Login and Bootstrap

The app creates its initial admin account through `manage.py first_setup`.

In Docker installs:
- `install.sh` handles this for you
- the backend startup script also runs first-time setup automatically if the instance has not been initialized yet

The bootstrap values come from `.env`:
- `SETUP_USERNAME`
- `SETUP_EMAIL`
- `SETUP_FULL_NAME`
- `SETUP_POSITION`
- `SETUP_COMPANY_NAME`
- `SETUP_PASSWORD`

If you leave `SETUP_PASSWORD=ChangeMe123!`, change it immediately after login.

## Production Notes

SecurityHub will run locally with loose settings, but production needs deliberate configuration.

Minimum production checklist:
- set a strong `SECRET_KEY`
- use real hostnames in `ALLOWED_HOST`
- set exact browser origins in `CORS_ALLOWED_ORIGINS`
- set exact POST origins in `CSRF_TRUSTED_ORIGINS`
- keep `DEBUG=False`
- use PostgreSQL, not SQLite
- enable HTTPS in front of the application
- review `WHITELIST_IP` carefully because it controls what the backend may fetch when generating reports

Storage:
- local filesystem storage works out of the box
- S3-compatible storage is supported through `USE_S3=True` and the `AWS_*` variables in [.env example](env.example)

Caching:
- a blank `REDIS_URL` uses per-process memory cache
- for multiple Gunicorn workers or multiple replicas, set `REDIS_URL`

## Local Development

Python dependency management uses `uv`. The Python source of truth is [pyproject.toml](pyproject.toml) with [uv.lock](uv.lock).

### Backend

From the repository root:

```bash
cp env.example .env
uv sync
uv run python securityhub/manage.py migrate
uv run python securityhub/manage.py first_setup
uv run python securityhub/manage.py runserver
```

Useful local-development notes:
- if all `POSTGRES_*` variables are absent, Django falls back to SQLite
- Redis is optional for single-worker local development
- the backend reads `.env` from the repo root

### Frontend

```bash
cd frontend
npm install
npm start
```

This starts the Vite dev server on `http://localhost:5173`.

### Tests

Backend:

```bash
uv run python securityhub/manage.py test
cd securityhub && uv run pytest
```

Frontend:

```bash
cd frontend
npm test
```

## Project Layout

High-level directories:
- `securityhub/` — Django project and apps
- `frontend/` — React frontend
- `docker/` — Dockerfiles
- `scripts/` — startup and support scripts
- `docs/` — architecture and contributor docs
- `securityhub/utils/parsers/` — scanner parser implementations
- `securityhub/tests/fixtures/scans/` — parser sample files used by tests

## Documentation

| Document | Purpose |
|---|---|
| [docs/INSTALLATION.md](docs/INSTALLATION.md) | Installation pointers for Docker and local development |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Django apps, request flow, parser pipeline, and system layout |
| [docs/writing-a-parser.md](docs/writing-a-parser.md) | Contract for adding a new scanner parser |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Development workflow, testing, and contribution rules |
| [SECURITY.md](SECURITY.md) | Vulnerability disclosure policy and secure-coding notes |
| [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) | Community expectations |
| [openapi-schema.yaml](openapi-schema.yaml) | Checked-in OpenAPI schema snapshot |

## Uninstalling

The uninstaller removes what the installer created. It does not remove your source tree or arbitrary system packages.

```bash
bash uninstall.sh
```

Options:

| Flag | Effect |
|---|---|
| `--keep-data` | Preserve database data |
| `--keep-env` | Keep `.env` |
| `--yes` | Skip confirmation |

Uploaded media under `securityhub/media/` is left in place.

## Security

If you find a vulnerability, report it privately through [GitHub Security Advisories](../../security/advisories/new).

Do not open public issues for security findings.

## Contributing

Contributions are welcome, especially:
- new parser support
- bug fixes with tests
- documentation fixes
- reporting and template improvements

Start with [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT. See [LICENSE.md](LICENSE.md).
