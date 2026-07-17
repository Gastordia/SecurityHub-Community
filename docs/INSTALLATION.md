# Installation

Short pointer doc. For full steps, follow the links below.

## Docker (recommended)

- **[README — Getting it running](../README.md#getting-it-running)** — Clone, run `install.sh` (or copy env manually), `docker compose up -d`.
- **Env template:** Copy [`env.example`](../env.example) at repo root to `.env` and edit.
- Default URLs (when using default Docker port mapping): [Frontend HTTP](http://localhost:3000), [Frontend HTTPS](https://localhost:8443), [API Docs](https://localhost:8443/api/docs/).

## Development (local backend + frontend)

- **[CONTRIBUTING — Setting up development environment](../CONTRIBUTING.md#setting-up-development-environment)** — uv, PostgreSQL, Redis, env, `first_setup`, runserver.
- **Env:** Copy [`env.example`](../env.example) at repo root to `.env` and configure.

## More

- **Architecture and deployment details:** See [docs/ARCHITECTURE.md](ARCHITECTURE.md).
- **Security / ENV:** See README and env example files for security-related variables.
