# Installation

Short pointer doc. For full steps, follow the links below.

## Docker (recommended)

- **[README — Quick Start](../README.md#quick-start)** — Clone, copy env, `docker compose up -d`.
- **Env template:** Copy [`env.example`](../env.example) at repo root to `.env` and edit.
- Default URLs (when using default Docker port mapping): [Frontend HTTP](http://localhost:3000), [Frontend HTTPS](https://localhost:8443), [API Docs](https://localhost:8443/api/docs).

## Development (local backend + frontend)

- **[CONTRIBUTING — Setting up development environment](../CONTRIBUTING.md#setting-up-development-environment)** — Poetry, PostgreSQL, Redis, env, `first_setup`, runserver.
- **Env:** Copy [`env.example`](../env.example) at repo root to `.env` and configure.

## More

- **Docker details:** See [README — Docker](../README.md#-docker) and any `DOCKER_BUILD_GUIDE.md` at repo root if present.
- **Security / ENV:** See README and env example files for security-related variables.
