#!/bin/bash
# SecurityHub Community Edition — Backend Startup (DEV)
# Uses Django runserver for hot-reload. Do NOT use in production.

set -e

cd securityhub

echo "Waiting for PostgreSQL..."
if [ -n "${POSTGRES_HOST}" ]; then
  until pg_isready -h "${POSTGRES_HOST}" -U "${POSTGRES_USER}"; do
    sleep 2
  done
fi
echo "PostgreSQL ready."

echo "Checking database ${POSTGRES_DB}..."
PGPASSWORD=$POSTGRES_PASSWORD psql -h $POSTGRES_HOST -U $POSTGRES_USER -lqt | cut -d \| -f 1 | grep -qw $POSTGRES_DB
if [ $? -ne 0 ]; then
  echo "Database ${POSTGRES_DB} not found. Exiting."
  exit 1
fi

echo "Running migrations..."
python3 manage.py migrate --noinput
echo "Migrations done."

SETUP_FLAG="${HOME}/.securityhub/first_setup_done"
if [ ! -f "${SETUP_FLAG}" ]; then
  echo "Running first-time setup..."
  python3 manage.py first_setup
  python3 manage.py create_default_templates || true
  mkdir -p "$(dirname ${SETUP_FLAG})"
  touch "${SETUP_FLAG}"
else
  echo "First-time setup already completed."
fi

if [ "${USE_S3:-False}" != "True" ]; then
  echo "Collecting static files..."
  python3 manage.py collectstatic --noinput || true
fi

echo "Starting Django dev server with hot-reload..."
exec python3 manage.py runserver 0.0.0.0:8000
