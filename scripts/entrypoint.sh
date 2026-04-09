#!/bin/sh
set -eu

python manage.py migrate --noinput
python manage.py collectstatic --noinput
python manage.py seed_accounts || true
python manage.py load_owasp_top10 || true

exec gunicorn config.wsgi:application --bind 0.0.0.0:8000 --workers 3 --timeout 60
