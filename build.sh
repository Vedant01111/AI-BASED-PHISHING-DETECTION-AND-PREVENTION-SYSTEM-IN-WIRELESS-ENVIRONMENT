#!/usr/bin/env bash
# Render runs this during every deploy.
set -o errexit

pip install -r requirements.txt

cd api
python manage.py collectstatic --noinput
python manage.py migrate
