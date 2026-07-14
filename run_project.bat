@echo off
:: Start Django server (frontend templates + API are both served on :8000)
start cmd /k ".\venv\Scripts\activate && cd api && python.exe .\manage.py runserver"

:: Delay to ensure backend starts first
timeout /t 5 /nobreak >nul

:: Open default browser
start "" "http://127.0.0.1:8000/"
start "" "http://127.0.0.1:8000/admin/"
