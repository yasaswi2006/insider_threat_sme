@echo off
title TERPE v2 - local
cd /d "%~dp0"
echo ============================================
echo   TERPE v2 - starting on this laptop
echo ============================================
echo Installing / checking packages (first time takes a few minutes)...
python -m pip install -q -r requirements.txt
if not exist ".streamlit\secrets.toml" echo API_URL = "http://127.0.0.1:8000"> ".streamlit\secrets.toml"
set ADMIN_USERNAME=baishakhi
set OWNER_USERNAME=baishakhi
if not exist terpe_users.db (
  echo.
  echo First run: choose the password for your admin account "baishakhi".
  echo Use 10+ characters with upper case, lower case, a number and a symbol.
  set /p ADMIN_PASSWORD=Admin password: 
)
for /f %%i in ('python -c "import secrets;print(secrets.token_urlsafe(40))"') do set JWT_SECRET=%%i
echo Starting the backend in a second window...
start "TERPE backend (keep open)" cmd /k python -m uvicorn api:app --host 127.0.0.1 --port 8000
timeout /t 12 /nobreak > nul
echo Opening the website in your browser...
python -m streamlit run app.py --server.port 8501
