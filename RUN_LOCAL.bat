@echo off
title TERPE v2 - local
cd /d "%~dp0"
echo ============================================
echo   TERPE v2 - starting on this laptop
echo ============================================
echo Installing / checking packages (first time takes a few minutes)...
python -m pip install -q fastapi uvicorn PyJWT pyarrow joblib scikit-learn pandas numpy requests streamlit plotly
if not exist ".streamlit\secrets.toml" echo API_URL = "http://127.0.0.1:8000"> ".streamlit\secrets.toml"
set ADMIN_USERNAME=yasaswi
set OWNER_USERNAME=yasaswi
if not exist terpe_users.db (
  echo.
  echo First run: choose the password for the admin account "yasaswi".
  echo Use 10+ characters with upper case, lower case, a number and a symbol.
  set /p ADMIN_PASSWORD=Admin password: 
)
for /f %%i in ('python -c "import secrets;print(secrets.token_urlsafe(40))"') do set JWT_SECRET=%%i
echo Starting the backend in a second window (its messages go to backend_log.txt)...
start "TERPE backend (keep open)" cmd /k "python -m uvicorn api:app --host 127.0.0.1 --port 8000 > backend_log.txt 2>&1"
timeout /t 15 /nobreak > nul
python -c "import urllib.request;print(urllib.request.urlopen('http://127.0.0.1:8000/health').read().decode())" || (echo. & echo BACKEND DID NOT START - send Claude a message, it can read backend_log.txt & echo.)
echo Opening the website in your browser...
python -m streamlit run app.py --server.port 8501
