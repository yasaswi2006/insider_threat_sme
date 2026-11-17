@echo off
cd /d "%~dp0"
echo Installing downloader...
python -m pip install huggingface_hub
echo Downloading CERT r4.2 files (about 290 MB)...
python download_data.py
echo.
echo Finished. You can close this window.
pause
