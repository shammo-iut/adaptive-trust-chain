@echo off
REM ATC Phase 4 — Streamlit App Launcher (Windows)
REM Assumes Python 3.14 installed at C:\Python314\
REM Edit the path below if your Python install is elsewhere.

SET PYTHON=C:\Python314\python.exe

echo Starting ATC Phase 4 ASI-PLC Simulator...
echo.

REM Check if Python exists at the specified path
IF NOT EXIST "%PYTHON%" (
    echo Python not found at %PYTHON%.
    echo Trying system PATH...
    SET PYTHON=python
)

REM Install dependencies if needed
%PYTHON% -m pip install --quiet streamlit numpy matplotlib seaborn scipy

REM Launch Streamlit
%PYTHON% -m streamlit run Prototype_app.py

pause
