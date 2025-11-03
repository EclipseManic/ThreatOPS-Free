@echo off
title ThreatOps SIEM - Complete Startup
color 0A

cd /d D:\Cusor AI\threat_ops

echo.
echo ================================================================
echo                   THREATOPS SIEM 
echo                 STARTING EVERYTHING...
echo ================================================================
echo.
echo This will open multiple windows for:
echo  - OpenSearch (database)
echo  - Filebeat (log collector)
echo  - OpenSearch Dashboards (analytics)
echo  - ThreatOps Dashboard (main UI)
echo.
echo DO NOT CLOSE THOSE WINDOWS!
echo.
pause

REM Use virtual environment Python
.venv\Scripts\python.exe run.py --mode all

echo.
pause
