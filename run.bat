@echo off
echo ===================================================
echo Starting Application (Backend + Frontend)
echo ===================================================

echo Cleaning up old processes on port 3001 (Backend) and 5173 (Frontend)...
for /f "tokens=5" %%a in ('netstat -aon ^| find ":3001" ^| find "LISTENING"') do taskkill /f /pid %%a 2>nul
for /f "tokens=5" %%a in ('netstat -aon ^| find ":5173" ^| find "LISTENING"') do taskkill /f /pid %%a 2>nul
echo Cleaned successfully!

echo Starting Backend...
start cmd /k "cd backend && npm start"

echo Starting Frontend...
start cmd /k "cd frontend && npm run dev"

echo Both services are starting up cleanly in separate windows!
exit
