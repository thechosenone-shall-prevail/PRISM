@echo off
echo ========================================
echo   PRISM Dashboard Startup
echo ========================================
echo.
echo Starting backend server...
echo Dashboard will be available at: http://localhost:8000/
echo.
echo Press Ctrl+C to stop the server
echo.
cd backend
uvicorn main:app --reload --host 0.0.0.0 --port 8000
