@echo off
title Mobile GRC Security Platform

cd /d D:\Mobile_GRC_Project

call venv\Scripts\activate

cls

echo ============================================
echo.
echo   ML-Enhanced Mobile Security Platform
echo.
echo   Server Starting...
echo.
echo   Open Browser:
echo   http://127.0.0.1:8000
echo.
echo ============================================

python -m uvicorn app.main:app --reload --log-level warning