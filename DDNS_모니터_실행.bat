@echo off
chcp 65001 > nul
title DDNS Ping 통합 관리 대시보드
cd /d "%~dp0"
python server.py
pause
