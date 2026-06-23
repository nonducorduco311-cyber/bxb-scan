@echo off
title ByTE X Bit Posture Scanner
"%~dp0bxb-scan.exe" --html "%~dp0posture-report.html"
echo.
echo A copy of this report was saved next to this file as posture-report.html
echo.
pause
