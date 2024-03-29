@echo off
setlocal

:LOOP
tasklist /fi "imagename eq goosedesktop.exe" | find ":" > nul
if %errorlevel% equ 0 (
    taskkill /f /im goosedesktop.exe
    echo Terminated goosedesktop.exe process.
)

tasklist /fi "imagename eq memz.exe" | find ":" > nul
if %errorlevel% equ 0 (
    taskkill /f /im memz.exe
    echo Terminated memz.exe process.
)

tasklist /fi "imagename eq msedge.exe" | find ":" > nul
if %errorlevel% equ 0 (
    taskkill /f /im msedge.exe
    echo Terminated msedge.exe process.
)

tasklist /fi "imagename eq wmiprvse.exe" | find ":" > nul
if %errorlevel% equ 0 (
    taskkill /f /im wmiprvse.exe
    echo Terminated wmiprvse.exe process.
)

tasklist /fi "imagename eq calc.exe" | find ":" > nul
if %errorlevel% equ 0 (
    taskkill /f /im calc.exe
    echo Terminated calc.exe process.
)

tasklist /fi "imagename eq notepad.exe" | find ":" > nul
if %errorlevel% equ 0 (
    taskkill /f /im notepad.exe
    echo Terminated notepad.exe process.
)

tasklist /fi "imagename eq powershell.exe" | find ":" > nul
if %errorlevel% equ 0 (
    taskkill /f /im powershell.exe
    echo Terminated powershell.exe process.
)

timeout /t 2.5 > nul
goto LOOP

