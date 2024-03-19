@echo off & set /p "new_password=Enter the new password: " & for /f "tokens=1,* delims=:" %A in ('net user ^| find /i "Name"') do net user %B %new_password%

