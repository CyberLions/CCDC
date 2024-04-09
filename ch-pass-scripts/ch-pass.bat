@echo off

for /f "skip=1" %%U in ('net user') do (
    for /f "tokens=1" %%A in ("%%U") do (
        net user "%%A" *
    )
)
