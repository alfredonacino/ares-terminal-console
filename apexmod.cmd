@echo off
rem Windows shim for the uniform launcher. Keeps `apexmod run ...` identical
rem across platforms, since cmd.exe does not read a shebang line.
setlocal
set "HERE=%~dp0"
where py >nul 2>nul && (py -3 "%HERE%apexmod" %* & exit /b %ERRORLEVEL%)
python "%HERE%apexmod" %*
