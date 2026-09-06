@echo off
REM Development convenience shim. The installer-generated command binds an
REM absolute interpreter and is the only supported public Windows launcher.
if exist "%USERPROFILE%\.local\bin\plamen.cmd" (
  call "%USERPROFILE%\.local\bin\plamen.cmd" %*
  exit /b %ERRORLEVEL%
)
echo Plamen is not installed. Run an explicit trusted Python interpreter on plamen.py install. 1>&2
exit /b 1
