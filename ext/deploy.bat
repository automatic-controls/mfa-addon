@echo off
if "%WebCTRL%" EQU "" goto :bad
if "%addonFile%" EQU "" goto :bad
if "%certFile%" EQU "" goto :bad
if /i "%*" EQU "--help" (
  echo DEPLOY            Copies the .addon archive and certificate file to the bound WebCTRL installation.
  exit /b 0
)
if "%*" NEQ "" (
  echo Unexpected parameter.
  exit /b 1
)
if not exist "%addonFile%" (
  echo Cannot deploy because !name!.addon does not exist.
  exit /b 1
)
echo Deploying...
if "!name!" EQU "AddonDevRefresher" (
  echo Cannot be used to self-deploy.
  echo Deployment unsuccessful.
  exit /b 1
)
if not exist "%WebCTRL%\programdata\addons" mkdir "%WebCTRL%\programdata\addons" >nul 2>nul
copy /y "%certFile%" "%WebCTRL%\programdata\addons\%certFileName%" >nul
copy /y "%addonFile%" "%WebCTRL%\programdata\addons\!name!.update" >nul
if %ErrorLevel% NEQ 0 (
  echo Deployment unsuccessful.
  exit /b 1
)
set /a count=0
:waitUpdate
timeout 1 /nobreak >nul
set /a count+=1
if exist "%WebCTRL%\programdata\addons\!name!.update" (
  if "%count%" EQU "60" (
    echo Timeout occurred.
    echo Deployment unsuccessful.
    exit /b 1
  ) else (
    goto :waitUpdate
  )
)
if exist "%WebCTRL%\programdata\addons\!name!.addon" (
  echo Deployment successful.
  exit /b 0
) else (
  echo Deployment unsuccessful.
  exit /b 1
)

:bad
  echo This script should not be invoked as a stand-alone application.
  echo You must use this file as an extension to addon-dev-script.
  echo https://github.com/automatic-controls/addon-dev-script
  echo Press any key to exit.
  pause >nul
exit /b 1