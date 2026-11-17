@echo off
setlocal
if "%~1"=="" (
  echo Sleep een originele Hermes .watchface op dit bestand.
  echo Er wordt een NIEUWE -migration-test.watchface aangemaakt.
  echo Het origineel wordt niet aangepast.
  pause
  exit /b 1
)
where py >nul 2>&1
if not errorlevel 1 (
  py -3 "%~dp0make_migration_watchface.py" "%~1"
) else (
  python "%~dp0make_migration_watchface.py" "%~1"
)
echo.
echo Kopieer beide bestanden naar Bestanden op je iPhone.
echo Test de nieuwe kopie met de TEST-importknop in HermesEnabler.
pause
