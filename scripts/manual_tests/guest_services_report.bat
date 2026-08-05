@echo off
setlocal enabledelayedexpansion

:: scripts/manual_tests/guest_services_report.bat
::
:: Purpose: collect Windows-side diagnostics relevant to GuestControl
:: readiness FROM INSIDE the guest VM. Copy this file into the guest
:: (or reach it via a shared folder) and run it manually inside
:: ADAM_WIN10_OFFICE -- it has no host-side VirtualBox or Python
:: dependency at all, it only shells out to standard Windows tools plus
:: VBoxControl.exe (bundled with Guest Additions).
::
:: Collects:
::   - sc query VBoxService    -- is the Guest Additions service running?
::   - sc qc VBoxService       -- its startup type (plain Automatic, or
::                                Automatic DELAYED -- the suspected
::                                cause of the ~70-100s GuestControl
::                                readiness delay after snapshot restore)
::   - sc query seclogon       -- Secondary Logon service, needed to run
::                                guest control processes as a specific user
::   - tasklist ^| findstr VBox -- which VBox-related processes are alive
::   - VBoxControl.exe --version -- Guest Additions version, from inside
::   - systeminfo              -- OS build, boot time / uptime
::
:: Output is saved next to this script, timestamped, so multiple runs
:: (e.g. right after boot, then again once GuestControl is confirmed
:: ready from the host side) can be compared side by side.

set TIMESTAMP=%date:~-4%%date:~4,2%%date:~7,2%_%time:~0,2%%time:~3,2%%time:~6,2%
set TIMESTAMP=%TIMESTAMP: =0%
set REPORT=%~dp0guest_services_report_%TIMESTAMP%.txt

echo ADAM guest services report > "%REPORT%"
echo Generated: %date% %time% >> "%REPORT%"
echo ============================================================ >> "%REPORT%"

echo. >> "%REPORT%"
echo --- sc query VBoxService --- >> "%REPORT%"
sc query VBoxService >> "%REPORT%" 2>&1

echo. >> "%REPORT%"
echo --- sc qc VBoxService --- >> "%REPORT%"
sc qc VBoxService >> "%REPORT%" 2>&1

echo. >> "%REPORT%"
echo --- sc query seclogon --- >> "%REPORT%"
sc query seclogon >> "%REPORT%" 2>&1

echo. >> "%REPORT%"
echo --- tasklist ^| findstr VBox --- >> "%REPORT%"
tasklist | findstr /I VBox >> "%REPORT%" 2>&1

echo. >> "%REPORT%"
echo --- VBoxControl.exe --version --- >> "%REPORT%"
"%ProgramFiles%\Oracle\VirtualBox Guest Additions\VBoxControl.exe" --version >> "%REPORT%" 2>&1

echo. >> "%REPORT%"
echo --- systeminfo --- >> "%REPORT%"
systeminfo >> "%REPORT%" 2>&1

echo.
echo Report saved to: %REPORT%

endlocal
