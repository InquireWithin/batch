:: 4/14/22 LB
:: justification for not using firewall:
:: Note that Windows will eventually remove the ability to use the batch interpreter to manage its firewall
:: You should also be aware that Microsoft, as the firewall and the OS are propreitary, may have a hidden rule
:: within the code that will interrupt or override these connection blocks.
:: It is much preferred you use almost any other type of firewall or packet blocking/filtering solution
::Some say that microsoft ignores telemetry server blocking via hosts file as well.
::TL;DR use pi hole for blocking microsoft telemetry just to be safe, but the ublock ad list in the preconfig works fine.

::If this file was flagged a security risk, know that this is why: https://www.bleepingcomputer.com/news/microsoft/windows-10-hosts-file-blocking-telemetry-is-now-flagged-as-a-risk/

::NOTE: This script ASSUMES your registry key:
::HKEY_LOCAL_MACHINES\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\DataBasePath
::is set to
::%SystemRoot%\System32\drivers\etc
::the file that will be edited is %SystemRoot%\System32\drivers\etc
::by default %SystemRoot% is C:\Windows

::choice /y yn /n /m "heres a choice (y/n)"
@echo off
ver
echo This script has a preconfigured domain/address blocking, and/or you can add your own (this will edit hosts file).
echo Reminder, This script requires administrator to run.

REM Creating a Newline variable (the two blank lines are required!) here in case I use it
set NLM=^
set NL=^^^%NLM%%NLM%^%NLM%%NLM%
goto main
:main
cls
echo Input options are as follows:
echo.
echo 1 - Use preconfiguration
echo.
echo 2 - Add a domain or address to block
echo.
echo 3 - Quit script
echo. 
echo 4 - Read hosts file
echo.
set /P INPUT=5 - CLEAN hosts file
echo.
If /I "%INPUT%" == "1" goto one
If /I "%INPUT%" == "2" goto two
If /I "%INPUT%" == "3" goto three
If /I "%INPUT%" == "4" goto four
if /I "%INPUT%" == "5" goto five
echo Invalid input
echo.
goto main
EXIT /B 0
::do these reg changes with reg export file.reg 
::then run that file	
::TODO: Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection set both AllowTelemetry and MaxTelemetryAllowed to 0.
::TODO: check if Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\ScheduledDiagnostics EnabledExecution can be set to 0.
::TODO: check keys in Computer\HKEY_CURRENT_USER\SOFTWARE\Microsoft\Edge\
::TODO: check if Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\MicrosoftEdge OSIntegrationLevel can be set to 0.
::TODO: Computer\HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Cortana toggle to 0
::TODO: Computer\HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\CloudStore check
::Analyze C:\Windows\DiagTrack\ It reveals some more services and possible reg keys to block within its files
:one
sc delete DiagTrack && sc delete dmwappushservice
echo 0.0.0.0 statsfe2.update.microsoft.com.akadns.net>> %SystemRoot%\System32\drivers\etc\hosts
echo 0.0.0.0 fe2.update.microsoft.com.akadns.net>> %SystemRoot%\System32\drivers\etc\hosts
echo 0.0.0.0 smdn.net>> %SystemRoot%\System32\drivers\etc\hosts
echo 0.0.0.0 survey.watson.microsoft.com>> %SystemRoot%\System32\drivers\etc\hosts
echo 0.0.0.0 view.atdmt.com>> %SystemRoot%\System32\drivers\etc\hosts
echo 0.0.0.0 watson.microsoft.com>> %SystemRoot%\System32\drivers\etc\hosts
echo 0.0.0.0 watson.ppe.telemetry.microsoft.com>> %SystemRoot%\System32\drivers\etc\hosts
echo 0.0.0.0 vortex.data.microsoft.com>> %SystemRoot%\System32\drivers\etc\hosts
echo 0.0.0.0 vortex-win.data.microsoft.com>> %SystemRoot%\System32\drivers\etc\hosts
echo 0.0.0.0 telecommand.telemetry.microsoft.com>> %SystemRoot%\System32\drivers\etc\hosts
echo 0.0.0.0 telecommand.telemetry.microsoft.com.nsatc.net>> %SystemRoot%\System32\drivers\etc\hosts
echo 0.0.0.0 oca.telemetry.microsoft.com>> %SystemRoot%\System32\drivers\etc\hosts
echo 0.0.0.0 sqm.telemetry.microsoft.com>> %SystemRoot%\System32\drivers\etc\hosts
echo 0.0.0.0 sqm.telemetry.microsoft.com.nsatc.net>> %SystemRoot%\System32\drivers\etc\hosts
echo 0.0.0.0 watson.telemetry.microsoft.com>> %SystemRoot%\System32\drivers\etc\hosts
echo 0.0.0.0 watson.telemetry.microsoft.com.nsatc.net>> %SystemRoot%\System32\drivers\etc\hosts
echo 0.0.0.0 redir.metaservices.microsoft.com>> %SystemRoot%\System32\drivers\etc\hosts
echo 0.0.0.0 choice.microsoft.com>> %SystemRoot%\System32\drivers\etc\hosts
echo 0.0.0.0 choice.microsoft.com.nsatc.net>> %SystemRoot%\System32\drivers\etc\hosts
echo 0.0.0.0 wes.df.telemetry.microsoft.com>> %SystemRoot%\System32\drivers\etc\hosts
echo 0.0.0.0 services.wes.df.telemetry.microsoft.com>> %SystemRoot%\System32\drivers\etc\hosts
echo 0.0.0.0 sqm.df.telemetry.microsoft.com>> %SystemRoot%\System32\drivers\etc\hosts
echo 0.0.0.0 telemetry.microsoft.com>> %SystemRoot%\System32\drivers\etc\hosts
echo 0.0.0.0 telemetry.appex.bing.net>> %SystemRoot%\System32\drivers\etc\hosts
echo 0.0.0.0 telemetry.urs.microsoft.com>> %SystemRoot%\System32\drivers\etc\hosts
echo 0.0.0.0 settings-sandbox.data.microsoft.com>> %SystemRoot%\System32\drivers\etc\hosts
echo 0.0.0.0 watson.live.com>> %SystemRoot%\System32\drivers\etc\hosts
echo 0.0.0.0 statsfe2.ws.microsoft.com>> %SystemRoot%\System32\drivers\etc\hosts
echo 0.0.0.0 corpext.msitadfs.glbdns2.microsoft.com>> %SystemRoot%\System32\drivers\etc\hosts
echo 0.0.0.0 compatexchange.cloudapp.net>> %SystemRoot%\System32\drivers\etc\hosts
echo 0.0.0.0 a-0001.a-msedge.net>> %SystemRoot%\System32\drivers\etc\hosts
echo 0.0.0.0 sls.update.microsoft.com.akadns.net>> %SystemRoot%\System32\drivers\etc\hosts
echo 0.0.0.0 diagnostics.support.microsoft.com>> %SystemRoot%\System32\drivers\etc\hosts
echo 0.0.0.0 corp.sts.microsoft.com>> %SystemRoot%\System32\drivers\etc\hosts
echo 0.0.0.0 statsfe1.ws.microsoft.com>> %SystemRoot%\System32\drivers\etc\hosts
echo 0.0.0.0 feedback.windows.com>> %SystemRoot%\System32\drivers\etc\hosts
echo 0.0.0.0 feedback.microsoft-hohm.com>> %SystemRoot%\System32\drivers\etc\hosts
echo 0.0.0.0 feedback.search.microsoft.com>> %SystemRoot%\System32\drivers\etc\hosts
echo 0.0.0.0 rad.msn.com>> %SystemRoot%\System32\drivers\etc\hosts
echo 0.0.0.0 preview.msn.com>> %SystemRoot%\System32\drivers\etc\hosts
echo 0.0.0.0 ad.doubleclick.net>> %SystemRoot%\System32\drivers\etc\hosts
echo 0.0.0.0 ads.msn.com>> %SystemRoot%\System32\drivers\etc\hosts
echo 0.0.0.0 ads1.msads.net>> %SystemRoot%\System32\drivers\etc\hosts
echo 0.0.0.0 ads1.msn.com>> %SystemRoot%\System32\drivers\etc\hosts
echo 0.0.0.0 a.ads1.msn.com>> %SystemRoot%\System32\drivers\etc\hosts
echo 0.0.0.0 a.ads2.msn.com>> %SystemRoot%\System32\drivers\etc\hosts
echo 0.0.0.0 adnexus.net>> %SystemRoot%\System32\drivers\etc\hosts
echo 0.0.0.0 adnxs.com>> %SystemRoot%\System32\drivers\etc\hosts
echo 0.0.0.0 az361816.vo.msecnd.net>> %SystemRoot%\System32\drivers\etc\hosts
echo 0.0.0.0 az512334.vo.msecnd.net>> %SystemRoot%\System32\drivers\etc\hosts
echo 0.0.0.0 ssw.live.com>> %SystemRoot%\System32\drivers\etc\hosts
echo 0.0.0.0 ca.telemetry.microsoft.com>> %SystemRoot%\System32\drivers\etc\hosts
echo 0.0.0.0 i1.services.social.microsoft.com>> %SystemRoot%\System32\drivers\etc\hosts
echo 0.0.0.0 df.telemetry.microsoft.com>> %SystemRoot%\System32\drivers\etc\hosts
echo 0.0.0.0 reports.wes.df.telemetry.microsoft.com>> %SystemRoot%\System32\drivers\etc\hosts
echo 0.0.0.0 cs1.wpc.v0cdn.net>> %SystemRoot%\System32\drivers\etc\hosts
echo 0.0.0.0 vortex-sandbox.data.microsoft.com>> %SystemRoot%\System32\drivers\etc\hosts
echo 0.0.0.0 oca.telemetry.microsoft.com.nsatc.net>> %SystemRoot%\System32\drivers\etc\hosts
echo 0.0.0.0 pre.footprintpredict.com>> %SystemRoot%\System32\drivers\etc\hosts
echo 0.0.0.0 spynet2.microsoft.com>> %SystemRoot%\System32\drivers\etc\hosts
echo 0.0.0.0 spynetalt.microsoft.com>> %SystemRoot%\System32\drivers\etc\hosts
echo 0.0.0.0 fe3.delivery.dsp.mp.microsoft.com.nsatc.net>> %SystemRoot%\System32\drivers\etc\hosts
echo 0.0.0.0 cache.datamart.windows.com>> %SystemRoot%\System32\drivers\etc\hosts
echo 0.0.0.0 db3wns2011111.wns.windows.com>> %SystemRoot%\System32\drivers\etc\hosts
echo 0.0.0.0 settings-win.data.microsoft.com>> %SystemRoot%\System32\drivers\etc\hosts
echo 0.0.0.0 v10.vortex-win.data.microsoft.com>> %SystemRoot%\System32\drivers\etc\hosts
echo 0.0.0.0 win10.ipv6.microsoft.com>> %SystemRoot%\System32\drivers\etc\hosts
echo 0.0.0.0 ca.telemetry.microsoft.com>> %SystemRoot%\System32\drivers\etc\hosts
echo 0.0.0.0 i1.services.social.microsoft.com.nsatc.net>> %SystemRoot%\System32\drivers\etc\hosts
echo 0.0.0.0 msnbot-207-46-194-33.search.msn.com>> %SystemRoot%\System32\drivers\etc\hosts
echo 0.0.0.0 settings.data.microsoft.com>> %SystemRoot%\System32\drivers\etc\hosts
echo 0.0.0.0 telecommand.telemetry.microsoft.com.nsatc.net >> %SystemRoot%\System32\drivers\etc\hosts
:: Above servers are from https://github.com/StevenBlack/hosts/issues/154#issuecomment-236422378 but are likely outdated by now

::These servers were found by ApateDNS on an offline w10 vm
echo 0.0.0.0 ctldl.windowsupdate.com >> %SystemRoot%\System32\drivers\etc\hosts
echo 0.0.0.0 slscr.update.microsoft.com >> %SystemRoot%\System32\drivers\etc\hosts

REM HERE ARE ALL THE SERVERS FROM UBLOCK ORIGINS FILTER ADDED TO HOSTS FILE (~3500 servers, non-microsoft)
curl https://raw.githubusercontent.com/gunawannet1/adblock/master/Peter%20Lowe%E2%80%99s%20Ad%20and%20tracking%20server%20list >> %SystemRoot%\System32\drivers\etc\hosts

REM More servers found to be ms telemetry (~467) posted on my github. I originally found these in a reddit comment ages ago. I just formatted them and gave them the prefix "0.0.0.0 "
curl https://raw.githubusercontent.com/InquireWithin/resources/main/ms_telemetry_list.txt >> %SystemRoot%\System32\drivers\etc\hosts

REM Here's another great anti-telemetry and anti-spyware script, written by alchemy1 (https://github.com/alchemy1/Win.10-SpyWare-Bloat-Telemetry-Remove/blob/master/RemoveW10Bloat.bat.txt)
REM Though its nearly half a decade old, It will help with legacy spyware implementations that microsoft hasnt hidden further within the OS since
curl https://raw.githubusercontent.com/alchemy1/Win.10-SpyWare-Bloat-Telemetry-Remove/master/RemoveW10Bloat.bat.txt > C:\temp\remw10bloat.bat
echo @ECHO OFF >> C:\temp\remw10bloat.bat
type C:\temp\remw10bloat_COPY.bat >> C:\temp\remw10bloat.bat
del C:\temp\remw10bloat_COPY.bat
ren C:\temp\remw10bloat.bat C:\temp\remw10bloat_COPY.bat	
call C:\temp\remw10bloat.bat
:: Not ready to implement yet
REM Using Windows10Debloater for additional bloat removal (https://github.com/Sycnex/Windows10Debloater)
REM this script uses the silent version (Windows10Debloater.ps1)
REM curl https://raw.githubusercontent.com/Sycnex/Windows10Debloater/master/Windows10Debloater.ps1 > C:\temp\Windows10Debloater.ps1
REM start powershell -noexit -command "Set-ExecutionPolicy Unrestricted -Force && 
ipconfig /flushdns
goto main
exit /b 0

:two
echo any domain or address placed here will be appended to the hosts file AS IS (unless blank or "main")
set /P inp=Enter line to append to hosts file:
If /I "%inp%"=="" exit /b && goto two
If /I "%inp%"=="main" exit /b && goto main
echo %inp% >> %SystemRoot%\System32\drivers\etc\hosts
ipconfig /flushdns
goto main
exit /b 0

:three
::quit script
goto:eof
exit
exit /b 0

:four
::read from hosts
for /F "tokens=*" %%A in (%SystemRoot%\System32\drivers\etc\hosts) do (
  echo %%A
  )
goto main
exit /b 0

:five
REM you can do this in powershell with Clear-Content as well
;echo if this fails, ensure that the file isnt being used by another process (notepad, etc)
break>%SystemRoot%\System32\drivers\etc\hosts
goto main
exit /b 0
