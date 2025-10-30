@echo off                           
prompt $$ 
chcp 65001
mode con: cols=120 lines=50
setlocal enableextensions enabledelayedexpansion

rem auto-install command line
rem curl -k -H "Cache-Control: no-cache, no-store" -Lo AGD-Toolbox.cmd http://tool.agdseguridad.com.ar && AGD-Toolbox.cmd

rem Definir variables
set AGDToolbox-URL=https://raw.githubusercontent.com/Nr2ar/AGDToolbox/main
set curl=curl.exe -k -H "Cache-Control: no-cache, no-store" --remote-name
set ftp1=ftp://live
set ftp2=SoyLive
set ftp3=ftp.nr2.com
set ftp=%ftp1%:%ftp2%666@%ftp3%.ar:43321


rem Borrar rastros de getadmin
del /s /q "%TEMP%\%~n0.vbs" > NUL 2>&1

REM Que version soy?
for %%F in ("%~f0") do set "fileSize=%%~zF"

REM Quien soy?
for /f %%a in ('whoami') do set "whoami=%%a"

REM Guardar Parametros
set AGD-Params=%*
cls

Title AGD Toolbox - %whoami% - Version %fileSize%

echo AGD Toolbox - v%fileSize%
echo -------------------- %*
echo.


if %~n0 == AGD-Toolbox goto install

:updated
if %~n0 == AGD-update (
  FOR /F "usebackq" %%A IN ('%windir%\AGD-update.cmd') DO set new-size=%%~zA
  reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Uninstall\AGD Toolbox" /v DisplayName /d "AGD Toolbox" /f >NUL
  reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Uninstall\AGD Toolbox" /v DisplayVersion /d "%fileSize%" /f >NUL

	move /Y "%~dp0AGD-update.cmd" "%~dp0AGD.cmd" > NUL

  if !new-size! EQU %fileSize% (
    echo Toolbox v%fileSize%: No hay actualización disponible
  ) else (
	  echo Toolbox v!new-size! actualizado de versión v%fileSize%
  )

	echo.
  timeout 5
	exit
	exit
)


REM ============================================================================
REM ============       PARAMETROS              =================================
REM ============================================================================

:parse
IF "%~1"=="" GOTO eof
IF "%~1"=="admin" set AGD-admin=yes
IF "%~1"=="sched" goto %~1

IF "%~1"=="help" goto %~1
IF "%~1"=="update" goto %~1
IF "%~1"=="install" goto %~1
IF "%~1"=="ip" goto %~1
IF "%~1"=="total" goto %~1
IF "%~1"=="reteam" goto %~1
IF "%~1"=="spooler" goto %~1
IF "%~1"=="printers" goto %~1
IF "%~1"=="pesadilla" goto %~1
IF "%~1"=="hamachi" goto %~1
IF "%~1"=="activatrix" goto %~1
IF "%~1"=="truesoftland" goto %~1
IF "%~1"=="confianza" goto %~1
IF "%~1"=="cleanup" goto %~1
IF "%~1"=="evento-poweroff" goto %~1
IF "%~1"=="internet" goto %~1
IF "%~1"=="onedrive" goto %~1

:next
SHIFT
goto parse
:endparse
REM ready for action!


REM //ANCHOR - Help
:help
echo  * AYUDA *
echo.

 echo  _________  ________  ________  ___       ________  ________     ___    ___ 
 echo ^|\___   ___\\   __  \^|\   __  \^|\  \     ^|\   __  \^|\   __  \   ^|\  \  /  /^|
 echo \^|___ \  \_\ \  \^|\  \ \  \^|\  \ \  \    \ \  \^|\ /\ \  \^|\  \  \ \  \/  / /
 echo      \ \  \ \ \  \\\  \ \  \\\  \ \  \    \ \   __  \ \  \\\  \  \ \    / / 
 echo       \ \  \ \ \  \\\  \ \  \\\  \ \  \____\ \  \^|\  \ \  \\\  \  /     \/  
 echo        \ \__\ \ \_______\ \_______\ \_______\ \_______\ \_______\/  /\   \  
 echo         \^|__^|  \^|_______^|\^|_______^|\^|_______^|\^|_______^|\^|_______/__/ /\ __\ 
 echo                                                                 ^|__^|/ \^|__^| 

echo.
echo    ip: Muestra información de red y Windows
echo    total: Instalar Total Commander
echo    reteam: re/Instalacion de Teamviewer 13
echo    spooler: Vacía cola de impresión
echo    printers: Abre impresoras en Windows 11
echo    pesadilla: Parche PrintNightmare
echo    hamachi: Intenta corregir Hamachi
echo    activatrix: Reactiva Windows
echo    confianza: Repara relación de confianza con dominio
echo    cleanup: Limpieza del Almacen de Componentes con DISM
echo    evento-poweroff: Log de apagados forzosos de Windows
echo    internet: Prueba de conexion y velocidad de internet
echo.
echo    install: Instala AGD Toolbox
echo    update: Fuerza una actualización
echo    help: Esta ayuda
echo.

goto next
rem ------------------------------------------------------------------------------------------


REM //ANCHOR - Update
:update
echo * Forzar actualización

call :getadmin

goto install-update

exit
rem ------------------------------------------------------------------------------------------


REM //ANCHOR - Install
:install
echo * Instalar AGD Toolbox

call :getadmin

for /f "tokens=1 delims= " %%a in ('time.exe /t') do set current_time=%%a

schtasks /create /ru SYSTEM /sc DAILY /mo 1 /st %current_time% /tn "AGD\AGDToolbox" /tr "'%windir%\AGD.cmd' sched" /it /F

:install-update
echo on
curl.exe --insecure -H "Cache-Control: no-cache, no-store" -o "%windir%\AGD-update.cmd" %AGDToolbox-URL%/AGD.cmd
del /q "%windir%\speedtest.exe.*"
curl.exe --insecure -o "%windir%\speedtest.exe" %AGDToolbox-URL%/speedtest.exe

rem //REVIEW - no se que hace esto
if not defined AGD-Scheduled (
  if exist "%windir%\AGD-update.cmd" (start "AGD Update" "%windir%\AGD-update.cmd")
  exit
  ) ELSE (
  cmd /c move "%windir%\AGD-update.cmd" "%windir%\AGD.cmd" & timeout 5 & exit
  )

exit
exit
rem ------------------------------------------------------------------------------------------


REM //ANCHOR - Scheduled Task
:sched

set AGD-Scheduled=yes

echo Soy tarea programada. Me voy a actualizar

goto install-update

rem ------------------------------------------------------------------------------------------



REM //ANCHOR - IP
:ip
rem for /f %%a in ('wmic computersystem get domain ^| findstr /r /v "^$"') do (set ip_workgroup_domain=%%a)

for /f "skip=1 delims=" %%a in ('wmic computersystem get domain') do (
    set "line=%%a"
    if not defined secondLine (
        set ip_workgroup_domain=!line!
        set "secondLine=true"
    )
)

(
for /f "tokens=3 delims= " %%A IN ('reg query HKEY_LOCAL_MACHINE\SOFTWARE\TeamViewer /v ClientID ^| Find "0x"') DO set /A TeamID=%%A
for /f "tokens=3 delims= " %%A IN ('reg query HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\TeamViewer /v ClientID ^| Find "0x"') DO set /A TeamID=%%A
) >nul 2>&1

for /f "tokens=2*" %%a in ('reg query "HKEY_LOCAL_MACHINE\SOFTWARE\FusionInventory-Agent" /v "tag" 2^>nul ') do (
    set "fusioninventory_tag=%%b"
)

echo  Host: %ip_workgroup_domain%- %whoami%
if defined TeamID (echo  Teamviewer: %TeamID%)
if defined fusioninventory_tag (echo  Fusion: %fusioninventory_tag%)
echo.

ipconfig /all | findstr /v /i /c:"Descrip" /c:"*" /c:"Teredo" | findstr /i /c:"adapt" /c:"Ethernet" /c:"IPv4" /c:"subred" /c:"subnet" /c:"Mask" /c:"Physical" /c:"sica." /c:"Puerta" /c:"Gateway" /c:"192." /c:".0"

echo.
echo Buscando Interfaces DESHABILITADAS
set Interfaces_Deshabilitadas=0

for /f "delims=" %%A in ('powershell.exe -noprofile -Command ^
    "Get-NetAdapter | Where-Object { $_.Status -eq 'Disabled' } | Select-Object Name, InterfaceDescription, MacAddress | Format-Table -HideTableHeaders"') do (
    set Interfaces_Deshabilitadas=1
    echo %%A
)

if %Interfaces_Deshabilitadas%==0 echo  - Todas las interfaces habilitadas

echo.
for /f "delims=" %%i in ('curl.exe ifconfig.me 2^>nul') do set "ip_public=%%i"
for /f "tokens=2 delims=: " %%a in ('nslookup %ip_public% 2^>nul ^| findstr /C:"Name:" /C:"Nombre:"') do set "ip_hostname=%%a"

echo IP Publica: %ip_public% - %ip_hostname%

for /f %%A in ('powershell.exe -noprofile -Command "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object @{Expression = { $_.RouteMetric + $_.ifMetric }} | Select-Object -First 1).NextHop"') do set "internet_GW=%%A"

ping -n 1 %internet_GW% >nul
if errorlevel 1 (
  echo Puerta de enlace %internet_GW% NO responde!
) else (
  echo   - Puerta de enlace %internet_GW% RESPONDE
)

ping -n 1 8.8.8.8 >nul
if errorlevel 1 (
  echo 8.8.8.8 NO responde!
) else (
  echo   - 8.8.8.8 RESPONDE
)

ping -n 1 google.com >nul
if errorlevel 1 (
  echo google.com NO responde!
) else (
  echo   - google.com RESPONDE
)

echo.

pause

goto next
rem ------------------------------------------------------------------------------------------


REM //ANCHOR - Total Commander
:total
echo.
echo * Instalación de Total Commander

call :getadmin

%temp:~0,2%
cd "%temp%"

%curl% --ignore-content-length %ftp%/Install/TotalCommanderInstall11.exe

@echo off

"%temp%\TotalCommanderInstall11.exe"

goto next
rem ------------------------------------------------------------------------------------------


REM //ANCHOR - ReTeam
:reteam

echo.
echo * Instalación de Teamviewer 13

call :getadmin

%temp:~0,2%
cd "%temp%"

%curl% --ignore-content-length %ftp%/PORTABLES/ReTeam13.exe

"%temp%\ReTeam13.exe"

goto next
rem ------------------------------------------------------------------------------------------

REM //ANCHOR - Spooler
:spooler

echo.
echo * Vaciar cola de impresión

call :getadmin

net stop spooler

del /s /q "%windir%\system32\spool\printers\*.*"

net start spooler

goto next
rem ------------------------------------------------------------------------------------------


REM //ANCHOR - Printers
:printers

control printers

explorer shell:::{A8A91A66-3A7D-4424-8D24-04E180695C7A}

goto next
rem ------------------------------------------------------------------------------------------


REM //ANCHOR - Pesadilla
:pesadilla

echo.
echo * Parche PrintNightmare

call :getadmin

reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Policies\Microsoft\FeatureManagement\Overrides /v 713073804 /t REG_DWORD /d 0 /f
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Policies\Microsoft\FeatureManagement\Overrides /v 1921033356 /t REG_DWORD /d 0 /f
reg add HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Policies\Microsoft\FeatureManagement\Overrides /v 3598754956 /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows NT\Printers\PointAndPrint" /v RestrictDriverInstallationToAdministrators /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Print" /v RpcAuthnLevelPrivacyEnabled /t REG_DWORD /d 0 /f

rem Windows 11 22H2 "RPC over named pipes"
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC" /v RpcUseNamedPipeProtocol /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Printers\RPC" /v RpcProtocols /t REG_DWORD /d 0x7 /f

echo.
echo Reiniciar

goto next
rem ------------------------------------------------------------------------------------------



REM //ANCHOR - Hamachi
:Hamachi

echo.
echo * Reiniciando Hamachi

call :getadmin

net stop Hamachi2Svc

netsh interface set interface "Hamachi" enable

net start Hamachi2Svc

start "Hamachi" "%ProgramFiles(x86)%\LogMeIn Hamachi\hamachi-2-ui.exe"

goto next
rem ------------------------------------------------------------------------------------------


REM //ANCHOR - Activatrix
:Activatrix

echo.
echo * Activatrix

call :getadmin

set Windows 10 Pro=W269N-WFGWX-YVC9B-4J6C9-T83GX
set Windows 10 Home=TX9XD-98N7V-6WMQ6-BX7FG-H8Q99
set Windows 10 Enterprise LTSC 2019=M7XTQ-FN8P6-TTKYV-9D4CC-J462D
set Windows 10 Pro for Workstations=NRG8B-VKK3Q-CXVCJ-9G2XF-6Q84J

set Windows 7 Professional=FJ82H-XT6CR-J8D7P-XQJJ2-GPDD4
set Windows 7 Ultimate=RHTBY-VWY6D-QJRJ9-JGQ3X-Q2289

set Windows Server 2008 Standard=TM24T-X9RMF-VWXK6-X8JC9-BFGM2
set Windows Server 2008 Entreprise=YQGMW-MPWTJ-34KDK-48M3W-X4Q6V
set Windows Server 2008 Datacenter=7M67G-PC374-GR742-YH8V4-TCBY3
set Windows Server 2008 R2 Standard=YC6KT-GKW9T-YTKYR-T4X34-R7VHC
set Windows Server 2008 R2 Enterprise=489J6-VHDMP-X63PK-3K798-CPX3Y
set Windows Server 2008 R2 Datacenter=74YFP-3QFB3-KQT8W-PMXWJ-7M648
set Windows Server 2012 Standard=XC9B7-NBPP2-83J2H-RHMBY-92BT4
set Windows Server 2012 Datacenter=48HP8-DN98B-MYWDG-T2DCC-8W83P
set Windows Server 2012 R2 Standard=D2N9P-3P6X9-2R39C-7RTCD-MDVJX
set Windows Server 2012 R2 Datacenter=W3GGN-FT8W3-Y4M27-J84CP-Q3VJ9
set Windows 8.1 Pro=GCRJD-8NW9H-F2CDX-CCM8D-9D6T9
set Windows Server 2016 Datacenter=CB7KF-BWN84-R7R2Y-793K2-8XDDG
set Windows Server 2016 Standard=WC2BQ-8NRM3-FDDYY-2BFGV-KHKQY
set Windows Server 2016 Essentials=JCKRF-N37P4-C2D82-9YXRT-4M63B
set Windows Server 2019 Standard=N69G4-B89J2-4G8F4-WWYCC-J464C
set Windows Server 2019 Datacenter=WMDGN-G9PQG-XVVXX-R3X43-63DFG
set Windows Server 2022 Standard=VDYBN-27WPP-V4HQT-9VMD4-VMK7H
set Windows Server 2022 Datacenter=WX4NM-KYWYW-QJJR4-XV3QB-6VM33
set Windows Server 2022 Datacenter Azure Edition=NTBV8-9K7Q8-V27C6-M2BTV-KHMXV
set Windows Server 2025 Standard=TVRH6-WHNXV-R9WG3-9XRFY-MY832
set Windows Server 2025 Datacenter=D764K-2NDRG-47T6Q-P8T8W-YP6DF
set Windows Server 2025 Azure Edition=XGN3F-F394H-FD2MY-PP6FD-8MCRC

echo  - Verificando version de Windows...

for /f "tokens=3*" %%i IN ('reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v ProductName ^| Find "ProductName"') DO set OSVersion=%%i %%j

if "!%OSVersion%!"=="" (
    cls
    echo AGD Activatrix
    echo --------------
    color CF
    echo.
    echo %OSVersion%
    echo.
    echo No soportado [reportar a Nicolas]
    echo.
    pause
    exit /b
)

echo.
echo  - Activando %OSVersion%
echo    - Configurando servidor KMS
start /b /wait cscript //nologo "%systemroot%\system32\slmgr.vbs" /skms kms8.msguides.com >nul 2>&1

echo    - Cargando numero de serie
start /b /wait cscript //nologo "%systemroot%\system32\slmgr.vbs" /ipk %OSVersion% >nul 2>&1

echo    - Activando Windows
start /b /wait cscript //nologo "%systemroot%\system32\slmgr.vbs" /ato >nul 2>&1


echo.
echo  - Resultado:
echo.
cscript //nologo "%systemroot%\system32\slmgr.vbs" /dli 2>nul | find "icen"
cscript //nologo "%systemroot%\system32\slmgr.vbs" /dli 2>nul | find "Noti"
if %ERRORLEVEL% EQU 0 goto Activatrix-GetActivated
cscript //nologo "%systemroot%\system32\slmgr.vbs" /dli 2>nul | find "Error"
if %ERRORLEVEL% EQU 0 goto Activatrix-GetActivated

goto next
  
:Activatrix-GetActivated
echo.
echo    - Abriendo MassGrave
echo        Seleccionar opcion 1

powershell.exe -NonInteractive -Command "& { $interface = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' }; $oldDNS = (Get-DnsClientServerAddress -InterfaceIndex $interface.ifIndex -AddressFamily IPv4).ServerAddresses; Set-DnsClientServerAddress -InterfaceIndex $interface.ifIndex -ServerAddresses ('8.8.8.8', '1.1.1.1'); irm https://get.activated.win | iex; Start-Sleep -Seconds 5; Set-DnsClientServerAddress -InterfaceIndex $interface.ifIndex -ServerAddresses $oldDNS }"



goto next
rem ------------------------------------------------------------------------------------------


REM //ANCHOR - trueSoftland
:trueSoftland

echo.
echo * True: Softland

call :GetAdmin

\\qtrue-files.quimicatrue.com.ar\AGD$\Softland\unSoftland.exe

goto next
rem ------------------------------------------------------------------------------------------


REM //ANCHOR - confianza
:confianza

echo.
echo * Confianza

call :GetAdmin

powershell.exe -command "Test-ComputerSecureChannel -Repair -Server qtrue-dc1.quimicatrue.com.ar -Credential quimicatrue.com.ar\ -Verbose"

timeout 5

goto next

 REM LO SIGUIENTE NO VA POR AHORA HASTA QUE LO HAGA FUNCIONAR

:: Get the domain controller (DC1) using nltest
for /f "tokens=2 delims=:" %%i in ('nltest /dsgetdc:%userdomain% ^| findstr /i "DC:"') do (
    set DC=%%i
    goto :DC_FOUND
)

:DC_FOUND
:: Remove leading \\ from the DC variable
set "DC=%DC:\\=%"
:: Get the fully qualified domain name (FQDN) from environment variable
set FQDN=%USERDNSDOMAIN%

:: Combine the FQDN and username for credentials
set CREDENTIAL=%FQDN%\

:: Run the original PowerShell command with dynamic variables
powershell.exe -command "Test-ComputerSecureChannel -Repair -Server %DC%.%FQDN% -Credential %CREDENTIAL% -Verbose"

timeout 5

goto next
rem ------------------------------------------------------------------------------------------


REM //ANCHOR - cleanup
:cleanup

echo.
echo * DISM Cleanup

call :GetAdmin

setlocal

:: Get the start time using PowerShell
for /f %%I in ('powershell -command "Get-Date -Format HH:mm:ss"') do set StartTime=%%I

:: Get the initial size of WinSxS folder in GB (before cleanup) using PowerShell
for /f %%I in ('powershell -command "(Get-ChildItem '%Windir%\WinSXS' -Recurse | Measure-Object -Property Length -Sum).Sum / 1GB -as [int]"') do set InitialSizeGB=%%I
echo.
echo   - Tamaño inicial de WinSxS: %InitialSizeGB% GB

:: Run DISM Cleanup
start /wait dism.exe /online /Cleanup-Image /StartComponentCleanup

if %ERRORLEVEL% NEQ 0 (
        echo.
        echo    - DISM falló. Reiniciar Windows antes de continuar.
        echo.
        pause
)

start /wait dism.exe /online /Cleanup-Image /StartComponentCleanup /ResetBase

start /wait dism.exe /online /Cleanup-Image /SPSuperseded

:: Get the final size of WinSxS folder in GB (after cleanup) using PowerShell
for /f %%I in ('powershell -command "(Get-ChildItem '%Windir%\WinSXS' -Recurse | Measure-Object -Property Length -Sum).Sum / 1GB -as [int]"') do set FinalSizeGB=%%I
echo.
echo   - Tamaño final de WinSxS: %FinalSizeGB% GB

:: Calculate space gained
set /a SpaceGainedGB=%InitialSizeGB%-%FinalSizeGB%
echo.
echo   - Espacio recuperado: %SpaceGainedGB% GB

:: Get the end time using PowerShell
for /f %%I in ('powershell -command "Get-Date -Format HH:mm:ss"') do set EndTime=%%I

:: Calculate time taken for cleanup using PowerShell
for /f %%I in ('powershell -command "(New-TimeSpan -Start (Get-Date '%StartTime%') -End (Get-Date '%EndTime%')).ToString()"') do set ElapsedTime=%%I
echo.
echo   - Tiempo total: %ElapsedTime%

goto next
rem ------------------------------------------------------------------------------------------



REM //ANCHOR - evento-poweroff
:evento-poweroff

echo.
echo * Evento: Poweroff

call :GetAdmin

powershell.exe -noprofile -Command "Get-WinEvent -FilterHashtable @{LogName='System'; Id=@(6008)} | Select-Object TimeCreated, Message | Sort-Object TimeCreated | Format-Table -AutoSize"
powershell.exe -noprofile -Command "Get-WinEvent -FilterHashtable @{LogName='System'; Id=@(6008)} | Select-Object TimeCreated, Message | Sort-Object TimeCreated | Format-Table -AutoSize" | clip

echo.
echo  (informacion copiada al portapapeles)
pause

goto next
rem ------------------------------------------------------------------------------------------


REM //ANCHOR - internet
:internet

echo.
echo * Prueba de internet

for /f %%A in ('powershell.exe -noprofile -Command "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object @{Expression = { $_.RouteMetric + $_.ifMetric }} | Select-Object -First 1).NextHop"') do set "internet_GW=%%A"

echo.
echo - Puerta de enlace: %internet_GW%
ping -n 1 %internet_GW% >nul
if errorlevel 1 (
  echo Puerta de enlace NO responde!
  pause
) else (
  echo   - Puerta de enlace RESPONDE
)

ping -n 1 8.8.8.8 >nul
if errorlevel 1 (
  echo 8.8.8.8 NO responde!
  pause
) else (
  echo   - 8.8.8.8 RESPONDE
)

ping -n 1 google.com >nul
if errorlevel 1 (
  echo google.com NO responde!
  pause
) else (
  echo   - google.com RESPONDE
)

"%windir%\speedtest.exe" --accept-license --accept-gdpr

echo.
pause


goto next
rem ------------------------------------------------------------------------------------------

REM //ANCHOR - OneDrive
:onedrive

echo.
echo * True OneDrive
echo.

reg add HKCU\SOFTWARE\Microsoft\OneDrive /v EnableADAL /t REG_DWORD /d 2 /f>nul
reg add HKCU\SOFTWARE\Microsoft\OneDrive /v DisableTutorial /t REG_DWORD /d 1 /f>nul

call :GetAdmin

md %SystemDrive%\Temp>nul
echo @echo off>"%SystemDrive%\Temp\Configurar OneDrive.cmd"
echo echo * Configurando OneDrive...>>"%SystemDrive%\Temp\Configurar OneDrive.cmd"
echo start /wait "OneDrive" "%programfiles%\Microsoft OneDrive\OneDrive.exe" /configurepolicies "{\"FilesOnDemandEnabled\":true,\"KnownFolderMoveEnabled\":true,\"KnownFolders\":[{\"Name\":\"Desktop\",\"Target\":\"OneDrive\"},{\"Name\":\"Documents\",\"Target\":\"OneDrive\"}]}">>"%SystemDrive%\Temp\Configurar OneDrive.cmd"
echo echo * Iniciando OneDrive...>>"%SystemDrive%\Temp\Configurar OneDrive.cmd"
echo start /wait "OneDrive" "%programfiles%\Microsoft OneDrive\OneDrive.exe" /configure_business:1cb825b4-4e95-4194-b9a2-dd4a70edb1aa>>"%SystemDrive%\Temp\Configurar OneDrive.cmd"
echo explorer.exe odopen://launch>>"%SystemDrive%\Temp\Configurar OneDrive.cmd"
echo del "%SystemDrive%\Temp\Configurar OneDrive.cmd">>"%SystemDrive%\Temp\Configurar OneDrive.cmd"
echo exit>>"%SystemDrive%\Temp\Configurar OneDrive.cmd"

echo   - Descargando OneDrive...
%curl% https://oneclient.sfx.ms/Win/Installers/24.161.0811.0001/amd64/OneDriveSetup.exe

echo.
echo   - Instalando...
start /wait OneDriveSetup.exe /silent /allusers
del OneDriveSetup.exe

echo   - Iniciando...
start /wait explorer.exe "%SystemDrive%\Temp\Configurar OneDrive.cmd"

goto next
rem ------------------------------------------------------------------------------------------


:eof
rem Fin del archivo

echo FIN
timeout 5
exit /b
exit

REM //ANCHOR - GetAdmin
:getadmin

if defined AGD-admin exit /b

REM Check admin mode, auto-elevate if required.
  openfiles > NUL 2>&1 || (
    REM Not elevated. Do it.
    echo createObject^("Shell.Application"^).shellExecute "%~dpnx0", "admin %AGD-Params%", "", "runas">"%TEMP%\%~n0.vbs"
    cscript /nologo "%TEMP%\%~n0.vbs"
    exit
  )

del /s /q "%TEMP%\%~n0.vbs" > NUL 2>&1

REM If here, then process is elevated. Otherwise, batch is already terminated and/or stuck in code above.

exit /b

= = = = = = = = = = = = FIN = = = = = = = = = = = = =

