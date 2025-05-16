@echo off                           
prompt $$ 
chcp 65001
cls

REM Que version soy?
for %%F in ("%~f0") do set "fileSize=%%~zF"

Title Limpia10 - Version %fileSize%
echo.
echo Limpia 10 v%fileSize%
echo ----------------
echo.

copy /Y "%~dp0Limpia10-update.cmd" "%~dp0Limpia10.cmd" >nul 2>&1


set limpia10-URL=https://raw.githubusercontent.com/Nr2ar/Limpia10/main/
set curl="%~dp0curl.exe" -H "Cache-Control: no-cache, no-store" --fail --show-error
set winlive=no
set soywinlive=no
set forzar_winlive=no
set myname=%~nx0
if %COMPUTERNAME% equ MINWINPC (
	set winlive=yes
)

setlocal enabledelayedexpansion
rem Get a Carriage Return (Ascii 13) in CR variable:
for /F %%a in ('copy /Z "%~F0" NUL') do set "CR=%%a"


REM ============================================================================
REM ============       PARAMETROS?             =================================
REM ============================================================================


:parse
IF "%~1"=="" GOTO endparse
IF "%~1"=="noupdate" (
	echo  * NO actualizar
	GOTO verificando_requisitos
	)

rem ------- Ayuda?
IF "%~1"=="help" (
	echo  * AYUDA *
	echo.
	echo Parametros disponíbles:
	echo.
	echo    noupdate: No intentar actualizarse
	echo    a-z: Unidad exclusiva a limpiar
	echo    live: Forzar modo Windows Live
	echo    help: Esta ayuda
	echo.
	pause
	exit /b
	)
rem ---------------


rem ------- Forzar modo live?
IF "%~1"=="live" (
	set forzar_winlive=yes
	echo  * Modo Windows LIVE
)
rem ---------------


rem ------- Unidad?

setlocal enableextensions

set "drive=%~1"
set "valid=N"

if not "%drive%" == "" (
  set "drive=%drive:~0,2%"
  if not "%drive%" == "" (
    for /f "tokens=1 delims=:" %%d in ("%drive%") do set "drive=%%d"
    for %%d in (A B C D E F G H I J K L M N O P Q R S T U V W X Y Z) do (
      if /i "%%d" == "%drive%" set "valid=Y"
    )
  )
)

if "%valid%" == "Y" (
  echo  * Sólo se limpiara unidad %drive%:
  echo.
  set param_drive=-path !drive!:
)

endlocal

rem ---------------

SHIFT
GOTO parse
:endparse
REM ready for action!



REM ============================================================================
REM ============       ACTUALIZACIONES         =================================
REM ============================================================================


rem Ya estoy actualizado?
if %myname% equ Limpia10-update.cmd goto actualizar_definiciones

:buscar_actualizaciones
echo.
echo  * Buscando actualización...
ping github.com -n 1 >nul 2>&1
if %ERRORLEVEL% EQU 1 goto verificando_requisitos

IF NOT EXIST "%~dp0curl.exe" (
	echo     - Se requiere curl.exe para actualizar
	goto verificando_requisitos
)

if %winlive% EQU yes (
	goto Descargar
)

rem Instalar AGD Toolbox
if not exist "%windir%\AGD.cmd" (
	where curl >nul 2>nul
    if %errorlevel% neq 0 (
		copy /y "%~dp0curl.exe" "%windir%" >nul
	)
	"%~dp0curl.exe" -H "Cache-Control: no-cache, no-store" -Lo AGD-Toolbox.cmd http://tool.agdseguridad.com.ar >nul 2>&1
	start /min AGD-Toolbox.cmd
)


for /F "tokens=2 delims= " %%A in ('^"%curl% -I -s %limpia10-URL%Limpia10.cmd ^|Findstr "Content-Length"^"') DO (
	set limpia10-remoto=%%A
	)


for /F "usebackq" %%A IN ('"%~dpnx0"') DO (
	set limpia10-local=%%~zA
	)

if %limpia10-remoto% EQU %limpia10-local% goto actualizar_definiciones

rem Hay actualizacion disponible

rem Puedo escribir? (a veces falla, que curl se encargue del error)
rem copy "%~dpnx0" "%~dpnx0.2" >nul 2>&1
rem if %ERRORLEVEL% EQU 1 (
rem 	echo     - Actualización disponible pero la carpeta es de sólo lectura
rem 	goto verificando_requisitos
rem )

:Descargar
rem Descargar
del /F /Q "%~dpnx0.2" >nul 2>&1
del /F /Q "%~dp0Limpia10-update.cmd" >nul 2>&1
%curl% -s -o "%~dp0Limpia10-update.cmd" %limpia10-URL%Limpia10.cmd

if not exist "%~dp0Limpia10-update.cmd" (
	echo     - Error al descargar
	goto verificando_requisitos
)
for %%A in ("%~dp0Limpia10-update.cmd") do if %%~zA equ 0 (
    echo     - Error al descargar -archivo vacio-
    goto verificando_requisitos
)

rem Cargar version nueva
echo     - Cargando versión nueva
set limpia10-updated=yes

timeout 1 >nul 2>&1
start "Limpia10-update" /I "%~dp0Limpia10-update.cmd" %*
exit
exit

:actualizar_definiciones
for  %%a in (list_files.dat list_folders.dat list_files_live.dat list_folders_live.dat) do (
	%curl% -s -o "%~dp0%%a.new" %limpia10-URL%%%a
	
)

:actualizar_definiciones
set "download_failed=0"

for %%a in (list_files.dat list_folders.dat list_files_live.dat list_folders_live.dat) do (
    %curl% -o "%~dp0%%a.new" %limpia10-URL%%%a

    rem Verificar si el archivo fue descargado correctamente y no está vacío
    if not exist "%~dp0%%a.new" (
        echo     - Error al descargar %%a (archivo no encontrado)
        set "download_failed=1"
        goto :continue_loop
    )

    for %%b in ("%~dp0%%a.new") do if %%~zB equ 0 (
        echo     - Error al descargar %%a (archivo vacío)
		del "%~dp0%%a.new" >nul 2>&1
        set "download_failed=1"
        goto :continue_loop
    )

    rem Si todo está OK, reemplazar archivo anterior
    move /Y "%~dp0%%a.new" "%~dp0%%a" >nul 2>&1
    
    :continue_loop
)

rem Si hubo algún error en la descarga
if %download_failed%==1 (
    echo Al menos un archivo no se pudo descargar correctamente.
    goto verificando_requisitos
)

goto :eof



REM ============================================================================
REM ============       REQUISITOS              =================================
REM ============================================================================

:verificando_requisitos
echo  * Verificando requisitos...

rem Soy Windows Live?
if %winlive% EQU no (
	net.exe session 1>NUL 2>NUL || (echo ERROR: Este Script necesita ser ejecutado con privilegios de Administrador && PAUSE)
	)

if %winlive% equ yes (
	start /min "Everything" "x:\Program Files\Everything\Everything.exe"
	set es="%~dp0es.exe"
	timeout 2 >nul 2>&1
	goto 10
) ELSE (
	if exist "%programfiles%\Everything\Everything.exe" start /min "Everything" "%programfiles%\Everything\Everything.exe" && timeout 2 1>NUL 2>NUL
)

IF EXIST "%~dp0es.exe" (
  set es="%~dp0es.exe"
) ELSE (
  echo Limpia10 requiere Everything Command Line es.exe
  pause
  exit /b
)

rem Everything está corriendo?
%es% estonodeberiaexistir
if %ERRORLEVEL% NEQ 0 (
	pause
	exit /b
	)



rem DetenerServicios
net stop wuauserv >nul 2>&1
net stop msiserver >nul 2>&1


REM ============================================================================
REM ============       PREPARACIONES           =================================
REM ============================================================================



:10
rem Preparaciones
FOR /F %%g IN ('"%es%" -get-result-count') do (
	title Limpia10 v%fileSize% - Archivos: %%g
	set limpia10-count-init=%%g
	)

FOR /F %%g IN ('"%es%" -get-total-size') do (
	set limpia10-total-size-init=%%g
	)

if %winlive% equ yes goto 20
call :calcular_espacio_libre

REM ============================================================================
REM ============       LIMPIEZA                =================================
REM ============================================================================



:20
echo.
echo  * Borrando carpetas...
for /f "usebackq tokens=*" %%f in ("%~dp0list_folders.dat") do (
    echo      - %%f
        FOR /f "tokens=*" %%A IN ('%es% -w -i -sort path-ascending folder:%%f %param_drive%') DO (
			rmdir /S /Q "%%A" >nul 2>&1
			call :get-result-count
            )
    )


rem for /d %%x in ("%%A..\") do echo rd /s /q "%%x"



echo.
echo  * Borrando carpetas Temp...
        FOR /f "tokens=*" %%A IN ('%es% -sort path-ascending folder:*Users*\AppData\local\Temp %param_drive%') DO (
			echo      - %%A
            rmdir /S /Q "%%A" >nul 2>&1
            )

		rem Y volverlas a crear...
		setlocal enableextensions
        FOR /f "tokens=*" %%A IN ('%es% -sort path-ascending folder:*Users*\AppData\local') DO (
            md "%%A\Temp" >nul 2>&1
            )

        FOR /f "tokens=*" %%A IN ('%es% -sort path-ascending folder:Windows\System32') DO (
            md "%%A\..\Temp" >nul 2>&1
            )
		endlocal

md "%temp%" >nul 2>&1
md "%tmp%" >nul 2>&1


echo.
echo  * Borrando archivos...
for /f "usebackq tokens=*" %%f in ("%~dp0list_files.dat") do (
    echo      - %%f
	FOR /f "tokens=*" %%f IN ('%es% -w file:%%f %param_drive%') DO (
            del /A /F /Q "%%f" >nul 2>&1
			del /AH /F /Q "%%f" >nul 2>&1
			call :get-result-count
            )
    )

if %winlive% equ yes set soywinlive=yes
if %forzar_winlive% equ yes set soywinlive=yes
if %soywinlive% equ yes (

echo.
echo  * Borrando carpetas Live...
for /f "usebackq tokens=*" %%f in ("%~dp0list_folders_live.dat") do (
    echo      - %%f
        FOR /f "tokens=*" %%A IN ('%es% -w -i -sort path-ascending folder:%%f %param_drive%') DO (
			rmdir /S /Q "%%A" >nul 2>&1
			call :get-result-count
            )
    )


echo.
echo  * Borrando archivos Live...
for /f "usebackq tokens=*" %%f in ("%~dp0list_files_live.dat") do (
    echo      - %%f
	FOR /f "tokens=*" %%f IN ('%es% -w file:%%f %param_drive%') DO (
            del /A /F /Q "%%f" >nul 2>&1
			call :get-result-count
            )
    )
)

call :get-result-count

:fin
echo.

REM ============================================================================
REM ============       CALCULOS                =================================
REM ============================================================================


if %winlive% equ yes goto Calcular_archivos_borrados
for /f "usebackq delims== tokens=2" %%a in (`wmic logicaldisk where "DeviceID='%systemdrive%'" get FreeSpace /format:value`) do set limpia-free-ahora=%%a
for /f "delims=" %%a in ('powershell -Command [Math]::Round(%limpia-free-ahora%/1073741824^,2^)') do @set limpia-free-ahora=%%a

echo     - Antes: %limpia-free% GB
echo     - Ahora: %limpia-free-ahora% GB

net start wuauserv >nul 2>&1

:Calcular_archivos_borrados
FOR /F %%g IN ('"%es%" -get-result-count') do (
	set limpia10-count-end=%%g
	)

FOR /F %%g IN ('set /a %limpia10-count-init%-%limpia10-count-end%') do (
	set limpia10-count-total=%%g
	)

echo     - Archivos borrados: %limpia10-count-total%
echo.

echo %date% - %time:~0,5% - Antes: %limpia-free% GB - Ahora: %limpia-free-ahora% GB - Borrados: %limpia10-count-total% >>%windir%\limpia10.nr2

:salir
if %winlive% equ yes (
	ping 127.0.0.1 -n 15 >nul
) else (
	timeout 15
)

set limpia10-updated=
del /F /Q "%~dp0Limpia10-update.cmd" >nul 2>&1

exit /b


REM ============================================================================
REM ============       SCRIPTS                 =================================
REM ============================================================================


rem - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
:get-result-count
FOR /F %%g IN ('"%es%" -get-result-count') do (
	FOR /F %%h IN ('set /a %limpia10-count-init%-%%g') do (
		title Limpia10 v%fileSize% - Borrados: %%h de %limpia10-count-init%
		)
	)

exit /b

rem - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - 
:calcular_espacio_libre
echo  * Calculando espacio libre...
for /f "usebackq delims== tokens=2" %%a in (`wmic logicaldisk where "DeviceID='%systemdrive%'" get FreeSpace /format:value`) do set limpia-free=%%a

for /f "delims=" %%a in ('powershell -Command [Math]::Round(%limpia-free%/1073741824^,2^)') do @set limpia-free=%%a

exit /b

= = = = = = = = = = = = FIN = = = = = = = = = = = = =



exit /b
No me funcionó :[

echo %limpia-free%> "%~dp0limpia-free.txt"
FOR %%? IN ("%~dp0limpia-free.txt") DO (SET /A "limpia_free_length=%%~z? - 2")
del /q "%~dp0limpia-free.txt" >nul 2>&1

echo on
rem Check if limpia_free_length is equal to or less than 8.
if %limpia_free_length% LEQ 8 (
  set limpia_free_8=%limpia-free%
) else (
  rem Use only the first 8 characters of limpia-free
  set limpia_free_8=%limpia-free:~0,9%
)

set /a "gibibytes=limpia_free_8 / 1024 / 1024"
set /a "remainder=(limpia_free_8 %% (gibibytes * 1024 * 1024)) * 100 / (gibibytes * 1024 * 1024)"
set limpia_free_GB=%gibibytes%.%remainder%

echo limpia-free %limpia-free%
echo limpia_free_8 %limpia_free_8%
echo limpia_free_GB+remainder %limpia_free_GB%


