@echo off
rem ## Memory Processing Script

rem ## Constants
set VOLATILITY_HOME=".\volatility-2.3Alpha"

rem ## unix style with file:// schema prefix
set VOLATILITY_LOCATION=file://./memdump.bin

rem ## windows style
set VOLATILITY_OUTPUT_PATH=.

rem ## KLUDGE ##
C:
cd %VOLATILITY_HOME%

rem ## If blank, exit
if "%1" == "" goto USAGE
rem ## if "info" display image info
if "%1" == "info" goto IMAGEINFO
if "%1" == "imageinfo" goto IMAGEINFO
rem ## otherwise assume we got the desired profile name
set VOLATILITY_PROFILE=%1
goto PROCESSING

:USAGE
echo Please run this as...
echo %0 info
echo To display the imageinfo, and then pass the Profile as an argument to perform processing
echo . 
echo Example:
echo %0 WinXPSP3x86
echo .
goto END


:IMAGEINFO
set VOLATILITY_PROFILE=
python vol.py --output-file="%VOLATILITY_OUTPUT_PATH%\imageinfo.txt" imageinfo
type "%VOLATILITY_OUTPUT_PATH%\imageinfo.txt"

goto END


:PROCESSING
FOR %%M IN (connections connscan sockets consoles cmdscan sessions handles mutantscan getsids hivelist userassist pslist psscan pstree psxview svcscan) DO (python vol.py --output-file="%VOLATILITY_OUTPUT_PATH%\%%M.txt" %%M)


:END