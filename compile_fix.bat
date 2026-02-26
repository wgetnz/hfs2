@echo off
set "DCC32=D:\Apps\RS1033\bin\dcc32.exe"
if not exist "%DCC32%" set "DCC32=D:\Apps\RS1033\dcc32.exe"

set "BRCC32=D:\Apps\RS1033\bin\brcc32.exe"
if not exist "%BRCC32%" set "BRCC32=D:\Apps\RS1033\brcc32.exe"

echo Compiling resources...
"%BRCC32%" data.rc
if %errorlevel% neq 0 (
    echo Resource compilation failed!
    exit /b %errorlevel%
)

set "DELPHI_LIB=D:\Apps\RS1033\lib\win32\release"
set "LIBS=Lib\FastMM4;Lib\TRegExpr\src;Lib\ICS8\Source;Lib\ICS8\Source\Include;Lib\JCL\jcl\source\windows;Lib\JCL\jcl\source\common;Lib\JCL\jcl\source\include"
set "SEARCH_PATH=%LIBS%;%DELPHI_LIB%"

echo Compiling project...
"%DCC32%" hfs.dpr -M -Q -TX.exe -E. -I"%SEARCH_PATH%" -U"%SEARCH_PATH%" -R"%SEARCH_PATH%" -O"%SEARCH_PATH%" -NSSystem;System.Win;Winapi;Vcl;Vcl.Imaging;Data;Xml;Web;Soap;Data.Win;Datasnap.Win;Web.Win;Soap.Win;Xml.Win;Bde;Vcl.Touch;Vcl.Samples;Vcl.Shell;Datasnap
if %errorlevel% neq 0 (
    echo Compilation failed!
    exit /b %errorlevel%
)
echo Compilation successful!
