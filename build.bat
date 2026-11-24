@echo off
rem build.bat: compile PIC stub + BOF. Artifacts in build\ (gitignored).
rem stub.c must stay fully inlined (extract_stub.py enforces zero .text relocs).
setlocal
rem deterministic toolchain env (vcvars not needed for /c compiles)
set "MSVC=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207"
set "SDK=C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0"
set "PATH=%MSVC%\bin\Hostx64\x64;%PATH%"
set "INCLUDE=%MSVC%\include;%SDK%\ucrt;%SDK%\um;%SDK%\shared;%SDK%\winrt;%SDK%\cppwinrt"
cd /d "%~dp0src"
if not exist ..\build mkdir ..\build

set CFLAGS=/nologo /TC /c /O2 /GS- /GR- /EHs-c- /Zl

echo [1/3] stub.c -^> stub.obj
cl %CFLAGS% /Fo..\build\stub.obj stub.c || goto :err

echo [2/3] extract_stub.py -^> stub_blob.h
set PY=python
where py >nul 2>&1 && set PY=py -3
%PY% extract_stub.py ..\build\stub.obj stub_blob.h || goto :err

echo [3/4] abe.c -^> abe.x64.o (BOF COFF)
cl %CFLAGS% /Fo..\build\abe.obj abe.c || goto :err
copy /y ..\build\abe.obj ..\build\abe.x64.o >nul

echo [4/4] AppBound0.cs -^> AppBound0.exe (net4x execute-assembly)
"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe" /nologo /target:exe /optimize+ /platform:x64 /out:..\build\AppBound0.exe AppBound0.cs AbeHwbp.cs AppBound0Stub.cs || goto :err

echo [+] OK: build\abe.x64.o + build\AppBound0.exe
exit /b 0

:err
echo [-] build failed
exit /b 1
