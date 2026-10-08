@echo off
if not defined TASK_VCVARS set "TASK_VCVARS=E:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
call "%TASK_VCVARS%" >nul
cd /d "%~dp0.."
cl /nologo /std:c++17 /EHsc /W4 /WX /utf-8 /MT /O2 /Zi /DWIN32_LEAN_AND_MEAN /DNOMINMAX /I source tools\loader_target.cpp tools\loader_session.cpp tools\steam_discovery.cpp tools\native_loader.cpp /Febuild\channel_expand_loader.exe /Fobuild\ /Fdbuild\channel_expand_loader.pdb /link bcrypt.lib advapi32.lib shell32.lib /INCREMENTAL:NO
if errorlevel 1 exit /b 1
cl /nologo /LD /std:c++17 /EHsc /W4 /WX /utf-8 /MT /O2 /DWIN32_LEAN_AND_MEAN /DNOMINMAX /I source tools\loader_fixture.cpp source\native_protocol.cpp /Febuild\loader_fixture.dll /Fobuild\ /link /DEF:tools\loader_fixture.def /INCREMENTAL:NO
