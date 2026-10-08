@echo off
if not defined TASK_VCVARS set "TASK_VCVARS=E:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
call "%TASK_VCVARS%" >nul
cd /d "%~dp0.."
if not defined TASK_GUI_OUT set "TASK_GUI_OUT=build\graphical"
if not exist "%TASK_GUI_OUT%" mkdir "%TASK_GUI_OUT%"
cl /nologo /std:c++17 /EHsc /W4 /WX /utf-8 /MT /O2 /Zi /DWIN32_LEAN_AND_MEAN /DNOMINMAX /DUNICODE /D_UNICODE /I source tools\loader_target.cpp tools\loader_session.cpp tools\steam_discovery.cpp tools\native_loader.cpp /Fe"%TASK_GUI_OUT%\channel_expand_loader.exe" /Fo"%TASK_GUI_OUT%/" /Fd"%TASK_GUI_OUT%\channel_expand_loader.pdb" /link bcrypt.lib advapi32.lib shell32.lib /INCREMENTAL:NO
if errorlevel 1 exit /b 1
cl /nologo /std:c++17 /EHsc /W4 /WX /utf-8 /MT /O2 /Zi /DWIN32_LEAN_AND_MEAN /DNOMINMAX /DUNICODE /D_UNICODE /I source tools\loader_target.cpp tools\loader_session.cpp tools\steam_discovery.cpp tools\launcher_gui.cpp /Fe"%TASK_GUI_OUT%\channel_expand_launcher.exe" /Fo"%TASK_GUI_OUT%/" /Fd"%TASK_GUI_OUT%\channel_expand_launcher.pdb" /link bcrypt.lib advapi32.lib shell32.lib user32.lib gdi32.lib comctl32.lib ole32.lib uuid.lib /SUBSYSTEM:WINDOWS /MANIFEST:EMBED /MANIFESTINPUT:tools\launcher_gui.manifest /INCREMENTAL:NO
if errorlevel 1 exit /b 1
cl /nologo /LD /std:c++17 /EHsc /W4 /WX /utf-8 /MT /O2 /DWIN32_LEAN_AND_MEAN /DNOMINMAX /I source tools\loader_fixture.cpp source\native_protocol.cpp /Fe"%TASK_GUI_OUT%\loader_fixture.dll" /Fo"%TASK_GUI_OUT%/" /link /DEF:tools\loader_fixture.def /INCREMENTAL:NO

