@echo off
setlocal
if not defined TASK_VCVARS set "TASK_VCVARS=E:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
call "%TASK_VCVARS%" >nul
if errorlevel 1 exit /b 1
cd /d "%~dp0"
if not exist build mkdir build
set "TASK_ZYDIS=third_party\zydis"
set "TASK_GMOD=third_party\garrysmod_common\include"
if not exist "%TASK_ZYDIS%\Zydis.c" exit /b 2
if not exist "%TASK_GMOD%\GarrysMod\Lua\Interface.h" exit /b 2
if not exist build\Zydis_local.obj (
cl /nologo /c /O2 /MT /DZYDIS_STATIC_BUILD /I "%TASK_ZYDIS%" "%TASK_ZYDIS%\Zydis.c" /Fobuild\Zydis_local.obj
if errorlevel 1 exit /b 1
)
cl /nologo /std:c++17 /EHsc /W4 /WX /utf-8 /MT /O2 /Zi /DWIN32_LEAN_AND_MEAN /DNOMINMAX /DZYDIS_STATIC_BUILD /I source /I "%TASK_ZYDIS%" source\pe_inventory.cpp source\channel_storage.cpp source\audio_adapter.cpp source\frame_bridge.cpp source\patch_transaction.cpp source\native_protocol.cpp tools\inspect_engine.cpp build\Zydis_local.obj /Febuild\inspect_engine.exe /Fobuild\ /Fdbuild\inspect_engine.pdb /link bcrypt.lib /INCREMENTAL:NO /OPT:REF /OPT:ICF
if errorlevel 1 exit /b 1
cl /nologo /LD /std:c++17 /EHsc /W4 /WX /utf-8 /MT /O2 /Zi /DWIN32_LEAN_AND_MEAN /DNOMINMAX /DZYDIS_STATIC_BUILD /I source /I "%TASK_ZYDIS%" /I "%TASK_GMOD%" source\pe_inventory.cpp source\channel_storage.cpp source\audio_adapter.cpp source\frame_bridge.cpp source\patch_transaction.cpp source\native_protocol.cpp source\patch_runtime.cpp source\native_entry.cpp source\module.cpp build\Zydis_local.obj /Febuild\gmcl_channel_expand_win64.dll /Fobuild\ /Fdbuild\gmcl_channel_expand_win64.pdb /link bcrypt.lib /PDB:build\gmcl_channel_expand_win64.pdb /INCREMENTAL:NO /OPT:REF /OPT:ICF
if errorlevel 1 exit /b 1
call build\native-loader-build.cmd
exit /b %errorlevel%
