# GMod Audio Channel Expand

Experimental Windows x64 Garry's Mod audio channel expansion: **512 total slots**, with **64 dynamic + 448 static** channels. Includes a Chinese native GUI launcher, automatic Steam-library discovery and live diagnostics. No Lua console commands are required.

**Current release: v0.11.0-rc3. This is a public release candidate, not a stable 1.0 release.**

## Quick start / 使用

1. Download the `win64.zip` Release asset and extract the entire folder to a writable location.
2. Exit GMod if it is already running.
3. Double-click `channel_expand_launcher.exe`.
4. Let it discover your Steam installation, or select the `GarrysMod` folder manually. Choose the right installation if several are found.
5. Click “启动 GMod 并启用 512 槽位”. Wait until the GUI reports “512 槽位已激活”. Then play normally.

无需手工填写路径、PID，无需 `lua_run_cl`，也无需把 DLL 复制进游戏目录。下载整个 Windows 发布包，不要只下载 EXE。

## Startup behavior / 初始化行为

The GUI has no confirmation checkboxes. Clicking Start uses the existing native initialization protocol and may **stop current client sounds once** to establish an empty channel table. It does not repeatedly stop sounds.

关闭界面只结束监控，已启用的扩容保留到游戏进程退出。不支持热卸载；取消等待也不撤销已经启用的部分。正在执行的原生请求不会被强行终止，其内存会保留至完成或游戏退出。

The runtime retains strict engine-build, module-hash, process-identity, synchronization and storage checks. Removing the GUI checkboxes does not remove those checks. In an **unrecoverable synchronization/patch state**, the existing fail-stop path can terminate the current GMod process. Save important in-game work before use. Partial or unknown initialization states require exiting GMod before retrying.

## Compatibility

- Windows x64, using the GMod x64 client. Intended for recent Windows10/11; cross-machine testing is incomplete.
- Only the following exact `engine.dll` SHA-256 is supported:
  `7C21E827722FA7AC9BA4539DC652D3B79F58E240DA49D28E75A1A9A1A88C4173`
- Core DLL version: `0.11.0-rc1-native-loader`, SHA-256:
  `D16B94A2EC6CF203AD956D76CA96C9E9AFB0125FB65F2251467EF5FE173B2DA9`

Steam or GMod may be installed on any drive. Discovery reads Steam registry entries, `libraryfolders.vdf` and `appmanifest_4000.acf`; it does not scan every disk. A different engine build is refused even if the game is found. Game updates can therefore require a new supported module.

The launcher does not edit the on-disk engine, Steam launch options or server settings. It does not elevate automatically. Server compatibility and permission to use client modules depend on the server; this release does not guarantee acceptance everywhere.

## Diagnostics

Use “复制诊断” / “打开日志”. Logs are stored in `logs/`; portable settings are in `channel_expand_loader.ini` alongside the launcher. Config write failure allows session-only use; log write failure blocks activation.

“扫描范围” is not the number of currently playing sounds. A successful status sample does not by itself prove safe installation synchronization. Stale or unavailable samples are shown as such.

Optional CLI: `channel_expand_loader.exe --discover`, or `--status --pid N` for an already loaded module. The CLI retains its advanced `--configure` flags. Do not start concurrent installations through GUI and CLI.

When moving to another computer, use a clean extraction rather than copying old absolute-path settings.

## Validation status

The unchanged core has user-runtime evidence for 512 active channels, native mixing and cleanup, DSP auxiliary routing, map reload, empty sound-system restart, and no-Lua native startup with audible output. The RC2 GUI was reported to work by the local tester.

RC3 removes GUI confirmation controls and reuses the exact same core DLL. Build, real Windows private-child loader, protocol, Steam-data parsing, configuration/cancellation and actual hidden Win32 control checks passed. The final RC3 GUI change has not received a new full in-game log.

**Real network voice, engine music/streaming, long-duration endurance, broader server compatibility and cross-machine behavior remain incompletely validated.** Please report failures with module version and diagnostics; redact personal information before posting logs.

## Build source

The separate `source.zip` asset contains the current source and third-party build dependencies. Use MSVC x64 and C++17. Set `TASK_VCVARS` to your `vcvars64.bat` if it is not at the script's default path, then run `build/graphical-launcher-build.cmd`.

The GUI/CLI build does not rebuild the core. Rebuilding the core changes its hash and requires a matching package/hash file and renewed runtime validation. The supplied DLL is not digitally signed; SHA-256 checks verify integrity, not publisher authenticity.

## Third-party notices and project license

Zydis and garrysmod_common notices are preserved in `THIRD_PARTY_NOTICES.txt` and the source distribution. No license has yet been assigned to this project's own code; source availability alone does not grant an additional redistribution license.
