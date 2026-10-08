newoption { trigger="zydis", value="path", description="Directory containing amalgamated Zydis.c/h" }
newoption { trigger="gmod-include", value="path", description="garrysmod_common/include directory" }
local zydis = _OPTIONS.zydis or "third_party/zydis"
local gmod = _OPTIONS["gmod-include"] or "third_party/garrysmod_common/include"
workspace "channel_expand"
    location "build/projects"
    configurations { "Release" }
    architecture "x86_64"
    system "windows"
    symbols "On"
    optimize "Speed"
    staticruntime "On"
    targetdir "build/bin/%{cfg.buildcfg}"
    objdir "build/obj/%{prj.name}/%{cfg.buildcfg}"
    defines { "WIN32_LEAN_AND_MEAN", "NOMINMAX", "ZYDIS_STATIC_BUILD" }
project "zydis"
    kind "StaticLib"
    language "C"
    files { zydis.."/Zydis.c", zydis.."/Zydis.h" }
    includedirs { zydis }
    warnings "Off"
local function common_cpp()
    language "C++"
    cppdialect "C++17"
    includedirs { "source", zydis }
    files { "source/manifest.hpp", "source/pe_inventory.cpp" }
    links { "zydis", "bcrypt" }
    warnings "Extra"
    fatalwarnings "All"
    buildoptions { "/utf-8" }
end
project "inspect_engine"
    kind "ConsoleApp"
    common_cpp()
    files { "tools/inspect_engine.cpp", "source/channel_storage.cpp", "source/audio_adapter.cpp", "source/frame_bridge.cpp", "source/patch_transaction.cpp", "source/native_protocol.cpp" }
project "channel_expand"
    kind "SharedLib"
    common_cpp()
    includedirs { gmod }
    files { "source/channel_storage.cpp", "source/audio_adapter.cpp", "source/frame_bridge.cpp", "source/patch_transaction.cpp", "source/patch_runtime.cpp", "source/native_protocol.cpp", "source/native_entry.cpp", "source/module.cpp" }
    targetname "gmcl_channel_expand_win64"
    targetprefix ""
    targetextension ".dll"

project "channel_expand_loader"
    kind "ConsoleApp"
    language "C++"
    cppdialect "C++17"
    includedirs { "source" }
    files { "tools/native_loader.cpp", "tools/loader_target.cpp", "tools/loader_target.hpp", "tools/loader_session.cpp", "tools/loader_session.hpp", "tools/steam_discovery.cpp", "tools/steam_discovery.hpp", "source/native_protocol.hpp" }
    links { "bcrypt", "advapi32", "shell32" }
    warnings "Extra"
    fatalwarnings "All"
    buildoptions { "/utf-8" }

project "channel_expand_launcher"
    kind "WindowedApp"
    language "C++"
    cppdialect "C++17"
    includedirs { "source" }
    files { "tools/launcher_gui.cpp", "tools/launcher_gui.manifest", "tools/loader_target.cpp", "tools/loader_target.hpp", "tools/loader_session.cpp", "tools/loader_session.hpp", "tools/steam_discovery.cpp", "tools/steam_discovery.hpp", "source/native_protocol.hpp" }
    defines { "UNICODE", "_UNICODE", "WIN32_LEAN_AND_MEAN", "NOMINMAX" }
    links { "bcrypt", "advapi32", "shell32", "user32", "gdi32", "comctl32", "ole32", "uuid" }
    warnings "Extra"
    fatalwarnings "All"
    buildoptions { "/utf-8" }
