#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include <cstdint>
namespace channel_expand::loader {
struct RemoteModule { std::uintptr_t base{}; std::uint32_t size{}; std::wstring name,path; };
struct TargetIdentity { DWORD pid{}; std::uint64_t created{}; std::wstring path; };
bool RetryableModuleSnapshotError(DWORD error) noexcept;
bool Modules(DWORD pid,std::vector<RemoteModule>& out,std::wstring& reason,DWORD* error=nullptr);
bool ResolveRemoteExport(HANDLE process,DWORD pid,std::uintptr_t module,const std::string& name,std::uintptr_t& address,std::wstring& reason,unsigned depth=0);
bool ValidateGmodTarget(HANDLE process,const std::wstring& game,const std::wstring& engine,TargetIdentity& id,std::wstring& reason,DWORD* module_error=nullptr);
bool FileSha256(const std::wstring&,std::string&,std::wstring&);
bool SamePath(const std::wstring&,const std::wstring&);
}
