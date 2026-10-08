#pragma once
#include <string>
#include <vector>
namespace channel_expand::loader {
struct InstallCandidate { std::wstring root,game,engine,client,source,reason;bool supported{}; };
struct DiscoveryResult { std::vector<InstallCandidate> candidates;std::vector<std::wstring> diagnostics; };
DiscoveryResult DiscoverSteamInstalls();
InstallCandidate ValidateInstallRoot(const std::wstring& root);
std::vector<std::wstring> ParseSteamLibraries(const std::string& utf8,const std::wstring& steam_root);
std::wstring ParseInstallDirectory(const std::string& utf8);
bool SelfCheckDiscovery(std::wstring& why);
}
