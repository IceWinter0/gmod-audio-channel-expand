#pragma once
#include "loader_target.hpp"
#include "native_protocol.hpp"
#include <filesystem>
#include <functional>
#include <memory>
#include <atomic>
namespace channel_expand::loader {
std::filesystem::path Home();
std::string Narrow(const std::wstring&);
std::wstring Wide(const std::string&);
struct LoaderConfig { std::wstring game,module,engine; std::string hash; bool acknowledged{},clear_once{}; };
struct SessionEvent { NativeRequestV1 status; std::wstring message,log_path; DWORD pid{}; bool has_status{},terminal{}; };
using EventSink=std::function<void(const SessionEvent&)>;
LoaderConfig LoadConfig(const std::wstring& home);
void SaveConfig(const std::wstring& home,const LoaderConfig&);
std::string ValidatePackage(const std::wstring& home);
std::wstring DefaultModulePath(const std::wstring& home);
void VerifyModule(const LoaderConfig&);
std::wstring FormatStatus(const NativeRequestV1&);
int SelfCheckLoader(const std::wstring& fixture);
bool SelfCheckConfig(std::wstring& why);
class LoaderSession {
 public:
  LoaderSession(); ~LoaderSession(); LoaderSession(const LoaderSession&)=delete; LoaderSession& operator=(const LoaderSession&)=delete;
  void Start(const LoaderConfig&,const EventSink&);
  void StartAt(const LoaderConfig&,DWORD,const EventSink&);
  void BindForQuery(const LoaderConfig&,DWORD,const EventSink&);
  void Query(const EventSink&);
  void Cancel() noexcept; bool Running() const noexcept;
 private: struct Impl; std::unique_ptr<Impl> impl_; std::atomic<bool> cancelled_{false};
  void Begin(const LoaderConfig&,DWORD,bool,bool,const EventSink&);
};
}
