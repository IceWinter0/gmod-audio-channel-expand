#include "loader_session.hpp"
#include <shellapi.h>
#include <tlhelp32.h>
#include <fstream>
#include <iostream>
#include <algorithm>
#include <set>
#include <sstream>
#include <cstring>
#include <chrono>
namespace channel_expand::loader {
struct Handle { HANDLE h{}; ~Handle(){if(h && h!=INVALID_HANDLE_VALUE)CloseHandle(h);} Handle()=default; explicit Handle(HANDLE p):h(p){}; Handle(const Handle&)=delete; Handle& operator=(const Handle&)=delete; };
std::filesystem::path Home() { wchar_t path[32768]{}; const auto n=GetModuleFileNameW(nullptr,path,32768);if(!n||n>=32768)throw std::runtime_error("launcher path unavailable");return std::filesystem::path(path).parent_path(); }
std::wstring Key(const std::filesystem::path& file,const wchar_t* key) { wchar_t out[32768]{};const auto n=GetPrivateProfileStringW(L"channel_expand",key,L"",out,32768,file.c_str());if(n>=32767)throw std::runtime_error("configuration value truncated");return out; }
std::string Narrow(const std::wstring& s){if(s.empty())return {};const auto n=WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,s.data(),static_cast<int>(s.size()),nullptr,0,nullptr,nullptr);if(n<=0)throw std::runtime_error("invalid Unicode");std::string out(static_cast<std::size_t>(n),'\0');WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,s.data(),static_cast<int>(s.size()),out.data(),n,nullptr,nullptr);return out;}
std::wstring Wide(const std::string& s){if(s.empty())return {};const auto n=MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,s.data(),static_cast<int>(s.size()),nullptr,0);if(n<=0)return L"invalid UTF8";std::wstring out(static_cast<std::size_t>(n),L'\0');MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,s.data(),static_cast<int>(s.size()),out.data(),n);return out;}

std::string ValidatePackage(const std::wstring& home) {
 std::ifstream f(std::filesystem::path(home)/L"native_module.sha256",std::ios::binary);std::string hash;f>>hash;
 if(hash.size()!=64||!std::all_of(hash.begin(),hash.end(),[](char c){return (c>='0'&&c<='9')||(c>='A'&&c<='F');}))throw std::runtime_error("package native_module.sha256 missing/invalid");
 return hash;
}
std::wstring DefaultModulePath(const std::wstring& home){return (std::filesystem::path(home)/L"gmcl_channel_expand_win64.dll").wstring();}
void VerifyModule(const LoaderConfig& c){ std::wstring why;std::string hash;
 if(_wcsicmp(std::filesystem::path(c.module).filename().c_str(),L"gmcl_channel_expand_win64.dll")||!FileSha256(c.module,hash,why)||hash!=c.hash||hash!=ValidatePackage(Home().wstring()))throw std::runtime_error("module path/hash does not match this package");
}
LoaderConfig LoadConfig(const std::wstring& home){
 const auto file=std::filesystem::path(home)/L"channel_expand_loader.ini";
 const auto get=[&](const wchar_t* key){wchar_t out[32768]{};const auto n=GetPrivateProfileStringW(L"channel_expand",key,L"",out,32768,file.c_str());if(n>=32767)throw std::runtime_error("configuration value truncated");return std::wstring(out);};
 LoaderConfig c;c.game=get(L"game");c.module=get(L"module");c.hash=get(L"module_sha256").empty()?std::string{}:Narrow(get(L"module_sha256"));
 c.acknowledged=get(L"abi")==L"1"&&get(L"ack_fail_stop")==L"1"&&c.hash==ValidatePackage(home);c.clear_once=get(L"clear_once")==L"1"&&c.acknowledged;
 if(c.module.empty())c.module=DefaultModulePath(home);if(!c.game.empty())c.engine=(std::filesystem::path(c.game).parent_path()/L"engine.dll").wstring();return c;
}
void SaveConfig(const std::wstring& home,const LoaderConfig& c){
 const auto file=std::filesystem::path(home)/L"channel_expand_loader.ini";
 const auto put=[&](const wchar_t* key,const std::wstring& value){if(!WritePrivateProfileStringW(L"channel_expand",key,value.c_str(),file.c_str()))throw std::runtime_error("configuration directory is not writable");};
 put(L"abi",L"1");put(L"game",c.game);put(L"module",c.module);put(L"module_sha256",Wide(c.hash));put(L"ack_fail_stop",c.acknowledged?L"1":L"0");put(L"clear_once",c.clear_once?L"1":L"0");
}
std::wstring FormatStatus(const NativeRequestV1& r){std::ostringstream line;line<<"state="<<r.state<<" stage="<<r.stage<<" capacity="<<r.capacity<<" active="<<r.active<<" dynamic="<<r.dynamic<<" static="<<r.statics<<" total="<<r.total<<" errors="<<r.errors<<" fallback="<<r.fallback<<" frames="<<r.frames<<" mixed="<<r.mixed<<" diagnostics="<<r.diagnostic_flags<<" reason="<<r.reason;return Wide(line.str());}
std::set<DWORD> Candidates(const LoaderConfig& c){std::set<DWORD> out;Handle snapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0));if(snapshot.h==INVALID_HANDLE_VALUE)throw std::runtime_error("process snapshot failed");PROCESSENTRY32W p{};p.dwSize=sizeof(p);if(!Process32FirstW(snapshot.h,&p))throw std::runtime_error("process enumeration failed");do{if(_wcsicmp(p.szExeFile,L"gmod.exe"))continue;Handle h(OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,FALSE,p.th32ProcessID));if(!h.h)continue;wchar_t image[32768]{};DWORD n=32768;if(QueryFullProcessImageNameW(h.h,0,image,&n)&&SamePath(image,c.game))out.insert(p.th32ProcessID);}while(Process32NextW(snapshot.h,&p));return out;}
struct RemoteCall {
 HANDLE process{};void* memory{};Handle thread;bool completed=false;
 explicit RemoteCall(HANDLE p):process(p){}
 ~RemoteCall(){if(memory){if(WaitForSingleObject(process,0)==WAIT_OBJECT_0) return; if(completed || (thread.h&&WaitForSingleObject(thread.h,0)==WAIT_OBJECT_0))VirtualFreeEx(process,memory,0,MEM_RELEASE);else std::wcerr<<L"Pending remote request retained until target exit; never freed while executing.\n";}}
 bool Run(std::uintptr_t entry,const void* input,std::size_t bytes,DWORD timeout,std::wstring& why){memory=VirtualAllocEx(process,nullptr,bytes,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);if(!memory){why=L"remote allocation failed";return false;}SIZE_T written{};if(!WriteProcessMemory(process,memory,input,bytes,&written)||written!=bytes){completed=true;why=L"remote request write failed";return false;}thread.h=CreateRemoteThread(process,nullptr,0,reinterpret_cast<LPTHREAD_START_ROUTINE>(entry),memory,0,nullptr);if(!thread.h){completed=true;why=L"remote thread creation refused";return false;}const auto wait=WaitForSingleObject(thread.h,timeout);if(wait!=WAIT_OBJECT_0){why=L"remote call timeout/unknown; no retry or thread termination";return false;}completed=true;return true;}
 bool Response(void* output,std::size_t bytes,std::wstring& why){DWORD code{};if(!completed||!GetExitCodeThread(thread.h,&code)||code!=0){why=L"native export failed; query actual state before retry";return false;}SIZE_T got{};if(!ReadProcessMemory(process,memory,output,bytes,&got)||got!=bytes){why=L"native response unreadable";return false;}return true;}
};
std::uintptr_t Entry(HANDLE h,DWORD pid,const LoaderConfig& c,bool load,std::wstring& why){std::vector<RemoteModule> modules;if(!Modules(pid,modules,why))return 0;std::uintptr_t found=0,kernel=0;
 for(const auto& m:modules){if(_wcsicmp(m.name.c_str(),L"kernel32.dll")==0)kernel=m.base;if(_wcsicmp(m.name.c_str(),L"gmcl_channel_expand_win64.dll")==0){if(!SamePath(m.path,c.module)){why=L"different module copy already loaded";return 0;}found=m.base;}}
 if(!found){if(!load){why=L"native module not loaded; query performs no loading";return 0;}std::uintptr_t library{};if(!kernel||!ResolveRemoteExport(h,pid,kernel,"LoadLibraryW",library,why))return 0;
  RemoteCall call(h);if(!call.Run(library,c.module.c_str(),(c.module.size()+1)*sizeof(wchar_t),15000,why))return 0;
  // LoadLibrary's HMODULE cannot be recovered from the DWORD thread exit code.
  if(!Modules(pid,modules,why))return 0;for(const auto& m:modules)if(SamePath(m.path,c.module))found=m.base;
  if(!found){why=L"LoadLibrary completed but exact module absent";return 0;}
 }
 std::uintptr_t entry{};if(!ResolveRemoteExport(h,pid,found,"ChannelExpandNativeEntry",entry,why))return 0;return entry;
}
int SelfCheckLoader(const std::wstring& fixture) {
    SECURITY_ATTRIBUTES security{sizeof(security),nullptr,TRUE};Handle done(CreateEventW(&security,TRUE,FALSE,nullptr));
    if(!done.h)throw std::runtime_error("fixture event creation failed");
    const auto exe=(Home()/L"channel_expand_loader.exe").wstring();
    auto command=L"\""+exe+L"\" --loader-owned-child "+std::to_wstring(reinterpret_cast<std::uintptr_t>(done.h));
    STARTUPINFOW startup{};startup.cb=sizeof(startup);PROCESS_INFORMATION created{};
    if(!CreateProcessW(exe.c_str(),command.data(),nullptr,nullptr,TRUE,CREATE_NO_WINDOW|CREATE_SUSPENDED,nullptr,Home().c_str(),&startup,&created))throw std::runtime_error("owned fixture child creation failed");
    Handle process(created.hProcess),initial(created.hThread);
    struct ExitChild { HANDLE event,process;~ExitChild(){SetEvent(event);WaitForSingleObject(process,5000);} } exit{done.h,process.h};
    std::wstring why;std::vector<RemoteModule> modules;std::uintptr_t kernel=0;
    DWORD cold_error{};
    const bool cold_success=Modules(created.dwProcessId,modules,why,&cold_error);
    const bool cold_pending=!cold_success && (cold_error==ERROR_PARTIAL_COPY || cold_error==ERROR_BAD_LENGTH) && why.find(L"retryable module snapshot")!=std::wstring::npos;
    if(ResumeThread(initial.h)==static_cast<DWORD>(-1))throw std::runtime_error("owned cold child resume failed");
    if(RetryableModuleSnapshotError(ERROR_ACCESS_DENIED)||RetryableModuleSnapshotError(ERROR_INVALID_PARAMETER)||RetryableModuleSnapshotError(ERROR_INVALID_HANDLE))throw std::runtime_error("terminal snapshot errors marked retryable");
    if(!cold_pending)throw std::runtime_error("cold snapshot was treated as terminal instead of retryable (observed Win32="+std::to_string(cold_error)+")");
    for(int attempt=0;attempt<100&&!kernel;++attempt){if(Modules(created.dwProcessId,modules,why))for(const auto& m:modules)if(_wcsicmp(m.name.c_str(),L"kernel32.dll")==0)kernel=m.base;if(!kernel)Sleep(10);}
    if(!kernel)throw std::runtime_error("fixture kernel module unavailable");
    std::uintptr_t library{};if(!ResolveRemoteExport(process.h,created.dwProcessId,kernel,"LoadLibraryW",library,why))throw std::runtime_error(Narrow(why));
    const auto source=std::filesystem::canonical(fixture);const auto folder=Home()/(L"private-loader-\x4E2D\x6587 space-"+std::to_wstring(created.dwProcessId));std::filesystem::create_directory(folder);const auto copy=folder/source.filename();std::filesystem::copy_file(source,copy,std::filesystem::copy_options::overwrite_existing);
    const auto path=copy.wstring();
    { RemoteCall load(process.h);if(!load.Run(library,path.c_str(),(path.size()+1)*sizeof(wchar_t),5000,why))throw std::runtime_error(Narrow(why)); }
    if(!Modules(created.dwProcessId,modules,why))throw std::runtime_error(Narrow(why));std::uintptr_t module=0;for(const auto& m:modules)if(SamePath(m.path,path))module=m.base;
    if(!module || module<=UINT32_MAX)throw std::runtime_error("fixture64 module base missing/truncated");
    std::uintptr_t echo{},delay{},unused{};
    if(!ResolveRemoteExport(process.h,created.dwProcessId,module,"FixtureEcho",echo,why)||!ResolveRemoteExport(process.h,created.dwProcessId,module,"FixtureDelay",delay,why))throw std::runtime_error(Narrow(why));
    if(ResolveRemoteExport(process.h,created.dwProcessId,module,"FixtureData",unused,why)||ResolveRemoteExport(process.h,created.dwProcessId,module,"MissingExport",unused,why))throw std::runtime_error("data/missing export accepted as code");
    std::uintptr_t forwarded{};
    if(!ResolveRemoteExport(process.h,created.dwProcessId,module,"ForwardedLoadLibrary",forwarded,why)||forwarded!=library)throw std::runtime_error("real forwarded image export differs");
    if(ResolveRemoteExport(process.h,created.dwProcessId,module,"FixtureEcho",unused,why,8))throw std::runtime_error("export recursion bound ignored");
    IMAGE_DOS_HEADER fixture_dos{};IMAGE_NT_HEADERS64 fixture_nt{};SIZE_T read_bytes{};
    if(!ReadProcessMemory(process.h,reinterpret_cast<void*>(module),&fixture_dos,sizeof(fixture_dos),&read_bytes)||
       !ReadProcessMemory(process.h,reinterpret_cast<void*>(module+static_cast<std::uintptr_t>(fixture_dos.e_lfanew)),&fixture_nt,sizeof(fixture_nt),&read_bytes))throw std::runtime_error("fixture header read failed");
    const auto count_address=module+fixture_nt.OptionalHeader.DataDirectory[0].VirtualAddress+offsetof(IMAGE_EXPORT_DIRECTORY,NumberOfNames);
    DWORD original_count{},old_protection{},ignored{};
    if(!ReadProcessMemory(process.h,reinterpret_cast<void*>(count_address),&original_count,sizeof(original_count),&read_bytes)||
       !VirtualProtectEx(process.h,reinterpret_cast<void*>(count_address),sizeof(DWORD),PAGE_READWRITE,&old_protection))throw std::runtime_error("fixture export mutation prepare failed");
    const DWORD oversized=65537;
    if(!WriteProcessMemory(process.h,reinterpret_cast<void*>(count_address),&oversized,sizeof(oversized),&read_bytes))throw std::runtime_error("fixture export mutation write failed");
    const bool malformed_accepted=ResolveRemoteExport(process.h,created.dwProcessId,module,"FixtureEcho",unused,why);
    if(!WriteProcessMemory(process.h,reinterpret_cast<void*>(count_address),&original_count,sizeof(original_count),&read_bytes)||
       !VirtualProtectEx(process.h,reinterpret_cast<void*>(count_address),sizeof(DWORD),old_protection,&ignored)||malformed_accepted)throw std::runtime_error("malformed export not rejected/restored");
    NativeRequestV1 request;request.action=1;request.request_id=1;
    void* freed=nullptr;
    {RemoteCall call(process.h);if(!call.Run(echo,&request,sizeof(request),5000,why)||!call.Response(&request,sizeof(request),why)||request.frames!=0xFEDCBA9876543210ull)throw std::runtime_error("fixture protocol/64bit response failed");freed=call.memory;}
    MEMORY_BASIC_INFORMATION page{};if(!VirtualQueryEx(process.h,freed,&page,sizeof(page))||page.State!=MEM_FREE)throw std::runtime_error("completed request page not freed");
    request=NativeRequestV1{};request.action=1;request.request_id=2;
    {RemoteCall call(process.h);if(call.Run(delay,&request,sizeof(request),10,why))throw std::runtime_error("delay fixture did not time out");
      if(!VirtualQueryEx(process.h,call.memory,&page,sizeof(page))||page.State!=MEM_COMMIT)throw std::runtime_error("pending request freed before completion");
      if(WaitForSingleObject(call.thread.h,5000)!=WAIT_OBJECT_0)throw std::runtime_error("delay fixture failed to finish");call.completed=true;
      if(!call.Response(&request,sizeof(request),why)||request.request_id!=2)throw std::runtime_error("delayed request response corrupted");}
    TargetIdentity rejected{};
    if(ValidateGmodTarget(process.h,exe,L"not-an-engine.dll",rejected,why))throw std::runtime_error("owned private child accepted as GMod");
    request=NativeRequestV1{};request.action=1;request.request_id=3;
    {RemoteCall exiting(process.h);if(exiting.Run(delay,&request,sizeof(request),10,why))throw std::runtime_error("exit fixture did not remain pending");
      SetEvent(done.h);if(WaitForSingleObject(process.h,5000)!=WAIT_OBJECT_0)throw std::runtime_error("owned child did not exit while request pending");}
    
    std::cout<<"NATIVE_LOADER_SELF_CHECK_PASS: cold299 retry/terminal refusal, real owned x64 child, Unicode path, normal LoadLibrary, image export rejection,64bit ABI, timeout ownership, non-GMod refusal\n";return 0;
}
struct LoaderSession::Impl {
 Handle process;LoaderConfig config;DWORD pid{};std::uint64_t created{},request_id{};std::uintptr_t entry{};std::filesystem::path logpath;std::ofstream log;std::wstring last;ULONGLONG lastlog{};
 void Emit(const EventSink& sink,const std::wstring& message,const NativeRequestV1* r=nullptr,bool terminal=false){
  SessionEvent e;e.message=message;e.pid=pid;e.log_path=logpath.wstring();e.terminal=terminal;if(r){e.status=*r;e.has_status=true;}
  const std::wstring key=r?std::to_wstring(r->state)+L"/"+std::to_wstring(r->stage)+L"/"+Wide(r->reason):message;
  if(log.is_open()&&(key!=last||GetTickCount64()-lastlog>=10000||terminal)){log<<"tick="<<GetTickCount64()<<" "<<Narrow(r?FormatStatus(*r):message)<<'\n';log.flush();if(!log)throw std::runtime_error("session log write failed");last=key;lastlog=GetTickCount64();}
  sink(e);
 }
 NativeRequestV1 Request(NativeAction action,std::uint32_t flags=0){
  NativeRequestV1 r;r.request_id=++request_id;r.action=static_cast<std::uint32_t>(action);r.flags=flags;std::wstring why;
  RemoteCall call(process.h);if(!call.Run(entry,&r,sizeof(r),15000,why)||!call.Response(&r,sizeof(r),why))throw std::runtime_error(Narrow(why));
  if(r.magic!=kNativeMagic||r.abi!=1||r.size!=1024||r.request_id!=request_id||r.action!=static_cast<std::uint32_t>(action)||r.flags!=flags||r.state>5||r.stage>9||!std::memchr(r.reason,0,sizeof(r.reason)))throw std::runtime_error("native response ABI/id invalid");return r;
 }
};
LoaderSession::LoaderSession():impl_(std::make_unique<Impl>()){}
LoaderSession::~LoaderSession()=default;
void LoaderSession::Cancel() noexcept {cancelled_.store(true);}
bool LoaderSession::Running() const noexcept{return impl_->process.h&&WaitForSingleObject(impl_->process.h,0)==WAIT_TIMEOUT;}
void LoaderSession::Start(const LoaderConfig& c,const EventSink& sink){Begin(c,0,true,false,sink);}
void LoaderSession::StartAt(const LoaderConfig& c,DWORD pid,const EventSink& sink){Begin(c,pid,false,false,sink);}
void LoaderSession::BindForQuery(const LoaderConfig& c,DWORD pid,const EventSink& sink){Begin(c,pid,false,true,sink);}
void LoaderSession::Begin(const LoaderConfig& c,DWORD pid,bool launch,bool query,const EventSink& sink){
 cancelled_.store(false);impl_=std::make_unique<Impl>();auto& x=*impl_;x.config=c;try{x.Emit(sink,L"validating package");if(cancelled_.load())throw std::runtime_error("cancelled before launch");
 if(!c.acknowledged||c.game.empty())throw std::runtime_error("configuration/fail-stop acknowledgment required");VerifyModule(c);
 std::filesystem::create_directories(Home()/L"logs");x.logpath=Home()/L"logs"/(L"native-loader-"+std::to_wstring(GetCurrentProcessId())+L"-"+std::to_wstring(GetTickCount64())+L".log");
 x.log.open(x.logpath,std::ios::binary|std::ios::app);if(!x.log)throw std::runtime_error("cannot create local log; launch blocked");
 const auto check=[&](){if(cancelled_.load())throw std::runtime_error("cancelled; installed patches remain until game exit");};
 const auto deadline=GetTickCount64()+120000;
 if(launch){if(!Candidates(c).empty())throw std::runtime_error("GMod already running; exit game before using launcher");check();const auto result=reinterpret_cast<INT_PTR>(ShellExecuteW(nullptr,L"open",L"steam://rungameid/4000",nullptr,nullptr,SW_SHOWNORMAL));if(result<=32)throw std::runtime_error("Steam launch failed");
  x.Emit(sink,L"waiting_process");while(GetTickCount64()<deadline){check();const auto now=Candidates(c);if(now.size()>1)throw std::runtime_error("ambiguous new GMod processes");if(now.size()==1){pid=*now.begin();break;}Sleep(200);}if(!pid)throw std::runtime_error("game launch timed out");
 }
 check();if(!pid)throw std::runtime_error("explicit PID required");x.pid=pid;x.process.h=OpenProcess(PROCESS_CREATE_THREAD|PROCESS_QUERY_INFORMATION|PROCESS_VM_OPERATION|PROCESS_VM_WRITE|PROCESS_VM_READ|SYNCHRONIZE,FALSE,pid);if(!x.process.h)throw std::runtime_error("target access refused; no automatic elevation");
 FILETIME ct{},et{},kt{},ut{};if(!GetProcessTimes(x.process.h,&ct,&et,&kt,&ut))throw std::runtime_error("target creation time unavailable");x.created=(static_cast<std::uint64_t>(ct.dwHighDateTime)<<32)|ct.dwLowDateTime;
 x.log<<"pid="<<pid<<" created="<<x.created<<" game="<<Narrow(c.game)<<" module="<<Narrow(c.module)<<" module_sha="<<c.hash<<'\n';x.log.flush();
 TargetIdentity identity{};std::wstring why;bool valid=false;DWORD module_error{};
 do{check();valid=ValidateGmodTarget(x.process.h,c.game,c.engine,identity,why,&module_error);if(valid)break;x.Emit(sink,L"waiting_target: "+why);
  if(why!=L"waiting for target engine/client modules"&&!RetryableModuleSnapshotError(module_error))throw std::runtime_error(Narrow(why));if(query)break;
  if(WaitForSingleObject(x.process.h,200)==WAIT_OBJECT_0)throw std::runtime_error("target exited while waiting for modules");
 }while(GetTickCount64()<deadline);
 if(!valid)throw std::runtime_error(Narrow(why));if(identity.created!=x.created)throw std::runtime_error("target creation identity changed");
 check();x.entry=Entry(x.process.h,pid,c,!query,why);if(!x.entry)throw std::runtime_error(Narrow(why));x.request_id=GetTickCount64();
 if(query){Query(sink);return;}bool started=false;
 do{check();const auto r=x.Request(started?NativeAction::Start:NativeAction::Readiness,started?kNativeAck|(c.clear_once?kNativeClearOnce:0):0);x.Emit(sink,Wide(r.reason),&r);
  if(r.state==static_cast<std::uint32_t>(NativeState::Active))return;
  if(r.state>=static_cast<std::uint32_t>(NativeState::Rejected))throw std::runtime_error("native initialization refused; see stage/reason");
  if(r.state==static_cast<std::uint32_t>(NativeState::Idle))started=true;
  if(WaitForSingleObject(x.process.h,200)==WAIT_OBJECT_0)throw std::runtime_error("target exited");
 }while(GetTickCount64()<deadline);throw std::runtime_error("startup timed out; state unknown, query before retry");
 }catch(const std::exception& e){try{x.Emit(sink,L"failed: "+Wide(e.what()));}catch(...){}throw;}
}
void LoaderSession::Query(const EventSink& sink){auto& x=*impl_;try{if(!Running()){x.Emit(sink,L"game exited",nullptr,true);return;}if(!x.entry)throw std::runtime_error("native session is not bound");const auto r=x.Request(NativeAction::Query);x.Emit(sink,Wide(r.reason),&r);}catch(const std::exception& e){try{x.Emit(sink,L"query failed: "+Wide(e.what()));}catch(...){}throw;}}
bool SelfCheckConfig(std::wstring& why){
 try{LoaderSession cancelled;bool cancelled_rejected=false;try{cancelled.Start(LoaderConfig{},[&](const SessionEvent&){cancelled.Cancel();});}catch(const std::exception& e){cancelled_rejected=std::string(e.what())=="cancelled before launch";}if(!cancelled_rejected||cancelled.Running())throw std::runtime_error("prelaunch cancellation failed");const auto folder=Home()/(L"private-config-"+std::to_wstring(GetCurrentProcessId()));std::filesystem::create_directories(folder);
  {std::ofstream f(folder/L"native_module.sha256");f<<std::string(64,'A');}
  auto c=LoadConfig(folder.wstring());if(c.acknowledged||c.clear_once)throw std::runtime_error("missing ack became enabled");c.game=L"L:\\Unicode space\\bin\\win64\\gmod.exe";c.module=DefaultModulePath(folder.wstring());c.hash=std::string(64,'A');c.acknowledged=true;c.clear_once=true;SaveConfig(folder.wstring(),c);const auto d=LoadConfig(folder.wstring());if(!d.acknowledged||!d.clear_once||d.game!=c.game)throw std::runtime_error("config round trip failed");
  {std::ofstream f(folder/L"native_module.sha256",std::ios::trunc);f<<std::string(64,'B');}if(LoadConfig(folder.wstring()).acknowledged)throw std::runtime_error("new core retained ack");
  bool rejected=false;try{SaveConfig((folder/L"missing"/L"child").wstring(),c);}catch(...){rejected=true;}if(!rejected)throw std::runtime_error("unwritable config accepted");
  std::filesystem::remove(folder/L"channel_expand_loader.ini");std::filesystem::remove(folder/L"native_module.sha256");std::filesystem::remove(folder);return true;
 }catch(const std::exception& e){why=Wide(e.what());return false;}
}
}
