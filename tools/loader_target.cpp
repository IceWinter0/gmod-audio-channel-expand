#include "loader_target.hpp"
#include <tlhelp32.h>
#include <bcrypt.h>
#include <filesystem>
#include <algorithm>
#include <cstring>
#include <limits>
namespace channel_expand::loader {
namespace {
struct Close { HANDLE h{}; ~Close(){if(h && h!=INVALID_HANDLE_VALUE) CloseHandle(h);} };
bool Read(HANDLE p,std::uintptr_t a,void* out,std::size_t n) { SIZE_T got{}; return a && n && a<=UINTPTR_MAX-n && ReadProcessMemory(p,reinterpret_cast<void*>(a),out,n,&got) && got==n; }
bool Text(HANDLE p,std::uintptr_t a,std::string& text,std::size_t limit=256) {
    text.clear(); for(std::size_t i=0;i<limit;++i) { char ch{}; if(!Read(p,a+i,&ch,1)) return false; if(!ch) return !text.empty(); text+=ch; } return false;
}
bool Owner(HANDLE process) {
    HANDLE remote{},local{};
    if(!OpenProcessToken(process,TOKEN_QUERY,&remote)) return false; Close r{remote};
    if(!OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&local)) return false; Close l{local};
    std::vector<std::uint8_t> a(65536),b(65536); DWORD na{},nb{};
    if(!GetTokenInformation(remote,TokenUser,a.data(),static_cast<DWORD>(a.size()),&na) ||
       !GetTokenInformation(local,TokenUser,b.data(),static_cast<DWORD>(b.size()),&nb)) return false;
    return EqualSid(reinterpret_cast<TOKEN_USER*>(a.data())->User.Sid,reinterpret_cast<TOKEN_USER*>(b.data())->User.Sid)!=0;
}
}
bool SamePath(const std::wstring& a,const std::wstring& b) {
    try {
        const auto x=std::filesystem::canonical(a).wstring(),y=std::filesystem::canonical(b).wstring();
        return CompareStringOrdinal(x.c_str(),-1,y.c_str(),-1,TRUE)==CSTR_EQUAL;
    } catch (...) { return false; }
}
bool FileSha256(const std::wstring& path,std::string& out,std::wstring& reason) {
    Close file{CreateFileW(path.c_str(),GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_FLAG_SEQUENTIAL_SCAN,nullptr)};
    if(file.h==INVALID_HANDLE_VALUE) { reason=L"cannot open file for hashing"; return false; }
    BCRYPT_ALG_HANDLE algorithm{}; BCRYPT_HASH_HANDLE hash{};
    if(BCryptOpenAlgorithmProvider(&algorithm,BCRYPT_SHA256_ALGORITHM,nullptr,0)<0) { reason=L"SHA256 provider failed"; return false; }
    struct Crypto { BCRYPT_ALG_HANDLE a; BCRYPT_HASH_HANDLE h{}; std::vector<std::uint8_t> object; ~Crypto(){if(h) BCryptDestroyHash(h); BCryptCloseAlgorithmProvider(a,0);} } c{algorithm};
    LARGE_INTEGER file_size{}; if(!GetFileSizeEx(file.h,&file_size) || file_size.QuadPart<=0 || file_size.QuadPart>64*1024*1024) { reason=L"hashed image size outside bound"; return false; }
    DWORD size{},bytes{}; if(BCryptGetProperty(algorithm,BCRYPT_OBJECT_LENGTH,reinterpret_cast<PUCHAR>(&size),sizeof(size),&bytes,0)<0 || !size || size>1048576) { reason=L"SHA256 object size failed"; return false; }
    c.object.resize(size); std::vector<std::uint8_t> buffer(65536); std::uint8_t digest[32]{};
    if(BCryptCreateHash(algorithm,&hash,c.object.data(),size,nullptr,0,0)<0) { reason=L"SHA256 create failed"; return false; } c.h=hash;
    for (;;) { DWORD read{}; if(!ReadFile(file.h,buffer.data(),static_cast<DWORD>(buffer.size()),&read,nullptr)) { reason=L"hash read failed"; return false; }
        if(!read) break; if(BCryptHashData(hash,buffer.data(),read,0)<0) { reason=L"SHA256 update failed"; return false; } }
    if(BCryptFinishHash(hash,digest,sizeof(digest),0)<0) { reason=L"SHA256 finish failed"; return false; }
    constexpr char hex[]="0123456789ABCDEF"; out.clear(); for(auto x:digest){out+=hex[x>>4];out+=hex[x&15];} reason.clear();return true;
}
bool RetryableModuleSnapshotError(DWORD error) noexcept { return error==ERROR_PARTIAL_COPY || error==ERROR_BAD_LENGTH; }
bool Modules(DWORD pid,std::vector<RemoteModule>& out,std::wstring& reason,DWORD* error) {
    if(error)*error=ERROR_SUCCESS;out.clear();
    HANDLE snapshot=INVALID_HANDLE_VALUE;DWORD snapshot_error=ERROR_SUCCESS;
    for(int attempt=0;attempt<8;++attempt) {
        snapshot=CreateToolhelp32Snapshot(TH32CS_SNAPMODULE|TH32CS_SNAPMODULE32,pid);
        if(snapshot!=INVALID_HANDLE_VALUE)break;
        snapshot_error=GetLastError();if(!RetryableModuleSnapshotError(snapshot_error))break;
        if(attempt<7)Sleep(10);
    }
    Close own{snapshot};
    const auto fail=[&](const wchar_t* message,DWORD code){if(error)*error=code;reason=message;reason+=L" (Win32="+std::to_wstring(code)+L")";SetLastError(code);return false;};
    if(snapshot==INVALID_HANDLE_VALUE)return fail(RetryableModuleSnapshotError(snapshot_error)?L"retryable module snapshot":L"module snapshot failed",snapshot_error);
    MODULEENTRY32W entry{};entry.dwSize=sizeof(entry);
    if(!Module32FirstW(snapshot,&entry))return fail(L"module enumeration failed",GetLastError());
    do { if(out.size()==4096)return fail(L"module count exceeds bound",ERROR_INVALID_DATA);
        out.push_back({reinterpret_cast<std::uintptr_t>(entry.modBaseAddr),entry.modBaseSize,entry.szModule,entry.szExePath});
    }while(Module32NextW(snapshot,&entry));
    const auto final_error=GetLastError();if(final_error!=ERROR_NO_MORE_FILES){out.clear();return fail(L"incomplete module enumeration",final_error);}
    reason.clear();return true;
}

bool ResolveRemoteExport(HANDLE process,DWORD pid,std::uintptr_t module,const std::string& name,std::uintptr_t& address,std::wstring& reason,unsigned depth) {
    address=0; if(depth>=8 || !module || name.empty() || name.size()>256){reason=L"export recursion/input invalid";return false;}
    IMAGE_DOS_HEADER dos{};IMAGE_NT_HEADERS64 nt{};
    if(!Read(process,module,&dos,sizeof(dos)) || dos.e_magic!=IMAGE_DOS_SIGNATURE || dos.e_lfanew<64 || dos.e_lfanew>1048576 ||
       !Read(process,module+static_cast<std::uintptr_t>(dos.e_lfanew),&nt,sizeof(nt)) || nt.Signature!=IMAGE_NT_SIGNATURE ||
       nt.FileHeader.Machine!=IMAGE_FILE_MACHINE_AMD64 || nt.OptionalHeader.Magic!=IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
       nt.OptionalHeader.SizeOfImage<4096 || nt.OptionalHeader.SizeOfImage>0x40000000){reason=L"invalid remote x64 image";return false;}
    const auto image=nt.OptionalHeader.SizeOfImage; const auto inside=[&](std::uint32_t rva,std::size_t n){return rva && rva<image && n<=image-rva && module<=UINTPTR_MAX-rva-n;};
    const auto dir=nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];IMAGE_EXPORT_DIRECTORY table{};
    if(dir.Size<sizeof(table) || !inside(dir.VirtualAddress,dir.Size) || !Read(process,module+dir.VirtualAddress,&table,sizeof(table)) ||
       !table.NumberOfFunctions || table.NumberOfFunctions>65536 || table.NumberOfNames>65536 ||
       !inside(table.AddressOfFunctions,static_cast<std::size_t>(table.NumberOfFunctions)*4) ||
       (table.NumberOfNames && (!inside(table.AddressOfNames,static_cast<std::size_t>(table.NumberOfNames)*4) || !inside(table.AddressOfNameOrdinals,static_cast<std::size_t>(table.NumberOfNames)*2)))){reason=L"invalid remote export directory";return false;}
    std::vector<DWORD> functions(table.NumberOfFunctions),names(table.NumberOfNames);std::vector<WORD> ordinals(table.NumberOfNames);
    if(!Read(process,module+table.AddressOfFunctions,functions.data(),functions.size()*4) ||
       (table.NumberOfNames && (!Read(process,module+table.AddressOfNames,names.data(),names.size()*4) || !Read(process,module+table.AddressOfNameOrdinals,ordinals.data(),ordinals.size()*2)))){reason=L"remote export arrays unreadable";return false;}
    std::uint32_t index=UINT32_MAX;
    if(name[0]=='#') {
        std::uint64_t number=0; if(name.size()==1){reason=L"empty export ordinal";return false;}
        for(std::size_t i=1;i<name.size();++i){if(name[i]<'0'||name[i]>'9'||number>65535){reason=L"invalid export ordinal";return false;}number=number*10+static_cast<unsigned>(name[i]-'0');}
        if(number>=table.Base && number-table.Base<table.NumberOfFunctions) index=static_cast<std::uint32_t>(number-table.Base);
    } else for(std::size_t i=0;i<names.size();++i) {
        std::string current; if(!inside(names[i],1) || !Text(process,module+names[i],current,std::min<std::size_t>(256,image-names[i]))){reason=L"remote export name invalid";return false;}
        if(current==name){if(ordinals[i]>=functions.size()){reason=L"export ordinal outside array";return false;}index=ordinals[i];break;}
    }
    if(index==UINT32_MAX || !inside(functions[index],1)){reason=L"remote export missing";return false;}
    const auto rva=functions[index];
    if(rva>=dir.VirtualAddress && rva-dir.VirtualAddress<dir.Size){
        std::string forward; if(!Text(process,module+rva,forward,std::min<std::size_t>(256,dir.Size-(rva-dir.VirtualAddress)))){reason=L"invalid forwarder";return false;}
        const auto dot=forward.rfind('.');if(dot==std::string::npos||!dot||dot+1==forward.size()){reason=L"malformed forwarder";return false;}
        std::wstring target; for(std::size_t i=0;i<dot;++i){const auto ch=static_cast<unsigned char>(forward[i]);if(ch<33||ch>126){reason=L"nonASCII forwarder module";return false;}target+=static_cast<wchar_t>(ch);} if(target.find(L'.')==std::wstring::npos)target+=L".dll";
        std::vector<RemoteModule> list;if(!Modules(pid,list,reason))return false;
        for(const auto& m:list)if(CompareStringOrdinal(m.name.c_str(),-1,target.c_str(),-1,TRUE)==CSTR_EQUAL)return ResolveRemoteExport(process,pid,m.base,forward.substr(dot+1),address,reason,depth+1);
        reason=L"forwarder module absent; no guessed API-set mapping";return false;
    }
    MEMORY_BASIC_INFORMATION page{};const auto value=module+rva;
    if(!VirtualQueryEx(process,reinterpret_cast<void*>(value),&page,sizeof(page)) || page.State!=MEM_COMMIT || page.Type!=MEM_IMAGE ||
       page.AllocationBase!=reinterpret_cast<void*>(module) || (page.Protect&PAGE_GUARD) || !(page.Protect&(PAGE_EXECUTE|PAGE_EXECUTE_READ|PAGE_EXECUTE_READWRITE|PAGE_EXECUTE_WRITECOPY))){reason=L"export target not executable owning image";return false;}
    address=value;reason.clear();return true;
}
bool ValidateGmodTarget(HANDLE process,const std::wstring& game,const std::wstring& engine,TargetIdentity& id,std::wstring& reason,DWORD* module_error) {
    if(module_error)*module_error=ERROR_SUCCESS;
    wchar_t image[32768]{};DWORD length=32768;
    if(!QueryFullProcessImageNameW(process,0,image,&length) || !SamePath(image,game)){reason=L"target executable path differs";return false;}
    const auto expected=std::filesystem::path(game);
    if(_wcsicmp(expected.filename().c_str(),L"gmod.exe") || _wcsicmp(expected.parent_path().filename().c_str(),L"win64")){reason=L"configured target must be bin/win64/gmod.exe";return false;}
    BOOL wow{};SYSTEM_INFO info{};GetNativeSystemInfo(&info);
    if(!IsWow64Process(process,&wow) || wow || info.wProcessorArchitecture!=PROCESSOR_ARCHITECTURE_AMD64 || !Owner(process)){reason=L"target must be same-user native x64";return false;}
    FILETIME created{},exited{},kernel{},user{};DWORD exit_code{};
    if(!GetProcessTimes(process,&created,&exited,&kernel,&user) || !GetExitCodeProcess(process,&exit_code) || exit_code!=STILL_ACTIVE){reason=L"target exited or identity unavailable";return false;}
    std::vector<RemoteModule> list;if(!Modules(GetProcessId(process),list,reason,module_error))return false;
    bool found=false;for(const auto& m:list)if(_wcsicmp(m.name.c_str(),L"engine.dll")==0){if(!SamePath(m.path,engine)){reason=L"loaded engine path differs";return false;}found=true;}
    bool client=false;const auto client_path=(std::filesystem::path(game).parent_path()/L"client.dll").wstring();
    for(const auto& m:list)if(_wcsicmp(m.name.c_str(),L"client.dll")==0){if(!SamePath(m.path,client_path)){reason=L"loaded client path differs";return false;}client=true;}
    if(!found || !client){reason=L"waiting for target engine/client modules";return false;}
    std::string sha;if(!FileSha256(engine,sha,reason))return false;
    if(sha!="7C21E827722FA7AC9BA4539DC652D3B79F58E240DA49D28E75A1A9A1A88C4173"){reason=L"unsupported target engine SHA256";return false;}
    id.pid=GetProcessId(process);id.path=image;id.created=(static_cast<std::uint64_t>(created.dwHighDateTime)<<32)|created.dwLowDateTime;reason.clear();return true;
}
}
