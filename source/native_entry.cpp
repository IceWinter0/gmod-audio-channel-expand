#include "native_protocol.hpp"
#include <windows.h>
#include <intrin.h>
#include <cstring>
extern "C" __declspec(dllexport) DWORD WINAPI ChannelExpandNativeEntry(void* address) {
    using namespace channel_expand;
    NativeRequestV1 request{}; SIZE_T count{};
    if (!address || !ReadProcessMemory(GetCurrentProcess(),address,&request,sizeof(request),&count) || count!=sizeof(request)) return ERROR_NOACCESS;
    const auto slot=reinterpret_cast<std::uintptr_t>(_AddressOfReturnAddress());
    NativeRequestV1 result; std::string reason;
    try {
        if (!ValidateNativeRequest(request,reason)) { result.state=static_cast<std::uint32_t>(NativeState::Rejected); SetNativeReason(result,reason); }
        else if (request.action==static_cast<std::uint32_t>(NativeAction::Start)) result=StartNativeSession(request.flags,slot);
        else result=QueryNativeSession(request.action==static_cast<std::uint32_t>(NativeAction::Readiness));
    } catch (const std::exception& e) { result.state=static_cast<std::uint32_t>(NativeState::Failed); SetNativeReason(result,e.what()); }
    catch (...) { result.state=static_cast<std::uint32_t>(NativeState::Failed); SetNativeReason(result,"unhandled native exception"); }
    result.action=request.action; result.flags=request.flags; result.request_id=request.request_id;
    if (!WriteProcessMemory(GetCurrentProcess(),address,&result,sizeof(result),&count) || count!=sizeof(result)) return ERROR_WRITE_FAULT;
    return ERROR_SUCCESS;
}
