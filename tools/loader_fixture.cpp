#include "native_protocol.hpp"
#include <windows.h>
#include <cstring>
using namespace channel_expand;
extern "C" __declspec(dllexport) std::uint64_t FixtureData=0x12345678ull;
extern "C" __declspec(dllexport) DWORD WINAPI FixtureEcho(void* address) {
    NativeRequestV1 value{};SIZE_T bytes{};
    if(!ReadProcessMemory(GetCurrentProcess(),address,&value,sizeof(value),&bytes)||bytes!=sizeof(value))return ERROR_NOACCESS;
    std::string reason;if(!ValidateNativeRequest(value,reason))return ERROR_INVALID_DATA;
    value.frames=0xFEDCBA9876543210ull;value.state=static_cast<std::uint32_t>(NativeState::Idle);SetNativeReason(value,"private Windows protocol fixture; no engine callbacks");
    return WriteProcessMemory(GetCurrentProcess(),address,&value,sizeof(value),&bytes)&&bytes==sizeof(value)?0:ERROR_WRITE_FAULT;
}
extern "C" __declspec(dllexport) DWORD WINAPI FixtureDelay(void* address) { Sleep(500);return FixtureEcho(address); }
