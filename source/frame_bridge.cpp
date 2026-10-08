#include "manifest.hpp"
#include <windows.h>
#include <winternl.h>
#include <intrin.h>
#include <Zydis.h>
#include <algorithm>
#include <atomic>
#include <cstring>
#include <limits>

namespace channel_expand {
bool ProjectMixShell(ExpandedSnapshot& full,OriginalSnapshot& shell,bool transfer,std::string& reason) {
    ExpandedSnapshot validated{};
    if (!CopySnapshotIndices(full.indices.data(),full.count,kTargetCapacity,validated,reason)) return false;
    const auto& routes=full.auxiliary_routes;
    if (transfer && (shell.auxiliary_routes.memory || shell.auxiliary_routes.elements ||
        shell.auxiliary_routes.size || shell.auxiliary_routes.allocation_count)) {
        reason="mix shell already owns routes"; return false;
    }
    if (transfer && (routes.size<0 || routes.allocation_count<routes.size || routes.size>512 ||
        routes.memory!=routes.elements || (!routes.memory && routes.allocation_count))) {
        reason="invalid mix shell route metadata"; return false;
    }
    shell.count=std::min(full.count,static_cast<std::int32_t>(kOldCapacity));
    std::copy_n(full.indices.begin(),shell.count,shell.indices.begin());
    std::copy_n(full.item_flags.begin(),shell.count,shell.item_flags.begin());
    shell.route_mask=full.route_mask;
    if (transfer) { shell.auxiliary_routes=routes; full.auxiliary_routes={}; }
    reason.clear(); return true;
}
bool RunMixShellSelfChecks(std::string& reason) {
    ExpandedSnapshot full{}; full.count=512; full.route_mask=0xA8;
    for (std::int32_t p=0;p<512;++p) { full.indices[p]=static_cast<std::int16_t>(511-p); full.item_flags[p]=static_cast<std::uint8_t>(p%7); }
    std::array<std::int32_t,3> route_values{7,12,19};
    full.auxiliary_routes={reinterpret_cast<std::uintptr_t>(route_values.data()),3,-1,3,0,reinterpret_cast<std::uintptr_t>(route_values.data())};
    const auto routes=full.auxiliary_routes;
    struct Guarded { std::uint64_t before{0x123456789ABCDEF0ull}; OriginalSnapshot shell{}; std::uint64_t after{0xFEDCBA9876543210ull}; } guarded;
    if (!ProjectMixShell(full,guarded.shell,true,reason) || guarded.shell.count!=128 || full.count!=512 ||
        full.indices[511]!=0 || std::memcmp(&routes,&guarded.shell.auxiliary_routes,sizeof(routes))) {
        reason="expanded shell projection or ownership transfer failed"; return false;
    }
    const Vector32Metadata empty{};
    if (std::memcmp(&full.auxiliary_routes,&empty,sizeof(empty))) { reason="shell route ownership duplicated"; return false; }
    for (std::int32_t p=0;p<128;++p) if (guarded.shell.indices[p]!=full.indices[p] || guarded.shell.item_flags[p]!=full.item_flags[p]) {
        reason="shell prefix differs from full snapshot"; return false;
    }
    if (!RemoveMixSnapshotItem(full,2,reason) || !ProjectMixShell(full,guarded.shell,false,reason) ||
        guarded.shell.indices[2]!=0 || std::memcmp(&routes,&guarded.shell.auxiliary_routes,sizeof(routes))) {
        reason="shell refresh lost processed tail or route ownership"; return false;
    }
    const auto saved_full=full; const auto saved_shell=guarded.shell;
    if (ProjectMixShell(full,guarded.shell,true,reason) || std::memcmp(&full,&saved_full,sizeof(full)) ||
        std::memcmp(&guarded.shell,&saved_shell,sizeof(saved_shell))) { reason="occupied shell ownership accepted"; return false; }
    full.count=513; const auto invalid=full;
    if (ProjectMixShell(full,guarded.shell,false,reason) || std::memcmp(&full,&invalid,sizeof(full)) ||
        std::memcmp(&guarded.shell,&saved_shell,sizeof(saved_shell))) { reason="invalid shell projection mutated objects"; return false; }
    if (guarded.before!=0x123456789ABCDEF0ull || guarded.after!=0xFEDCBA9876543210ull) { reason="shell projection crossed guards"; return false; }
    reason.clear(); return true;
}
namespace {
// Only these complete, relocation-free instruction prefixes may be displaced.
// Entry writes are eight aligned bytes; the gateway includes the whole final
// instruction even where its last bytes remain physically behind the jump.
constexpr std::size_t kHookCount=4;
constexpr std::array<std::uint32_t,kHookCount> kEntries{0x4E500,0x4A1B0,0x4A7F0,0x4C420};
constexpr std::array<std::uint32_t,kHookCount> kGateways{0x80,0xC0,0x100,0x140};
constexpr std::array<std::uint8_t,kHookCount> kLengths{11,10,8,13};
constexpr std::array<std::array<std::uint8_t,13>,kHookCount> kPrefixes{{
    {0x4C,0x8B,0xDC,0x55,0x49,0x8D,0xAB,0x58,0xFE,0xFF,0xFF},
    {0x4C,0x8B,0xDC,0x48,0x81,0xEC,0x08,0x09,0x00,0x00},
    {0x4C,0x8B,0xDC,0x49,0x89,0x53,0x10,0x57},
    {0x41,0x55,0x48,0x83,0xEC,0x60,0x0F,0xB6,0x81,0xA8,0x01,0,0}}};
constexpr std::array<std::array<std::uint8_t,8>,kHookCount> kUnwind{{
    {1,11,1,0,4,0x50,0,0}, {1,10,2,0,10,1,0x21,1}, {1,8,1,0,8,0x70,0,0},
    {1,13,2,0,6,0xB2,2,0xD0}}};
bool ReadSpan(std::uintptr_t address,void* out,std::size_t size) noexcept {
    SIZE_T got{};
    return ReadProcessMemory(GetCurrentProcess(),reinterpret_cast<const void*>(address),out,size,&got) && got==size;
}
void AbsoluteJump(std::uint8_t* dst,std::uintptr_t target) noexcept {
    const std::array<std::uint8_t,6> head{0xFF,0x25,0,0,0,0};
    std::memcpy(dst,head.data(),head.size()); std::memcpy(dst+6,&target,8);
}
bool DecodePrefix(std::size_t i,std::string& reason) {
    ZydisDecoder decoder{};
    ZydisDecoderInit(&decoder,ZYDIS_MACHINE_MODE_LONG_64,ZYDIS_STACK_WIDTH_64);
    std::size_t offset{};
    while (offset<kLengths[i]) {
        ZydisDecodedInstruction instruction{}; ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT]{};
        if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder,kPrefixes[i].data()+offset,kLengths[i]-offset,&instruction,operands)) ||
            !instruction.length || instruction.length>kLengths[i]-offset) { reason="gateway prefix decoding failed"; return false; }
        if (instruction.meta.category==ZYDIS_CATEGORY_CALL || instruction.meta.category==ZYDIS_CATEGORY_UNCOND_BR ||
            instruction.meta.category==ZYDIS_CATEGORY_COND_BR || instruction.meta.category==ZYDIS_CATEGORY_RET) {
            reason="gateway prefix contains control transfer"; return false;
        }
        for (std::uint8_t p=0;p<instruction.operand_count;++p) {
            if ((operands[p].type==ZYDIS_OPERAND_TYPE_MEMORY && operands[p].mem.base==ZYDIS_REGISTER_RIP) ||
                (operands[p].type==ZYDIS_OPERAND_TYPE_IMMEDIATE && operands[p].imm.is_relative)) {
                reason="gateway prefix needs relocation"; return false;
            }
        }
        offset+=instruction.length;
    }
    return true;
}
struct HookSet {
    std::uint8_t* page{};
    PRUNTIME_FUNCTION table{};
    bool registered{},retained{};
    ThreadSyncDiagnostic sync{};
    std::array<std::uintptr_t,kHookCount> entries{};
    std::array<std::array<std::uint8_t,8>,kHookCount> replacement{};
    ~HookSet() {
        if (retained) return;
        if (registered) RtlDeleteFunctionTable(table);
        if (page) VirtualFree(page,0,MEM_RELEASE);
    }
    bool Prepare(const std::array<std::uintptr_t,kHookCount>& addresses,const std::array<std::uintptr_t,kHookCount>& targets,std::string& reason) {
        entries=addresses;
        SYSTEM_INFO system{}; GetSystemInfo(&system);
        if (system.dwPageSize!=4096) { reason="unsupported hook page size"; return false; }
        const auto anchor=entries[0]&~(static_cast<std::uintptr_t>(system.dwAllocationGranularity)-1);
        for (std::uintptr_t distance=system.dwAllocationGranularity;distance<0x70000000 && !page;distance+=system.dwAllocationGranularity) {
            for (const bool above:{true,false}) {
                if ((above && anchor>UINTPTR_MAX-distance-8192) || (!above && anchor<distance+system.dwAllocationGranularity)) continue;
                const auto candidate=above?anchor+distance:anchor-distance;
                page=static_cast<std::uint8_t*>(VirtualAlloc(reinterpret_cast<void*>(candidate),8192,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE));
                if (page) break;
            }
        }
        if (!page) { reason="cannot allocate near hook gateways"; return false; }
        std::memset(page,0xCC,4096);
        table=reinterpret_cast<PRUNTIME_FUNCTION>(page+0x1100);
        for (std::size_t i=0;i<kHookCount;++i) {
            if (!targets[i] || (entries[i]&7) || !DecodePrefix(i,reason)) return false;
            std::array<std::uint8_t,13> actual{};
            if (!ReadSpan(entries[i],actual.data(),kLengths[i]) || std::memcmp(actual.data(),kPrefixes[i].data(),kLengths[i])) {
                reason="frame hook prefix differs"; return false;
            }
            AbsoluteJump(page+i*0x20,targets[i]);
            std::memcpy(page+kGateways[i],actual.data(),kLengths[i]);
            // FF 25 is recognized as an epilogue tail jump by Windows even
            // though this gateway still has a live prologue stack allocation.
            // mov rax,imm64 / jmp rax is outside that epilogue grammar.
            // Backend's displaced movzx produces a live EAX route mask, so
            // that gateway uses volatile r11; the other prefixes need r11.
            auto* tail=page+kGateways[i]+kLengths[i]; tail[0]=i==3?0x49:0x48; tail[1]=i==3?0xBB:0xB8;
            const auto continuation=entries[i]+kLengths[i]; std::memcpy(tail+2,&continuation,8);
            if (i==3) { tail[10]=0x41; tail[11]=0xFF; tail[12]=0xE3; }
            else { tail[10]=0xFF; tail[11]=0xE0; }
            const auto metadata=static_cast<DWORD>(0x1000+i*0x20);
            std::memcpy(page+metadata,kUnwind[i].data(),8);
            table[i]={kGateways[i],kGateways[i]+kLengths[i]+(i==3?13u:12u),metadata};
            const auto delta=static_cast<std::int64_t>(reinterpret_cast<std::uintptr_t>(page)+i*0x20)-static_cast<std::int64_t>(entries[i]+5);
            if (delta<INT32_MIN || delta>INT32_MAX) { reason="hook branch exceeds rel32 range"; return false; }
            replacement[i]={0xE9,0,0,0,0,0x90,0x90,0x90};
            const auto relative=static_cast<std::int32_t>(delta); std::memcpy(replacement[i].data()+1,&relative,4);
        }
        DWORD old{};
        if (!VirtualProtect(page,4096,PAGE_EXECUTE_READ,&old) || !FlushInstructionCache(GetCurrentProcess(),page,4096) ||
            !VirtualProtect(page+4096,4096,PAGE_READONLY,&old)) { reason="gateway protection or cache flush failed"; return false; }
        if (!RtlAddFunctionTable(table,static_cast<DWORD>(kHookCount),reinterpret_cast<DWORD64>(page))) { reason="gateway unwind registration failed"; return false; }
        registered=true; reason.clear(); return true;
    }
};

// Native handle enumeration avoids allocating a Toolhelp snapshot while a
// suspended engine thread might own a process heap or loader lock.
using NextThread = LONG (NTAPI*)(HANDLE,HANDLE,ACCESS_MASK,ULONG,ULONG,PHANDLE);
bool ThreadExitProven(HANDLE thread,DWORD& wait) noexcept {
    wait=WaitForSingleObject(thread,0); return wait==WAIT_OBJECT_0;
}
struct ThreadFreeze {
    struct Held { HANDLE handle{}; DWORD id{}; };
    std::array<Held,512> held{};
    std::size_t count{};
    NextThread next{};
    const char* failure{};
    ThreadSyncDiagnostic diagnostic{};
    explicit ThreadFreeze(NextThread function):next(function) {}
    ~ThreadFreeze() { Release(); }
    bool Release() noexcept {
        bool good=true;
        while (count) {
            const auto item=held[--count]; const auto h=item.handle;
            const auto previous=ResumeThread(h);
            if (previous==DWORD(-1) || !previous) {
                const auto error=previous==DWORD(-1)?GetLastError():DWORD{0};
                DWORD wait{};
                if (!ThreadExitProven(h,wait)) {
                    good=false; diagnostic.failed_thread_id=item.id;
                    diagnostic.win32_error=error; diagnostic.exit_wait_result=wait;
                }
            }
            CloseHandle(h);
        }
        return good;
    }
    bool Capture(const HookSet& hooks) noexcept {
        if (!next) { failure="native thread enumeration unavailable"; return false; }
        const auto own=GetCurrentThreadId();
        bool stable=false;
        for (int pass=0;pass<4 && !stable;++pass) {
            ++diagnostic.passes;
            const auto before=count; HANDLE previous{}; bool previous_owned=false;
            for (;;) {
                HANDLE current{};
                const auto status=next(GetCurrentProcess(),previous,SYNCHRONIZE|THREAD_SUSPEND_RESUME|THREAD_GET_CONTEXT|THREAD_QUERY_INFORMATION,0,0,&current);
                if (previous && !previous_owned) CloseHandle(previous);
                previous=nullptr; previous_owned=false;
                if (static_cast<ULONG>(status)==0x8000001Au) break;
                if (status<0 || !current) { diagnostic.native_status=static_cast<ULONG>(status); failure="native thread enumeration failed"; return false; }
                const auto id=GetThreadId(current);
                bool found=id==own;
                for (std::size_t p=0;p<count && !found;++p) found=held[p].id==id;
                if (!id) { diagnostic.win32_error=GetLastError(); CloseHandle(current); failure="thread id unavailable"; return false; }
                if (!found) {
                    if (count==held.size()) { CloseHandle(current); failure="too many threads for fixed synchronization buffer"; return false; }
                    if (SuspendThread(current)==DWORD(-1)) {
                        const auto error=GetLastError(); DWORD wait{};
                        if (ThreadExitProven(current,wait)) {
                            // A handle can outlive its thread between enumeration
                            // and suspension. Only a signalled kernel thread
                            // object proves exit; a refusal alone never does.
                            // Preserve this handle as the next cursor. A retained
                            // terminated object is enumerated again on every scan;
                            // restarting here would prevent stabilization forever.
                            ++diagnostic.exited_threads;
                            previous=current; continue;
                        }
                        diagnostic.failed_thread_id=id; diagnostic.win32_error=error;
                        diagnostic.exit_wait_result=wait;
                        CloseHandle(current); failure="thread suspension failed"; return false;
                    }
                    held[count++]={current,id}; previous_owned=true;
                }
                previous=current;
            }
            stable=count==before;
        }
        if (!stable) { failure="thread set did not stabilize"; return false; }
        for (std::size_t p=0;p<count;++p) {
            CONTEXT context{}; context.ContextFlags=CONTEXT_CONTROL;
            if (!GetThreadContext(held[p].handle,&context)) {
                diagnostic.failed_thread_id=held[p].id; diagnostic.win32_error=GetLastError();
                failure="suspended thread context unavailable"; return false;
            }
            for (std::size_t i=0;i<kHookCount;++i) if (context.Rip>=hooks.entries[i] && context.Rip<hooks.entries[i]+kLengths[i]) {
                failure="thread is executing a displaced prefix; retry later"; return false;
            }
        }
        return true;
    }
};
using QuerySystemInformation = LONG (NTAPI*)(ULONG,PVOID,ULONG,PULONG);
struct NativeThreadAudit {
    static constexpr ULONG kBytes=16*1024*1024;
    std::uint8_t* buffer{}; QuerySystemInformation query{};
    const char* failure{}; DWORD missing{}; ULONG status{},observed{},length{};
    ~NativeThreadAudit() { if (buffer) VirtualFree(buffer,0,MEM_RELEASE); }
    bool Prepare(std::string& reason) {
        if (buffer) { reason="independent audit already prepared"; return false; }
        query=reinterpret_cast<QuerySystemInformation>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"NtQuerySystemInformation"));
        if (!query) { reason="independent system thread query unavailable"; return false; }
        buffer=static_cast<std::uint8_t*>(VirtualAlloc(nullptr,kBytes,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE));
        if (!buffer) { reason="independent thread audit buffer allocation failed"; return false; }
        std::memset(buffer,0,kBytes); reason.clear(); return true;
    }
    bool Check(const DWORD* ids,std::size_t count) noexcept {
        static_assert(sizeof(SYSTEM_PROCESS_INFORMATION)==0x100 && sizeof(SYSTEM_THREAD_INFORMATION)==0x50);
        static_assert(offsetof(SYSTEM_PROCESS_INFORMATION,UniqueProcessId)==0x50 &&
            offsetof(SYSTEM_THREAD_INFORMATION,ClientId)==0x28);
        failure=nullptr; missing=0; status=0; observed=0; length=0;
        const auto own=GetCurrentThreadId(),process=GetCurrentProcessId();
        if (!buffer || !query || count>512 || (count && !ids)) { failure="invalid independent audit inputs"; return false; }
        for (std::size_t i=0;i<count;++i) {
            if (!ids[i] || ids[i]==own) { failure="invalid suspended thread ID in audit"; return false; }
            for (std::size_t j=0;j<i;++j) if (ids[i]==ids[j]) { failure="duplicate suspended thread ID in audit"; return false; }
        }
        // This buffer and every data structure were allocated before suspension.
        // SystemProcessInformation lists threads independently of access-granted
        // NtGetNextThread handles. Do not skip any state based on a guessed exit.
        status=static_cast<ULONG>(query(5,buffer,kBytes,&length));
        if (status || length<sizeof(SYSTEM_PROCESS_INFORMATION) || length>kBytes) {
            failure="independent system thread query failed or exceeded fixed buffer"; return false;
        }
        for (std::size_t offset=0;offset<length;) {
            if (length-offset<sizeof(SYSTEM_PROCESS_INFORMATION)) { failure="truncated system process header"; return false; }
            SYSTEM_PROCESS_INFORMATION header{}; std::memcpy(&header,buffer+offset,sizeof(header));
            const auto extent=header.NextEntryOffset?static_cast<std::size_t>(header.NextEntryOffset):length-offset;
            if (extent<sizeof(header) || extent>length-offset || (header.NextEntryOffset && (extent&7))) {
                failure="invalid system process chain extent"; return false;
            }
            if (reinterpret_cast<std::uintptr_t>(header.UniqueProcessId)==process) {
                if (!header.NumberOfThreads || header.NumberOfThreads>513 ||
                    header.NumberOfThreads>(extent-sizeof(header))/sizeof(SYSTEM_THREAD_INFORMATION)) {
                    failure="invalid current-process system thread count"; return false;
                }
                std::array<bool,512> seen{}; std::array<DWORD,513> kernel_ids{}; bool own_seen=false;
                observed=header.NumberOfThreads;
                for (ULONG i=0;i<header.NumberOfThreads;++i) {
                    SYSTEM_THREAD_INFORMATION row{};
                    std::memcpy(&row,buffer+offset+sizeof(header)+i*sizeof(row),sizeof(row));
                    const auto raw_id=reinterpret_cast<std::uintptr_t>(row.ClientId.UniqueThread);
                    if (!raw_id || raw_id>MAXDWORD || reinterpret_cast<std::uintptr_t>(row.ClientId.UniqueProcess)!=process) {
                        failure="invalid system thread identity"; return false;
                    }
                    const auto id=static_cast<DWORD>(raw_id);
                    for (ULONG j=0;j<i;++j) if (kernel_ids[j]==id) { failure="duplicate system thread identity"; return false; }
                    kernel_ids[i]=id;
                    if (id==own) { own_seen=true; continue; }
                    bool matched=false;
                    for (std::size_t j=0;j<count;++j) if (ids[j]==id) { seen[j]=true; matched=true; break; }
                    if (!matched) { missing=id; failure="system thread was not captured and suspended"; return false; }
                }
                if (!own_seen) { failure="installer thread absent from system audit"; return false; }
                for (std::size_t i=0;i<count;++i) if (!seen[i]) {
                    missing=ids[i]; failure="captured thread absent from independent system audit"; return false;
                }
                return true;
            }
            if (!header.NextEntryOffset) break;
            offset+=extent;
        }
        failure="current process absent from independent system audit"; return false;
    }
};
struct UnsafeCodeRange { std::uintptr_t begin{},end{}; };
using QueryThreadInformation = LONG (NTAPI*)(HANDLE,ULONG,PVOID,ULONG,PULONG);
struct NativeStackGuard {
    QueryThreadInformation query{}; const char* failure{};
    std::uintptr_t hit_location{},hit_value{}; DWORD error{}; ULONG status{};
    bool Prepare(std::string& reason) {
        query=reinterpret_cast<QueryThreadInformation>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"NtQueryInformationThread"));
        if (!query) { reason="native thread stack bounds unavailable"; return false; }
        reason.clear(); return true;
    }
    bool Scan(std::uintptr_t cursor,std::uintptr_t bottom,std::uintptr_t top,const UnsafeCodeRange* ranges,std::size_t count) noexcept {
        if (count>128 || (count && !ranges)) { failure="invalid stack interval list"; return false; }
        for (std::size_t i=0;i<count;++i) if (!ranges[i].begin || ranges[i].begin>=ranges[i].end) {
            failure="invalid stack code range"; return false;
        }
        const auto unsafe=[&](std::uintptr_t value) noexcept {
            for (std::size_t i=0;i<count;++i) if (value>=ranges[i].begin && value<ranges[i].end) return true;
            return false;
        };
        if (!bottom || bottom>=top || cursor<bottom || cursor>=top || (cursor&7) || (top&7) || top-cursor>8*1024*1024) {
            failure="stack guard RSP outside bounded active TIB stack"; return false;
        }
        std::array<std::uintptr_t,256> words{};
        while (cursor<top) {
            MEMORY_BASIC_INFORMATION memory{};
            if (VirtualQuery(reinterpret_cast<void*>(cursor),&memory,sizeof(memory))!=sizeof(memory) ||
                memory.State!=MEM_COMMIT || (memory.Protect&(PAGE_NOACCESS|PAGE_GUARD))) {
                error=GetLastError(); failure="stack guard encountered unreadable or guard page"; return false;
            }
            const auto region=reinterpret_cast<std::uintptr_t>(memory.BaseAddress);
            if (region>cursor || memory.RegionSize>UINTPTR_MAX-region || region+memory.RegionSize<=cursor) {
                failure="stack guard memory extent invalid"; return false;
            }
            const auto bytes=std::min({top-cursor,region+memory.RegionSize-cursor,sizeof(words)});
            if (!bytes || (bytes&7) || !ReadSpan(cursor,words.data(),bytes)) {
                error=GetLastError(); failure="stack guard active stack read failed"; return false;
            }
            for (std::size_t i=0;i<bytes/sizeof(words[0]);++i) if (unsafe(words[i])) {
                hit_location=cursor+i*sizeof(words[0]); hit_value=words[i];
                failure="active stack retains an old-snapshot code address"; return false;
            }
            cursor+=bytes;
        }
        // This is conservative active-native-stack evidence, not a full proof:
        // dormant fibers/JIT-managed continuations and escaped data pointers are
        // separate installation gates. Do not set quiescence_proven from this.
        return true;
    }
    bool CheckOwn(std::uintptr_t return_slot,const UnsafeCodeRange* ranges,std::size_t count) noexcept {
        failure=nullptr; hit_location=hit_value=0; error=status=0;
        if (!query || IsThreadAFiber()) { failure="installer stack unavailable or uses unsupported fiber"; return false; }
        NT_TIB tib{};
        if (!ReadSpan(reinterpret_cast<std::uintptr_t>(NtCurrentTeb()),&tib,sizeof(tib))) {
            error=GetLastError(); failure="installer TIB unreadable"; return false;
        }
        // Include the immediate caller's saved return address, but exclude
        // installer locals below it (which contain deliberate patch addresses).
        return Scan(return_slot,reinterpret_cast<std::uintptr_t>(tib.StackLimit),reinterpret_cast<std::uintptr_t>(tib.StackBase),ranges,count);
    }
    bool Check(HANDLE thread,const UnsafeCodeRange* ranges,std::size_t count) noexcept {
        struct Basic { LONG exit_status{}; PVOID teb{}; CLIENT_ID client{}; ULONG_PTR affinity{}; LONG priority{},base_priority{}; } basic;
        static_assert(sizeof(Basic)==48 && offsetof(Basic,teb)==8 && offsetof(NT_TIB,StackBase)==8);
        failure=nullptr; hit_location=hit_value=0; error=status=0;
        if (!query || !thread || count>128 || (count && !ranges)) { failure="invalid stack guard inputs"; return false; }
        for (std::size_t i=0;i<count;++i) if (!ranges[i].begin || ranges[i].begin>=ranges[i].end) {
            failure="invalid unsafe code interval"; return false;
        }
        const auto unsafe=[&](std::uintptr_t value) noexcept {
            for (std::size_t i=0;i<count;++i) if (value>=ranges[i].begin && value<ranges[i].end) return true;
            return false;
        };
        CONTEXT context{}; context.ContextFlags=CONTEXT_CONTROL;
        if (!GetThreadContext(thread,&context)) { error=GetLastError(); failure="stack guard context unavailable"; return false; }
        if (unsafe(static_cast<std::uintptr_t>(context.Rip))) {
            hit_value=static_cast<std::uintptr_t>(context.Rip); failure="thread is executing old-snapshot code"; return false;
        }
        ULONG returned{}; status=static_cast<ULONG>(query(thread,0,&basic,sizeof(basic),&returned));
        if (status || (returned && returned!=sizeof(basic)) || !basic.teb ||
            reinterpret_cast<std::uintptr_t>(basic.client.UniqueProcess)!=GetCurrentProcessId() ||
            reinterpret_cast<std::uintptr_t>(basic.client.UniqueThread)==GetCurrentThreadId()) {
            failure="stack guard thread bounds query failed or not a suspended peer"; return false;
        }
        NT_TIB tib{};
        if (!ReadSpan(reinterpret_cast<std::uintptr_t>(basic.teb),&tib,sizeof(tib)) || tib.Self!=basic.teb) {
            error=GetLastError(); failure="stack guard TIB unreadable or inconsistent"; return false;
        }
        return Scan(static_cast<std::uintptr_t>(context.Rsp),reinterpret_cast<std::uintptr_t>(tib.StackLimit),
            reinterpret_cast<std::uintptr_t>(tib.StackBase),ranges,count);
    }
};
// Preparation owns vectors; Apply uses fixed buffers only. Caller must already
// hold an independently audited freeze and reject old native snapshot frames.
struct LegacySwitchTransaction {
    enum class Dialect { Original,Replacement,Unknown };
    struct Page { std::uintptr_t address{}; DWORD protection{}; bool writable{}; };
    std::array<MemoryPatch,15> sites{}; std::array<Page,32> pages{}; std::size_t page_count{};
    bool ready{},resume_safe{true}; Dialect dialect{Dialect::Original}; const char* failure{};
    bool Prepare(const MemoryPatch& constructor,const std::vector<MemoryPatch>& loads,std::string& reason) {
        constexpr std::array<std::uint8_t,8> original{0x48,0x89,0x5C,0x24,0x20,0x56,0x48,0x83};
        if (ready || loads.size()!=14 || !constructor.address || (constructor.address&7) ||
            constructor.expected.size()!=8 || constructor.replacement.size()!=8 ||
            std::memcmp(constructor.expected.data(),original.data(),8) || constructor.replacement[0]!=0xE9 ||
            constructor.replacement[5]!=0x90 || constructor.replacement[6]!=0x90 || constructor.replacement[7]!=0x90) {
            reason="invalid coupled constructor/load transaction"; return false;
        }
        SYSTEM_INFO system{}; GetSystemInfo(&system);
        if (system.dwPageSize!=4096) { reason="unsupported coupled switch pages"; return false; }
        for (std::size_t i=0;i<14;++i) {
            std::vector<std::uint8_t> encoded;
            if (!loads[i].address || !EncodeLegacyIndexLoad(loads[i].expected,encoded,reason) || encoded!=loads[i].replacement) {
                reason="coupled load does not match exact stack LEA-to-MOV encoding"; return false;
            }
            sites[i]=loads[i];
        }
        // Publish the constructor last; rollback runs in reverse order.
        sites[14]=constructor; page_count=0;
        for (std::size_t i=0;i<sites.size();++i) {
            const auto& patch=sites[i]; const auto bytes=patch.expected.size();
            if (bytes>15 || patch.address>UINTPTR_MAX-bytes) { reason="invalid coupled instruction span"; return false; }
            for (std::size_t j=0;j<i;++j) if (patch.address<sites[j].address+sites[j].expected.size() &&
                sites[j].address<patch.address+bytes) { reason="overlapping coupled switch sites"; return false; }
            std::array<std::uint8_t,15> actual{};
            if (!ReadSpan(patch.address,actual.data(),bytes) || std::memcmp(actual.data(),patch.expected.data(),bytes)) {
                reason="coupled switch expected instruction differs"; return false;
            }
            for (auto page=patch.address&~std::uintptr_t{4095};page<patch.address+bytes;page+=4096) {
                bool found=false; for (std::size_t j=0;j<page_count;++j) found|=pages[j].address==page;
                if (found) continue;
                MEMORY_BASIC_INFORMATION memory{};
                if (page_count==pages.size() || VirtualQuery(reinterpret_cast<void*>(page),&memory,sizeof(memory))!=sizeof(memory) ||
                    memory.State!=MEM_COMMIT || memory.Protect!=PAGE_EXECUTE_READ) {
                    reason="coupled switch page is not committed RX"; return false;
                }
                pages[page_count++]={page,memory.Protect,false};
            }
        }
        ready=true; reason.clear(); return true;
    }
    bool Matches(bool replacement) noexcept {
        for (const auto& site:sites) {
            std::array<std::uint8_t,15> actual{}; const auto& desired=replacement?site.replacement:site.expected;
            if (!ReadSpan(site.address,actual.data(),desired.size()) || std::memcmp(actual.data(),desired.data(),desired.size())) return false;
        }
        return true;
    }
    bool Exchange(std::size_t i,bool undo) noexcept {
        const auto& site=sites[i]; const auto& before=undo?site.replacement:site.expected;
        const auto& after=undo?site.expected:site.replacement;
        if (i==14) {
            LONG64 expected{},desired{}; std::memcpy(&expected,before.data(),8); std::memcpy(&desired,after.data(),8);
            return _InterlockedCompareExchange64(reinterpret_cast<volatile LONG64*>(site.address),desired,expected)==expected;
        }
        return _InterlockedCompareExchange8(reinterpret_cast<volatile char*>(site.address+1),static_cast<char>(after[1]),
            static_cast<char>(before[1]))==static_cast<char>(before[1]);
    }
    bool RestorePages() noexcept {
        bool restored=true;
        for (std::size_t i=page_count;i>0;--i) if (pages[i-1].writable) {
            auto& page=pages[i-1]; DWORD old{};
            if (VirtualProtect(reinterpret_cast<void*>(page.address),4096,page.protection|PAGE_TARGETS_NO_UPDATE,&old)) page.writable=false;
            else restored=false;
        }
        return restored;
    }
    bool SiteWritable(std::size_t i) const noexcept {
        const auto address=(sites[i].address+(i==14?0:1))&~std::uintptr_t{4095};
        for (std::size_t j=0;j<page_count;++j) if (pages[j].address==address) return pages[j].writable;
        return false;
    }
    bool Apply(int fail_after_write=-1) noexcept {
        failure=nullptr; resume_safe=true;
        if (!ready || dialect!=Dialect::Original) { failure="coupled switch is not prepared in original dialect"; return false; }
        if (!Matches(false)) { failure="coupled switch bytes changed before synchronized write"; return false; }
        std::size_t written{};
        const auto reject=[&](const char* message) noexcept {
            failure=message; bool recovered=true;
            if (written) {
                // Protection restoration may have failed after some pages were
                // already restored. Make every mutated page writable again.
                for (std::size_t i=0;i<page_count;++i) if (!pages[i].writable) {
                    DWORD old{};
                    if (VirtualProtect(reinterpret_cast<void*>(pages[i].address),4096,
                        PAGE_EXECUTE_READWRITE|PAGE_TARGETS_NO_UPDATE,&old)) pages[i].writable=true;
                    else recovered=false;
                }
                while (written) { const auto i=--written;
                    if (!SiteWritable(i) || !Exchange(i,true)) recovered=false;
                }
            }
            const bool original=Matches(false),replacement=Matches(true);
            dialect=original?Dialect::Original:(replacement?Dialect::Replacement:Dialect::Unknown);
            const bool flushed=FlushInstructionCache(GetCurrentProcess(),nullptr,0)!=FALSE;
            const bool protected_ok=RestorePages();
            resume_safe=recovered && original && flushed && protected_ok;
            // Unknown/mixed dialect is a hard stop for a future installer. A
            // retained context alone is not permission to resume old consumers.
            return false;
        };
        for (std::size_t i=0;i<page_count;++i) {
            DWORD old{}; auto& page=pages[i];
            if (!VirtualProtect(reinterpret_cast<void*>(page.address),4096,PAGE_EXECUTE_READWRITE|PAGE_TARGETS_NO_UPDATE,&old))
                return reject("coupled switch page protection failed");
            page.writable=true;
            if (old!=page.protection) { page.protection=old; return reject("coupled switch protection changed during preparation"); }
        }
        for (std::size_t i=0;i<sites.size();++i) {
            if (!Exchange(i,false)) return reject("coupled instruction atomic replacement refused");
            ++written;
            if (fail_after_write>=0 && written==static_cast<std::size_t>(fail_after_write)) return reject("injected coupled switch write failure");
        }
        if (!Matches(true)) return reject("coupled switch replacement verification failed");
        if (!FlushInstructionCache(GetCurrentProcess(),nullptr,0)) return reject("coupled switch cache flush failed");
        if (!RestorePages()) return reject("coupled switch protection restoration failed");
        dialect=Dialect::Replacement; resume_safe=true; return true;
    }
};
bool AtomicInstall(HookSet& hooks,bool undo,std::string& reason,int fail_after_write=-1) {
    struct Page { std::uintptr_t address{}; DWORD protect{}; bool changed{}; };
    std::array<Page,kHookCount> pages{}; std::size_t page_count{};
    for (std::size_t i=0;i<kHookCount;++i) {
        const auto address=hooks.entries[i]&~std::uintptr_t{4095};
        bool found=false; for (std::size_t j=0;j<page_count;++j) found|=pages[j].address==address;
        if (found) continue;
        MEMORY_BASIC_INFORMATION memory{};
        if (VirtualQuery(reinterpret_cast<void*>(address),&memory,sizeof(memory))!=sizeof(memory) || memory.State!=MEM_COMMIT ||
            (memory.Protect&0xFF)!=PAGE_EXECUTE_READ) { reason="entry page is not executable read-only memory"; return false; }
        pages[page_count++]={address,memory.Protect,false};
    }
    std::array<LONG64,kHookCount> expected{},desired{};
    for (std::size_t i=0;i<kHookCount;++i) {
        std::memcpy(&expected[i],undo?hooks.replacement[i].data():kPrefixes[i].data(),8);
        std::memcpy(&desired[i],undo?kPrefixes[i].data():hooks.replacement[i].data(),8);
    }
    const auto next=reinterpret_cast<NextThread>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"NtGetNextThread"));
    NativeThreadAudit audit; if (!audit.Prepare(reason)) return false;
    std::array<DWORD,512> audited_ids{};
    const char* failure=nullptr; std::size_t written{}; bool recovered=true;
    {
        ThreadFreeze frozen(next);
        if (!frozen.Capture(hooks)) failure=frozen.failure;
        if (!failure) {
            for (std::size_t i=0;i<frozen.count;++i) audited_ids[i]=frozen.held[i].id;
            frozen.diagnostic.coverage_checked=audit.Check(audited_ids.data(),frozen.count);
            frozen.diagnostic.system_threads=audit.observed;
            if (!frozen.diagnostic.coverage_checked) {
                failure=audit.failure; frozen.diagnostic.failed_thread_id=audit.missing;
                frozen.diagnostic.native_status=audit.status;
            }
        }
        hooks.sync=frozen.diagnostic; hooks.sync.suspended_threads=static_cast<std::uint32_t>(frozen.count);
        // No heap allocations, strings, logging or Source callbacks until all
        // held threads have resumed. Every byte write is aligned and atomic.
        if (!failure) {
            for (std::size_t i=0;i<kHookCount;++i) {
                LONG64 actual{};
                if (!ReadSpan(hooks.entries[i],&actual,8) || actual!=expected[i]) { failure="entry bytes changed before synchronized write"; break; }
            }
        }
        if (!failure) for (std::size_t p=0;p<page_count;++p) {
            DWORD old{};
            if (!VirtualProtect(reinterpret_cast<void*>(pages[p].address),4096,PAGE_EXECUTE_READWRITE|PAGE_TARGETS_NO_UPDATE,&old)) {
                failure="entry page cannot be made writable"; break;
            }
            pages[p].changed=true;
            if (old!=pages[p].protect) { pages[p].protect=old; failure="entry protection changed during preparation"; break; }
        }
        if (!failure) for (std::size_t i=0;i<kHookCount;++i) {
            if (_InterlockedCompareExchange64(reinterpret_cast<volatile LONG64*>(hooks.entries[i]),desired[i],expected[i])!=expected[i]) {
                failure="atomic entry replacement refused"; break;
            }
            ++written;
            if (fail_after_write>=0 && written==static_cast<std::size_t>(fail_after_write)) {
                failure="injected atomic write failure"; break;
            }
        }
        if (!failure && !FlushInstructionCache(GetCurrentProcess(),nullptr,0)) failure="entry cache flush failed";
        if (!failure) for (std::size_t p=0;p<page_count;++p) if (pages[p].changed) {
            DWORD ignored{};
            if (!VirtualProtect(reinterpret_cast<void*>(pages[p].address),4096,pages[p].protect|PAGE_TARGETS_NO_UPDATE,&ignored)) {
                failure="entry protection restoration failed"; break;
            }
            pages[p].changed=false;
        }
        if (failure && written) {
            for (std::size_t p=0;p<page_count;++p) {
                DWORD ignored{};
                if (VirtualProtect(reinterpret_cast<void*>(pages[p].address),4096,PAGE_EXECUTE_READWRITE|PAGE_TARGETS_NO_UPDATE,&ignored)) pages[p].changed=true;
                else recovered=false;
            }
            if (recovered) while (written) {
                const auto i=--written;
                if (_InterlockedCompareExchange64(reinterpret_cast<volatile LONG64*>(hooks.entries[i]),expected[i],desired[i])!=desired[i]) recovered=false;
            }
            if (!FlushInstructionCache(GetCurrentProcess(),nullptr,0)) recovered=false;
        }
        for (std::size_t p=0;p<page_count;++p) if (pages[p].changed) {
            DWORD ignored{};
            if (!VirtualProtect(reinterpret_cast<void*>(pages[p].address),4096,pages[p].protect|PAGE_TARGETS_NO_UPDATE,&ignored)) recovered=false;
        }
        if (!frozen.Release()) {
            recovered=false; failure="thread resumption could not be confirmed";
            const auto suspended=hooks.sync.suspended_threads;
            hooks.sync=frozen.diagnostic; hooks.sync.suspended_threads=suspended;
        }
        // If restoration is unconfirmed, code and context must remain alive.
        if (!recovered) hooks.retained=true;
    }
    if (failure || !recovered) {
        reason=failure?failure:"entry rollback failed";
        if (hooks.sync.failed_thread_id || hooks.sync.win32_error || hooks.sync.native_status) {
            reason+=" (thread="+std::to_string(hooks.sync.failed_thread_id)+", Win32="+std::to_string(hooks.sync.win32_error)+
                ", NTSTATUS="+std::to_string(hooks.sync.native_status)+")";
        }
        if (!recovered) reason+="; gateway resources retained because rollback was not confirmed";
        return false;
    }
    reason.clear(); return true;
}
bool CheckUnwind(const HookSet& hooks,std::string& reason) {
    for (std::size_t i=0;i<kHookCount;++i) for (const auto point:{i==3?2u:3u,static_cast<unsigned>(kLengths[i]),static_cast<unsigned>(kLengths[i]+10u)}) {
        const bool after=point>=kLengths[i];
        std::array<std::uint64_t,400> stack{};
        auto* entry=&stack[320]; entry[0]=0x123456789ABCDEF0ull;
        entry[-1]=0xABCDEF0123456789ull;
        CONTEXT context{}; context.ContextFlags=CONTEXT_FULL;
        context.Rip=reinterpret_cast<DWORD64>(hooks.page)+kGateways[i]+point;
        const auto stack_adjust=i==1?0x908u:(i==3?0x68u:8u);
        context.Rsp=reinterpret_cast<DWORD64>(entry)-(after?stack_adjust:(i==3?8u:0u));
        context.Rbp=0x55; context.Rdi=0x66;
        DWORD64 image{};
        const auto function=RtlLookupFunctionEntry(context.Rip,&image,nullptr);
        if (!function || function->BeginAddress!=kGateways[i] || image!=reinterpret_cast<DWORD64>(hooks.page)) {
            reason="gateway unwind lookup failed"; return false;
        }
        PVOID handler{}; DWORD64 frame{};
        RtlVirtualUnwind(UNW_FLAG_NHANDLER,image,context.Rip,function,&context,&handler,&frame,nullptr);
        if (context.Rip!=entry[0] || context.Rsp!=reinterpret_cast<DWORD64>(entry+1) ||
            (after && i==0 && context.Rbp!=entry[-1]) || (after && i==2 && context.Rdi!=entry[-1]) ||
            (i==3 && context.R13!=entry[-1])) {
            reason="gateway partial-prologue unwind differs: index="+std::to_string(i)+
                " after="+std::to_string(after)+" rip="+std::to_string(context.Rip)+
                " expected="+std::to_string(entry[0])+" rsp_delta="+
                std::to_string(static_cast<std::int64_t>(context.Rsp)-reinterpret_cast<std::int64_t>(entry+1)); return false;
        }
    }
    reason.clear(); return true;
}

using FrameEntry=void (*)(std::int64_t,std::uint8_t);
using OwnerEntry=void (*)(OriginalSnapshot*);
using PaintEntry=void (*)(OriginalSnapshot*,std::int64_t,std::int32_t,std::int32_t,std::int32_t);
using BackendEntry=void (*)(OriginalSnapshot*,std::int64_t,std::int32_t);
struct FrameContext {
    HookSet hooks;
    NativeAudioBindings audio{};
    NativePaintBindings paint{};
    std::uintptr_t base{};
    NativeStorageView original_storage{};
    std::atomic<const NativeStorageView*> storage{};
    std::atomic<bool> armed{};
    std::atomic<std::uint64_t> frames{},preprocessed{},backend_calls{},paint_calls{},mixed{},freed{},errors{},fallback_paints{};
    std::atomic<std::int32_t> last_input{},last_retained{};
    std::string last_error;
    FrameEntry frame() const noexcept { return reinterpret_cast<FrameEntry>(hooks.page+kGateways[0]); }
    OwnerEntry owner() const noexcept { return reinterpret_cast<OwnerEntry>(hooks.page+kGateways[1]); }
    PaintEntry painter() const noexcept { return reinterpret_cast<PaintEntry>(hooks.page+kGateways[2]); }
    BackendEntry backend() const noexcept { return reinterpret_cast<BackendEntry>(hooks.page+kGateways[3]); }
};
std::atomic<FrameContext*> g_frame{};
struct LegacyBridgeContext {
    std::uintptr_t base{};
    NativeLegacyConstructorContext constructor{};
    NativeLegacyConstructorThunk thunk;
    LegacySnapshotGateway gateway;
    LegacySwitchTransaction transaction;
    std::vector<MemoryPatch> patches;
    std::array<UnsafeCodeRange,16> unsafe{};
    std::atomic<bool> active{},fatal{};
    bool stacks_checked{},fail_stop_enabled{};
    ThreadSyncDiagnostic sync{};
    std::uintptr_t guard_stack_address{},guard_code_address{};
    std::string last_error;
    void Retain() noexcept { thunk.RetainForProcessLifetime(); gateway.RetainForProcessLifetime(); }
};
std::atomic<LegacyBridgeContext*> g_legacy{};
struct StorageBridgeContext {
    std::uintptr_t base{};
    NearChannelStorage storage;
    NativeStorageView view{};
    PreparedPatchTransaction transaction;
    std::vector<MemoryPatch> registry;
    std::array<UnsafeCodeRange,256> unsafe{}; std::size_t unsafe_count{};
    std::atomic<bool> active{},fatal{};
    bool stacks_checked{}; ThreadSyncDiagnostic sync{};
    std::uintptr_t hit_stack{},hit_code{};
    std::string error;
};
std::atomic<StorageBridgeContext*> g_storage{};
struct CapacityBridgeContext {
    std::uintptr_t base{}; NativeStorageView view{};
    PreparedPatchTransaction transaction; std::vector<MemoryPatch> registry;
    std::atomic<bool> active{},fatal{}; bool stacks_checked{};
    ThreadSyncDiagnostic sync{}; std::string error;
};
std::atomic<CapacityBridgeContext*> g_capacity{};


struct SoundLock {
    CRITICAL_SECTION* cs;
    explicit SoundLock(std::uintptr_t base):cs(reinterpret_cast<CRITICAL_SECTION*>(base+0x510D50)) { EnterCriticalSection(cs); }
    ~SoundLock() { LeaveCriticalSection(cs); }
};
struct WaitEvents { HANDLE ready{},done{}; };
DWORD WINAPI NativeWaiter(void* data) {
    const auto* events=static_cast<WaitEvents*>(data);
    SetEvent(events->ready); WaitForSingleObject(events->done,INFINITE); return 0;
}
struct MarkedWait { HANDLE ready{},done{}; std::uintptr_t return_address{}; volatile LONG completed{}; };
__declspec(noinline) void MarkedNativeWait(MarkedWait* data) {
    data->return_address=reinterpret_cast<std::uintptr_t>(_ReturnAddress());
    SetEvent(data->ready); WaitForSingleObject(data->done,INFINITE);
}
__declspec(noinline) DWORD WINAPI MarkedNativeRoot(void* data) {
    auto* marked=static_cast<MarkedWait*>(data); MarkedNativeWait(marked);
    InterlockedIncrement(&marked->completed); return 0;
}

struct FrameScope;
thread_local FrameScope* t_frame{};
struct FrameScope {
    FrameContext& context;
    NativeSnapshotOwner owner;
    OriginalSnapshot* shell{};
    FrameScope* previous{};
    bool prepared{},failed{};
    explicit FrameScope(FrameContext& c):context(c),owner(c.audio),previous(t_frame) { t_frame=this; }
    ~FrameScope() { t_frame=previous; }
};
void FrameFailure(FrameScope& scope,const std::string& reason) {
    if (!scope.failed) ++scope.context.errors;
    scope.failed=true; scope.owner.snapshot.count=0;
    if (scope.shell) scope.shell->count=0;
    scope.context.last_error=reason;
}
void LiveFrame(std::int64_t end,std::uint8_t flag) {
    auto* context=g_frame.load();
    if (!context) return; // No hook is exposed before this pointer is published.
    SoundLock locked(context->base);
    if (!context->armed.load()) { context->frame()(end,flag); return; }
    FrameScope scope(*context); ++context->frames;
    context->frame()(end,flag);
}
void LiveOwner(OriginalSnapshot* shell) {
    auto* context=g_frame.load(); if (!context) return;
    const auto view=CurrentNativeStorageView(context->base);
    auto* scope=t_frame;
    if (!context->armed.load() || !scope || scope->prepared || scope->shell) { context->owner()(shell); return; }
    scope->shell=shell;
    // Original frame initializes this vector empty before calling its owner.
    // Do not erase an unexpectedly owned object and silently leak it.
    if (!shell || shell->auxiliary_routes.memory || shell->auxiliary_routes.elements ||
        shell->auxiliary_routes.size || shell->auxiliary_routes.allocation_count) {
        FrameFailure(*scope,"original frame shell already owns routing"); return;
    }
    std::string reason;
    try {
        std::int32_t count{};
        if (!ReadSpan(reinterpret_cast<std::uintptr_t>(view.active_count),&count,4) || !scope->owner.Build(
            view.active_indices,count,view.capacity,reason)) {
            FrameFailure(*scope,reason.empty()?"cannot build live frame snapshot":reason); return;
        }
        NativePreprocessSample sample{};
        const auto good=PreprocessNativeMix(context->paint.preprocess,view.channels,
            view.capacity,scope->owner.snapshot,sample,reason);
        context->last_input=sample.input_count; context->last_retained=sample.retained; context->freed+=sample.freed;
        if (!good || !ProjectMixShell(scope->owner.snapshot,*shell,true,reason)) { FrameFailure(*scope,reason); return; }
        scope->prepared=true; ++context->preprocessed;
    } catch (const std::exception& e) { FrameFailure(*scope,e.what()); }
}
void LivePaint(OriginalSnapshot* shell,std::int64_t end,std::int32_t route,std::int32_t source_rate,std::int32_t input_rate) {
    auto* context=g_frame.load(); if (!context) return;
    const auto view=CurrentNativeStorageView(context->base);
    auto* scope=t_frame;
    if (!context->armed.load() || !scope || scope->shell!=shell) {
        ++context->fallback_paints; context->painter()(shell,end,route,source_rate,input_rate); return;
    }
    if (!scope->prepared || scope->failed) return;
    ++context->paint_calls; std::string reason;
    try {
        NativePaintSample sample{};
        const auto good=PaintNativeMix(context->paint,view.channels,
            view.capacity,scope->owner.snapshot,end,route,source_rate,input_rate,sample,reason);
        context->mixed+=sample.mixed; context->freed+=sample.freed;
        if (!good || !ProjectMixShell(scope->owner.snapshot,*shell,false,reason)) FrameFailure(*scope,reason);
    } catch (const std::exception& e) { FrameFailure(*scope,e.what()); }
}
void LiveBackend(OriginalSnapshot* shell,std::int64_t end,std::int32_t samples) {
    auto* context=g_frame.load(); if (!context) return;
    const auto view=CurrentNativeStorageView(context->base);
    auto* scope=t_frame;
    if (!context->armed.load() || !scope || scope->shell!=shell) { context->backend()(shell,end,samples); return; }
    if (!scope->prepared || scope->failed) return;
    ++context->backend_calls; std::string reason;
    try {
        NativeBackendSample sample{};
        const auto good=PaintNativeBackend(context->paint,view.channels,
            view.capacity,scope->owner.snapshot,*shell,end,samples,sample,reason);
        context->paint_calls+=sample.paint_calls; context->mixed+=sample.mixed; context->freed+=sample.freed;
        if (!good) FrameFailure(*scope,reason);
    } catch (const std::exception& e) { FrameFailure(*scope,e.what()); }
}
}
bool NormalizeRegisteredPatchBytes(const std::vector<MemoryPatch>& patches,std::uintptr_t address,
    std::vector<std::uint8_t>& bytes) noexcept {
    if (!address || address>UINTPTR_MAX-bytes.size() || patches.size()>256) return false;
    const auto end=address+bytes.size();
    // Validate the whole registry and all intersecting spans before changing
    // the caller's copy. Never mask foreign bytes or accept a partial read.
    for (std::size_t i=0;i<patches.size();++i) {
        const auto& p=patches[i];
        if (!p.address || p.expected.empty() || p.expected.size()!=p.replacement.size() || p.address>UINTPTR_MAX-p.expected.size()) return false;
        const auto patch_end=p.address+p.expected.size();
        for (std::size_t j=0;j<i;++j) if (p.address<patches[j].address+patches[j].expected.size() && patches[j].address<patch_end) return false;
        if (address>=patch_end || end<=p.address) continue;
        if (address>p.address || end<patch_end) return false;
        const auto* actual=bytes.data()+(p.address-address);
        if (std::memcmp(actual,p.expected.data(),p.expected.size()) && std::memcmp(actual,p.replacement.data(),p.replacement.size())) return false;
    }
    for (const auto& p:patches) if (address<=p.address && end>=p.address+p.expected.size())
        std::memcpy(bytes.data()+(p.address-address),p.expected.data(),p.expected.size());
    return true;
}
bool RunRegisteredPatchSelfChecks(std::string& reason) {
    constexpr std::uintptr_t base=0x180000000ull;
    const std::vector<MemoryPatch> patches{{base+8,{0x4C,0x8D,0x44,0x24,0x24},{0x4C,0x8B,0x44,0x24,0x24}},
        {base+24,{0x48,0x89,0x5C,0x24,0x20,0x56,0x48,0x83},{0xE9,1,2,3,4,0x90,0x90,0x90}}};
    std::vector<std::uint8_t> original(40,0xCC);
    for (const auto& p:patches) std::copy(p.expected.begin(),p.expected.end(),original.begin()+(p.address-base));
    auto bytes=original;
    for (const auto& p:patches) std::copy(p.replacement.begin(),p.replacement.end(),bytes.begin()+(p.address-base));
    if (!NormalizeRegisteredPatchBytes(patches,base,bytes) || bytes!=original) { reason="registered patches not normalized"; return false; }
    if (!NormalizeRegisteredPatchBytes(patches,base,bytes) || bytes!=original) { reason="original registered spans refused"; return false; }
    std::vector<std::uint8_t> partial(patches[0].replacement.begin(),patches[0].replacement.end()-1);
    const auto saved_partial=partial;
    if (NormalizeRegisteredPatchBytes(patches,base+8,partial) || partial!=saved_partial) { reason="partial instruction span accepted or changed"; return false; }
    bytes=original; std::copy(patches[0].replacement.begin(),patches[0].replacement.end(),bytes.begin()+8);
    bytes[25]^=1; const auto foreign=bytes;
    if (NormalizeRegisteredPatchBytes(patches,base,bytes) || bytes!=foreign) { reason="foreign bytes hidden or partial normalization leaked"; return false; }
    auto overlap=patches; overlap.push_back(patches[0]); bytes=original;
    if (NormalizeRegisteredPatchBytes(overlap,base,bytes) || bytes!=original) { reason="overlapping registered patches accepted"; return false; }
    reason.clear(); return true;
}
bool NormalizeFrameHookBytes(std::uintptr_t address,std::vector<std::uint8_t>& bytes) noexcept {
    const auto* context=g_frame.load();
    if (!context) return true;
    if (address>UINTPTR_MAX-bytes.size()) return false;
    const auto end=address+bytes.size();
    for (std::size_t i=0;i<kHookCount;++i) {
        const auto entry=context->hooks.entries[i];
        if (address>=entry+8 || end<=entry) continue;
        // Normalize only an entire registered span with exactly our live bytes.
        // Never hide a third-party hook or corruption at the same entry.
        if (address>entry || end<entry+8) return false;
        auto* actual=bytes.data()+(entry-address);
        if (!std::memcmp(actual,kPrefixes[i].data(),8)) continue;
        if (std::memcmp(actual,context->hooks.replacement[i].data(),8)) return false;
        std::memcpy(actual,kPrefixes[i].data(),8);
    }
    return true;
}
NativeStorageView CurrentNativeStorageView(std::uintptr_t base) noexcept {
    const auto* context=g_frame.load();
    if (context && context->base==base) if (const auto* view=context->storage.load()) return *view;
    return OriginalNativeStorageView(base);
}
bool NormalizeEngineHookBytes(std::uintptr_t address,std::vector<std::uint8_t>& bytes) noexcept {
    if (!NormalizeFrameHookBytes(address,bytes)) return false;
    const auto* context=g_legacy.load();
    if (context && (context->fatal.load() || !NormalizeRegisteredPatchBytes(context->patches,address,bytes))) return false;
    const auto* storage=g_storage.load();
    if (storage && (storage->fatal.load() || !NormalizeRegisteredPatchBytes(storage->registry,address,bytes))) return false;
    const auto* capacity=g_capacity.load();
    return !capacity || (!capacity->fatal.load() && NormalizeRegisteredPatchBytes(capacity->registry,address,bytes));
}
NativeSnapshotBuilder ResolveOriginalSnapshotBuilder(std::uintptr_t entry) noexcept {
    const auto* context=g_legacy.load();
    if (context && context->base+0x2C110==entry && !context->fatal.load()) return context->constructor.original;
    return reinterpret_cast<NativeSnapshotBuilder>(entry);
}
LegacySnapshotGateway::~LegacySnapshotGateway() noexcept {
    if (retained_) return;
    if (registered_) RtlDeleteFunctionTable(reinterpret_cast<PRUNTIME_FUNCTION>(page_+0x1040));
    if (page_) VirtualFree(reinterpret_cast<void*>(page_),0,MEM_RELEASE);
}
bool LegacySnapshotGateway::Prepare(std::uintptr_t entry,std::uintptr_t target,std::string& reason) {
    constexpr std::array<std::uint8_t,10> prefix{0x48,0x89,0x5C,0x24,0x20,0x56,0x48,0x83,0xEC,0x20};
    // Literal original prologue metadata: RBX save is described at offset10,
    // with stack offset0x48 after push RSI/sub RSP,0x20. Preserve that timing.
    constexpr std::array<std::uint8_t,12> unwind{1,10,4,0,10,0x34,9,0,10,0x32,6,0x60};
    std::array<std::uint8_t,10> actual{};
    if (page_ || !entry || (entry&7) || entry>UINTPTR_MAX-prefix.size() || !target ||
        !ReadSpan(entry,actual.data(),actual.size()) || actual!=prefix) {
        reason="constructor gateway duplicate, alignment or prefix mismatch"; return false;
    }
    SYSTEM_INFO system{}; GetSystemInfo(&system);
    if (system.dwPageSize!=4096 || !system.dwAllocationGranularity) { reason="constructor gateway unsupported pages"; return false; }
    const auto gran=static_cast<std::uintptr_t>(system.dwAllocationGranularity);
    const auto anchor=entry&~(gran-1);
    std::uint8_t* page{};
    for (std::uintptr_t distance=gran;distance<0x70000000 && !page;distance+=gran) {
        for (const bool above:{true,false}) {
            if ((above && anchor>UINTPTR_MAX-distance-8192) || (!above && anchor<distance+gran)) continue;
            page=static_cast<std::uint8_t*>(VirtualAlloc(reinterpret_cast<void*>(above?anchor+distance:anchor-distance),
                8192,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE));
            if (page) break;
        }
    }
    if (!page) { reason="constructor gateway near allocation failed"; return false; }
    struct Release { std::uint8_t* p; bool registered{};
        ~Release() { if (!p) return; if (registered) RtlDeleteFunctionTable(reinterpret_cast<PRUNTIME_FUNCTION>(p+0x1040));
            VirtualFree(p,0,MEM_RELEASE); } } release{page};
    const auto address=reinterpret_cast<std::uintptr_t>(page);
    const auto delta=static_cast<std::int64_t>(address)-static_cast<std::int64_t>(entry+5);
    if (delta<INT32_MIN || delta>INT32_MAX) { reason="constructor gateway branch outside rel32"; return false; }
    std::memset(page,0xCC,4096); AbsoluteJump(page,target);
    std::memcpy(page+0x40,prefix.data(),prefix.size());
    auto* tail=page+0x40+prefix.size(); tail[0]=0x48; tail[1]=0xB8;
    const auto continuation=entry+prefix.size(); std::memcpy(tail+2,&continuation,8); tail[10]=0xFF; tail[11]=0xE0;
    std::memcpy(page+0x1000,unwind.data(),unwind.size());
    const auto table=reinterpret_cast<PRUNTIME_FUNCTION>(page+0x1040); *table={0x40,0x56,0x1000};
    MemoryPatch patch; patch.address=entry; patch.expected.assign(prefix.begin(),prefix.begin()+8);
    patch.replacement={0xE9,0,0,0,0,0x90,0x90,0x90};
    const auto relative=static_cast<std::int32_t>(delta); std::memcpy(patch.replacement.data()+1,&relative,4);
    DWORD old{};
    if (!VirtualProtect(page,4096,PAGE_EXECUTE_READ,&old) || !FlushInstructionCache(GetCurrentProcess(),page,4096) ||
        !VirtualProtect(page+4096,4096,PAGE_READONLY,&old) || !RtlAddFunctionTable(table,1,address)) {
        reason="constructor gateway protection, cache or unwind registration failed"; return false;
    }
    release.registered=true;
    page_=address; registered_=true; patch_=std::move(patch); release.p=nullptr;
    reason.clear(); return true;
}
bool RunLegacyGatewaySelfChecks(std::string& reason) {
    const std::array<std::uint8_t,10> prefix{0x48,0x89,0x5C,0x24,0x20,0x56,0x48,0x83,0xEC,0x20};
    auto* fixture=static_cast<std::uint8_t*>(VirtualAlloc(nullptr,4096,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE));
    if (!fixture) { reason="constructor gateway fixture allocation failed"; return false; }
    struct Release { void* p; ~Release() { VirtualFree(p,0,MEM_RELEASE); } } release{fixture};
    std::memcpy(fixture,prefix.data(),prefix.size());
    const std::array<std::uint8_t,16> continuation{0xB8,17,0,0,0,0x48,0x83,0xC4,0x20,0x5E,0x48,0x8B,0x5C,0x24,0x20,0xC3};
    std::memcpy(fixture+10,continuation.data(),continuation.size());
    DWORD old{};
    if (!VirtualProtect(fixture,4096,PAGE_EXECUTE_READ,&old) || !FlushInstructionCache(GetCurrentProcess(),fixture,4096)) {
        reason="constructor gateway fixture RX protection failed"; return false;
    }
    const auto entry=reinterpret_cast<std::uintptr_t>(fixture);
    std::uintptr_t released{};
    {
    LegacySnapshotGateway gateway;
    if (!gateway.Prepare(entry,entry,reason)) return false;
    released=gateway.original()-0x40;
    MEMORY_BASIC_INFORMATION code{},metadata{};
    if (!VirtualQuery(reinterpret_cast<void*>(released),&code,sizeof(code)) || code.Protect!=PAGE_EXECUTE_READ ||
        !VirtualQuery(reinterpret_cast<void*>(released+0x1000),&metadata,sizeof(metadata)) || metadata.Protect!=PAGE_READONLY) {
        reason="constructor gateway W^X protections differ"; return false;
    }
    const auto& patch=gateway.entry_patch();
    if (patch.address!=entry || patch.expected.size()!=8 || patch.replacement.size()!=8 ||
        std::memcmp(patch.expected.data(),prefix.data(),8) || patch.replacement[0]!=0xE9) {
        reason="constructor gateway entry patch differs"; return false;
    }
    using Call=int (*)();
    std::int32_t relative{}; std::memcpy(&relative,patch.replacement.data()+1,4);
    const auto dispatch=static_cast<std::uintptr_t>(static_cast<std::int64_t>(entry+5)+relative);
    if (dispatch!=released || reinterpret_cast<Call>(dispatch)()!=17 || reinterpret_cast<Call>(gateway.original())()!=17 ||
        std::memcmp(fixture,prefix.data(),prefix.size())) { reason="constructor dispatch/original behavior or untouched entry differs"; return false; }
    for (const unsigned point:{0u,5u,6u,10u,20u}) {
        std::array<std::uint64_t,24> stack{}; auto* entry_stack=&stack[8];
        entry_stack[0]=0x123456789ABCDEF0ull; entry_stack[-1]=0x1122334455667788ull; entry_stack[4]=0x8877665544332211ull;
        CONTEXT context{}; context.ContextFlags=CONTEXT_FULL; context.Rip=gateway.original()+point;
        context.Rsp=reinterpret_cast<DWORD64>(entry_stack)-(point>=10?40u:(point>=6?8u:0u));
        context.Rbx=point>=10?0x55:entry_stack[4]; context.Rsi=point>=6?0x66:entry_stack[-1];
        DWORD64 image{},frame{}; PVOID handler{};
        const auto function=RtlLookupFunctionEntry(context.Rip,&image,nullptr);
        if (!function || function->BeginAddress!=0x40) { reason="constructor gateway unwind lookup failed"; return false; }
        RtlVirtualUnwind(UNW_FLAG_NHANDLER,image,context.Rip,function,&context,&handler,&frame,nullptr);
        if (context.Rip!=entry_stack[0] || context.Rsp!=reinterpret_cast<DWORD64>(entry_stack+1) ||
            context.Rbx!=entry_stack[4] || context.Rsi!=entry_stack[-1]) {
            reason="constructor partial-prologue unwind differs at "+std::to_string(point); return false;
        }
    }
    std::string refused;
    if (gateway.Prepare(entry,entry,refused)) { reason="duplicate constructor gateway accepted"; return false; }
    LegacySnapshotGateway invalid;
    if (invalid.Prepare(entry+8,entry,refused) || invalid.original()) { reason="unaligned constructor prefix accepted"; return false; }
    }
    MEMORY_BASIC_INFORMATION freed{}; DWORD64 image{};
    if (!VirtualQuery(reinterpret_cast<void*>(released),&freed,sizeof(freed)) || freed.State!=MEM_FREE ||
        RtlLookupFunctionEntry(released+0x40,&image,nullptr)) { reason="constructor gateway resources or unwind table leaked"; return false; }
    reason.clear(); return true;
}
bool RunLegacySwitchSelfChecks(std::string& reason) {
    auto* memory=static_cast<std::uint8_t*>(VirtualAlloc(nullptr,8192,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE));
    if (!memory) { reason="coupled switch fixture allocation failed"; return false; }
    struct Owner { void* p; ~Owner() { VirtualFree(p,0,MEM_RELEASE); } } owner{memory};
    const auto base=reinterpret_cast<std::uintptr_t>(memory);
    MemoryPatch constructor{base,{0x48,0x89,0x5C,0x24,0x20,0x56,0x48,0x83},{0xE9,0x1B,0,0,0,0x90,0x90,0x90}};
    std::vector<MemoryPatch> loads;
    std::memcpy(memory,constructor.expected.data(),8);
    for (std::size_t i=0;i<14;++i) {
        MemoryPatch load; load.address=base+(i<7?0:4096)+0x100+(i%7)*32;
        load.expected={0x4C,0x8D,0x44,0x24,static_cast<std::uint8_t>(0x24+i*8)};
        if (!EncodeLegacyIndexLoad(load.expected,load.replacement,reason)) return false;
        std::memcpy(reinterpret_cast<void*>(load.address),load.expected.data(),load.expected.size()); loads.push_back(std::move(load));
    }
    memory[0x80]=0xA5; memory[4096+0x80]=0x5A; DWORD old{};
    if (!VirtualProtect(memory,8192,PAGE_EXECUTE_READ,&old)) { reason="coupled switch fixture RX protection failed"; return false; }
    WaitEvents events{CreateEventW(nullptr,TRUE,FALSE,nullptr),CreateEventW(nullptr,TRUE,FALSE,nullptr)};
    const auto worker=events.ready && events.done?CreateThread(nullptr,0,NativeWaiter,&events,0,nullptr):nullptr;
    struct WorkerOwner { WaitEvents& e; HANDLE worker;
        ~WorkerOwner() { if (e.done) SetEvent(e.done); if (worker) { WaitForSingleObject(worker,5000); CloseHandle(worker); }
            if (e.ready) CloseHandle(e.ready); if (e.done) CloseHandle(e.done); } } worker_owner{events,worker};
    if (!worker || WaitForSingleObject(events.ready,5000)!=WAIT_OBJECT_0) { reason="coupled switch worker did not start"; return false; }
    NativeThreadAudit audit; NativeStackGuard guard;
    if (!audit.Prepare(reason) || !guard.Prepare(reason)) return false;
    HookSet no_entries; std::array<DWORD,512> ids{}; const UnsafeCodeRange range{base,base+8192};
    for (int fail=1;fail<=15;++fail) {
        LegacySwitchTransaction transaction; if (!transaction.Prepare(constructor,loads,reason)) return false;
        const char* failure{};
        {
            ThreadFreeze frozen(reinterpret_cast<NextThread>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"NtGetNextThread")));
            if (!frozen.Capture(no_entries)) failure=frozen.failure;
            else {
                for (std::size_t i=0;i<frozen.count;++i) ids[i]=frozen.held[i].id;
                if (!audit.Check(ids.data(),frozen.count)) failure=audit.failure;
                for (std::size_t i=0;i<frozen.count && !failure;++i) if (!guard.Check(frozen.held[i].handle,&range,1)) failure=guard.failure;
                if (!failure && (transaction.Apply(fail) || transaction.dialect!=LegacySwitchTransaction::Dialect::Original || !transaction.resume_safe ||
                    !transaction.Matches(false))) failure="coupled switch failure did not preserve original dialect";
            }
            if (!frozen.Release()) failure="coupled switch fixture resumption failed";
        }
        if (failure) { reason=failure; return false; }
    }
    LegacySwitchTransaction transaction; if (!transaction.Prepare(constructor,loads,reason)) return false;
    const char* failure{};
    {
        ThreadFreeze frozen(reinterpret_cast<NextThread>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"NtGetNextThread")));
        if (!frozen.Capture(no_entries)) failure=frozen.failure;
        else {
            for (std::size_t i=0;i<frozen.count;++i) ids[i]=frozen.held[i].id;
            if (!audit.Check(ids.data(),frozen.count)) failure=audit.failure;
            for (std::size_t i=0;i<frozen.count && !failure;++i) if (!guard.Check(frozen.held[i].handle,&range,1)) failure=guard.failure;
            if (!failure && (!transaction.Apply() || transaction.dialect!=LegacySwitchTransaction::Dialect::Replacement || !transaction.resume_safe ||
                !transaction.Matches(true))) failure=transaction.failure?transaction.failure:"coupled switch commit mismatch";
        }
        if (!frozen.Release()) failure="coupled switch commit resumption failed";
    }
    MEMORY_BASIC_INFORMATION first{},second{};
    if (failure || !VirtualQuery(memory,&first,sizeof(first)) || !VirtualQuery(memory+4096,&second,sizeof(second)) ||
        first.Protect!=PAGE_EXECUTE_READ || second.Protect!=PAGE_EXECUTE_READ || memory[0x80]!=0xA5 || memory[4096+0x80]!=0x5A) {
        reason=failure?failure:"coupled switch protections or neighbors differ"; return false;
    }
    reason.clear(); return true;
}
__declspec(noinline) bool RunOwnStackGuardSelfChecks(std::string& reason) {
    NativeStackGuard guard; if (!guard.Prepare(reason)) return false;
    const auto slot=reinterpret_cast<std::uintptr_t>(_AddressOfReturnAddress());
    std::uintptr_t caller{}; std::memcpy(&caller,reinterpret_cast<const void*>(slot),8);
    const UnsafeCodeRange old_caller{caller,caller+1};
    if (!guard.CheckOwn(slot,nullptr,0)) { reason=guard.failure; return false; }
    if (guard.CheckOwn(slot,&old_caller,1) || guard.hit_location!=slot || guard.hit_value!=caller) {
        reason="installer guard omitted its immediate caller return slot"; return false;
    }
    reason.clear(); return true;
}
bool RunStackGuardSelfChecks(std::string& reason) {
    NativeStackGuard guard; if (!guard.Prepare(reason)) return false;
    MarkedWait events{CreateEventW(nullptr,TRUE,FALSE,nullptr),CreateEventW(nullptr,TRUE,FALSE,nullptr)};
    const auto worker=events.ready && events.done?CreateThread(nullptr,0,MarkedNativeRoot,&events,0,nullptr):nullptr;
    struct Owner { MarkedWait& e; HANDLE worker;
        ~Owner() { if (e.done) SetEvent(e.done); if (worker) { WaitForSingleObject(worker,5000); CloseHandle(worker); }
            if (e.ready) CloseHandle(e.ready); if (e.done) CloseHandle(e.done); } } owner{events,worker};
    if (!worker || WaitForSingleObject(events.ready,5000)!=WAIT_OBJECT_0 || !events.return_address) {
        reason="marked native stack worker did not start"; return false;
    }
    const auto worker_id=GetThreadId(worker); HookSet no_entries; const char* failure{}; bool tested=false;
    {
        ThreadFreeze frozen(reinterpret_cast<NextThread>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"NtGetNextThread")));
        if (!frozen.Capture(no_entries)) failure=frozen.failure;
        else for (std::size_t i=0;i<frozen.count;++i) if (frozen.held[i].id==worker_id) {
            CONTEXT context{}; context.ContextFlags=CONTEXT_CONTROL;
            const UnsafeCodeRange marked{events.return_address,events.return_address+1};
            if (!GetThreadContext(frozen.held[i].handle,&context)) failure="marked worker context unavailable";
            else if (context.Rip==events.return_address) failure="marked worker did not wait inside a called helper";
            else if (!guard.Check(frozen.held[i].handle,nullptr,0)) failure=guard.failure;
            else if (guard.Check(frozen.held[i].handle,&marked,1) || guard.hit_value!=events.return_address || !guard.hit_location)
                failure="old-frame guard accepted actual live caller return address";
            else {
                const UnsafeCodeRange pc{static_cast<std::uintptr_t>(context.Rip),static_cast<std::uintptr_t>(context.Rip)+1};
                if (guard.Check(frozen.held[i].handle,&pc,1) || guard.hit_value!=context.Rip || guard.hit_location)
                    failure="old-frame guard accepted unsafe current RIP";
                else tested=true;
            }
            break;
        }
        if (!frozen.Release()) failure="stack guard fixture resumption failed";
    }
    if (failure || !tested) { reason=failure?failure:"stack guard worker not captured"; return false; }
    reason.clear(); return true;
}
bool RunThreadAuditSelfChecks(std::string& reason) {
    NativeThreadAudit audit; if (!audit.Prepare(reason)) return false;
    WaitEvents events{CreateEventW(nullptr,TRUE,FALSE,nullptr),CreateEventW(nullptr,TRUE,FALSE,nullptr)};
    const auto worker=events.ready && events.done?CreateThread(nullptr,0,NativeWaiter,&events,0,nullptr):nullptr;
    struct Owner { WaitEvents& e; HANDLE worker;
        ~Owner() { if (e.done) SetEvent(e.done); if (worker) { WaitForSingleObject(worker,5000); CloseHandle(worker); }
            if (e.ready) CloseHandle(e.ready); if (e.done) CloseHandle(e.done); } } owner{events,worker};
    if (!worker || WaitForSingleObject(events.ready,5000)!=WAIT_OBJECT_0) { reason="thread audit worker did not start"; return false; }
    const auto worker_id=GetThreadId(worker);
    HookSet no_entries; std::array<DWORD,512> ids{}; const char* failure{};
    {
        ThreadFreeze frozen(reinterpret_cast<NextThread>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"NtGetNextThread")));
        if (!frozen.Capture(no_entries)) failure=frozen.failure;
        else {
            bool found=false; std::size_t omitted_count{};
            for (std::size_t i=0;i<frozen.count;++i) { ids[i]=frozen.held[i].id; found|=ids[i]==worker_id; }
            if (!found) failure="thread audit fixture worker not captured";
            else if (!audit.Check(ids.data(),frozen.count)) failure=audit.failure;
            else {
                for (std::size_t i=0;i<frozen.count;++i) if (frozen.held[i].id!=worker_id) ids[omitted_count++]=frozen.held[i].id;
                if (audit.Check(ids.data(),omitted_count) || audit.missing!=worker_id) failure="independent audit accepted omitted live worker";
            }
        }
        if (!frozen.Release()) failure="thread audit fixture resumption failed";
    }
    if (failure) { reason=failure; return false; }
    reason.clear(); return true;
}
bool RunFrameBridgeSelfChecks(std::string& reason) {
    auto* fixture=static_cast<std::uint8_t*>(VirtualAlloc(nullptr,4096,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE));
    if (!fixture) { reason="native frame fixture allocation failed"; return false; }
    struct Owner { void* pointer; ~Owner() { VirtualFree(pointer,0,MEM_RELEASE); } } owner{fixture};
    const std::array<std::uint32_t,kHookCount> offsets{0,0x80,0x100,0x180};
    std::array<std::uintptr_t,kHookCount> entries{},targets{};
    for (std::size_t i=0;i<kHookCount;++i) {
        entries[i]=reinterpret_cast<std::uintptr_t>(fixture+offsets[i]);
        std::memcpy(fixture+offsets[i],kPrefixes[i].data(),kLengths[i]);
        auto* tail=fixture+offsets[i]+kLengths[i];
        if (i==0) *tail++=0x5D;
        else if (i==1) { const std::array<std::uint8_t,7> add{0x48,0x81,0xC4,0x08,0x09,0,0}; std::memcpy(tail,add.data(),7); tail+=7; }
        else if (i==2) *tail++=0x5F;
        else { const std::array<std::uint8_t,6> restore{0x48,0x83,0xC4,0x60,0x41,0x5D}; std::memcpy(tail,restore.data(),6); tail+=6; }
        *tail++=0xB8; const auto result=static_cast<std::uint32_t>(17+i); std::memcpy(tail,&result,4); tail[4]=0xC3;
        targets[i]=reinterpret_cast<std::uintptr_t>(fixture+0x200);
    }
    const std::array<std::uint8_t,6> replacement{0xB8,42,0,0,0,0xC3};
    std::memcpy(fixture+0x200,replacement.data(),replacement.size()); DWORD ignored{};
    if (!VirtualProtect(fixture,4096,PAGE_EXECUTE_READ,&ignored) || !FlushInstructionCache(GetCurrentProcess(),fixture,4096)) {
        reason="native frame fixture protection failed"; return false;
    }
    HookSet hooks;
    if (!hooks.Prepare(entries,targets,reason) || !CheckUnwind(hooks,reason)) return false;
    WaitEvents events{CreateEventW(nullptr,TRUE,FALSE,nullptr),CreateEventW(nullptr,TRUE,FALSE,nullptr)};
    const auto worker=events.ready && events.done?CreateThread(nullptr,0,NativeWaiter,&events,0,nullptr):nullptr;
    struct WorkerOwner {
        WaitEvents& events; HANDLE worker;
        ~WorkerOwner() {
            if (events.done) SetEvent(events.done);
            if (worker) { WaitForSingleObject(worker,5000); CloseHandle(worker); }
            if (events.ready) CloseHandle(events.ready); if (events.done) CloseHandle(events.done);
        }
    } worker_owner{events,worker};
    if (!worker || WaitForSingleObject(events.ready,5000)!=WAIT_OBJECT_0) { reason="native worker fixture did not start"; return false; }
    DWORD exit_wait{};
    if (ThreadExitProven(worker,exit_wait) || exit_wait!=WAIT_TIMEOUT || ThreadExitProven(nullptr,exit_wait)) {
        reason="live or invalid thread was classified as exited"; return false;
    }
    const char* freeze_failure=nullptr; bool freeze_ok=false;
    {
        ThreadFreeze frozen(reinterpret_cast<NextThread>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"NtGetNextThread")));
        if (!frozen.Capture(hooks)) freeze_failure=frozen.failure;
        else {
            for (std::size_t p=0;p<frozen.count;++p) if (frozen.held[p].id==GetThreadId(worker)) {
                CONTEXT context{}; context.ContextFlags=CONTEXT_CONTROL;
                if (GetThreadContext(frozen.held[p].handle,&context)) {
                    const auto saved=hooks.entries[0]; hooks.entries[0]=context.Rip;
                    freeze_ok=!frozen.Capture(hooks) && frozen.failure && !std::strcmp(frozen.failure,"thread is executing a displaced prefix; retry later");
                    hooks.entries[0]=saved;
                }
                break;
            }
        }
    }
    if (!freeze_ok) { reason=freeze_failure?freeze_failure:"native thread was not frozen or unsafe RIP was accepted"; return false; }
    using FixtureCall=int (*)(std::int64_t,std::uint8_t);
    OriginalSnapshot shell{};
    for (std::size_t i=0;i<kHookCount;++i) if (reinterpret_cast<FixtureCall>(entries[i])(reinterpret_cast<std::int64_t>(&shell),0)!=17+static_cast<int>(i) ||
        reinterpret_cast<FixtureCall>(hooks.page+kGateways[i])(reinterpret_cast<std::int64_t>(&shell),0)!=17+static_cast<int>(i)) { reason="native gateway did not preserve entry behavior"; return false; }
    for (int fail=1;fail<=static_cast<int>(kHookCount);++fail) {
        if (AtomicInstall(hooks,false,reason,fail) || hooks.retained) { reason="injected atomic failure did not roll back"; return false; }
        for (std::size_t i=0;i<kHookCount;++i) {
            std::array<std::uint8_t,8> actual{};
            if (!ReadSpan(entries[i],actual.data(),8) || std::memcmp(actual.data(),kPrefixes[i].data(),8)) {
                reason="atomic rollback lost entry bytes"; return false;
            }
        }
        MEMORY_BASIC_INFORMATION restored{};
        if (!VirtualQuery(fixture,&restored,sizeof(restored)) || restored.Protect!=PAGE_EXECUTE_READ) {
            reason="atomic rollback lost page protection"; return false;
        }
    }
    if (!AtomicInstall(hooks,false,reason)) return false;
    for (const auto entry:entries) if (reinterpret_cast<FixtureCall>(entry)(0,0)!=42) { reason="native dispatcher did not redirect"; return false; }
    {
        FrameContext context; context.hooks.entries=hooks.entries; context.hooks.replacement=hooks.replacement;
        g_frame.store(&context);
        bool good=true;
        for (std::size_t i=0;i<kHookCount;++i) {
            auto bytes=std::vector<std::uint8_t>(hooks.replacement[i].begin(),hooks.replacement[i].end());
            good=good && NormalizeFrameHookBytes(entries[i],bytes) && !std::memcmp(bytes.data(),kPrefixes[i].data(),8);
            bytes.assign(hooks.replacement[i].begin(),hooks.replacement[i].end()); bytes[6]^=1;
            good=good && !NormalizeFrameHookBytes(entries[i],bytes);
            bytes.assign(hooks.replacement[i].begin(),hooks.replacement[i].end()-1);
            good=good && !NormalizeFrameHookBytes(entries[i],bytes);
        }
        g_frame.store(nullptr);
        if (!good) { reason="registered hook normalization accepted foreign or partial bytes"; return false; }
    }
    if (AtomicInstall(hooks,false,reason)) { reason="stale entry bytes accepted"; return false; }
    if (!AtomicInstall(hooks,true,reason)) return false;
    for (std::size_t i=0;i<kHookCount;++i) if (reinterpret_cast<FixtureCall>(entries[i])(reinterpret_cast<std::int64_t>(&shell),0)!=17+static_cast<int>(i)) { reason="native hook restoration differs"; return false; }
    MEMORY_BASIC_INFORMATION memory{};
    if (!VirtualQuery(fixture,&memory,sizeof(memory)) || memory.Protect!=PAGE_EXECUTE_READ) { reason="native entry protection was not restored"; return false; }
    SetEvent(events.done);
    if (WaitForSingleObject(worker,5000)!=WAIT_OBJECT_0 || !ThreadExitProven(worker,exit_wait)) {
        reason="terminated native worker was not proved exited"; return false;
    }
    if (SuspendThread(worker)!=DWORD(-1) || !ThreadExitProven(worker,exit_wait)) {
        reason="native terminated-thread suspension fixture differs"; return false;
    }
    {
        // Keep the terminated worker handle alive. NtGetNextThread can keep
        // returning it on every pass; capture must advance through that object.
        ThreadFreeze frozen(reinterpret_cast<NextThread>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"NtGetNextThread")));
        if (!frozen.Capture(hooks)) { reason=frozen.failure?frozen.failure:"exited-thread capture failed"; return false; }
        if (!frozen.diagnostic.exited_threads) { reason="capture did not exercise the retained exited worker"; return false; }
        for (std::size_t i=0;i<frozen.count;++i) if (frozen.held[i].id==GetThreadId(worker)) {
            reason="terminated thread was retained as suspended"; return false;
        }
        if (!frozen.Release()) { reason="exited-thread fixture resumption failed"; return false; }
    }
    if (!AtomicInstall(hooks,false,reason) || !AtomicInstall(hooks,true,reason)) return false;
    reason.clear(); return true;
}
bool StartNativeFrameBridge(const BuildManifest& manifest,const PeImageView& image,std::uintptr_t base,std::string& reason) {
    if (const auto* active=g_frame.load()) {
        if (active->armed.load()) { reason.clear(); return true; }
        reason="previous frame activation failed: "+active->last_error+"; restart GMod before retry"; return false;
    }
    if (!manifest.supported || manifest.sha256!=kExpectedSha || !base) { reason="unsupported native frame build"; return false; }
    auto candidate=std::make_unique<FrameContext>(); candidate->base=base;
    candidate->original_storage=OriginalNativeStorageView(base);
    if (!ValidateNativeStorageView(candidate->original_storage,reason)) return false;
    candidate->storage.store(&candidate->original_storage);
    if (!BindNativeAudio(manifest,image,base,candidate->audio,reason) ||
        !BindNativePaint(manifest,image,base,candidate->paint,reason)) return false;
    const auto* root=image.rva_ptr(0x4E500,0xE05);
    std::vector<std::uint8_t> root_actual(0xE05);
    if (!root || !ReadSpan(base+0x4E500,root_actual.data(),root_actual.size()) || std::memcmp(root,root_actual.data(),root_actual.size())) {
        reason="native frame owner body differs"; return false;
    }
    std::array<std::uintptr_t,kHookCount> entries{};
    for (std::size_t i=0;i<kHookCount;++i) entries[i]=base+kEntries[i];
    const std::array<std::uintptr_t,kHookCount> targets{reinterpret_cast<std::uintptr_t>(&LiveFrame),
        reinterpret_cast<std::uintptr_t>(&LiveOwner),reinterpret_cast<std::uintptr_t>(&LivePaint),reinterpret_cast<std::uintptr_t>(&LiveBackend)};
    if (!candidate->hooks.Prepare(entries,targets,reason) || !CheckUnwind(candidate->hooks,reason)) return false;
    // No live engine hook can outlive this module or its gateways. Pin before
    // publication, and retain context/table/code until process exit on success.
    HMODULE pinned{};
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS|GET_MODULE_HANDLE_EX_FLAG_PIN,
        reinterpret_cast<LPCWSTR>(&LiveFrame),&pinned)) { reason="cannot pin native frame module"; return false; }
    SoundLock locked(base);
    g_frame.store(candidate.get());
    bool good=false;
    try { good=AtomicInstall(candidate->hooks,false,reason); }
    catch (...) {
        // A concurrent status reader may already have loaded the published
        // context and be waiting for the sound CS. Never destroy that context.
        candidate->hooks.retained=true; candidate.release();
        throw;
    }
    if (good) {
        candidate->hooks.retained=true; candidate->armed=true; candidate.release(); reason.clear(); return true;
    }
    // Publication is a process-lifetime boundary even after a complete rollback.
    // This also keeps gateways alive if recovery was uncertain. Activation may
    // be retried only after a process restart; no dangling status-reader pointer.
    candidate->hooks.retained=true;
    try { candidate->last_error=reason; } catch (...) { candidate.release(); throw; }
    candidate.release();
    return false;
}
[[noreturn]] void SnapshotTransitionFailStop() noexcept {
    TerminateProcess(GetCurrentProcess(),0xCE512008u);
    __fastfail(7);
}
bool RunSnapshotFailStopSelfChecks(std::string& reason) {
    std::array<wchar_t,32768> file{}; const auto length=GetModuleFileNameW(nullptr,file.data(),static_cast<DWORD>(file.size()));
    if (!length || length>=file.size()) { reason="fail-stop child executable path unavailable"; return false; }
    std::wstring command=L"\""+std::wstring(file.data(),length)+L"\" --snapshot-fail-stop-child";
    STARTUPINFOW startup{}; startup.cb=sizeof(startup); PROCESS_INFORMATION process{};
    if (!CreateProcessW(file.data(),command.data(),nullptr,nullptr,FALSE,CREATE_NO_WINDOW,nullptr,nullptr,&startup,&process)) {
        reason="fail-stop fixture child creation failed"; return false;
    }
    const auto waited=WaitForSingleObject(process.hProcess,5000); DWORD code{};
    const bool queried=GetExitCodeProcess(process.hProcess,&code)!=FALSE;
    if (waited!=WAIT_OBJECT_0) { TerminateProcess(process.hProcess,0xCE512009u); WaitForSingleObject(process.hProcess,5000); }
    CloseHandle(process.hThread); CloseHandle(process.hProcess);
    if (waited!=WAIT_OBJECT_0 || !queried || code!=0xCE512008u) { reason="fail-stop fixture did not end only its child with expected code"; return false; }
    reason.clear(); return true;
}
bool StartNativeSnapshotBridge(const BuildManifest& manifest,const PeImageView& image,std::uintptr_t base,
    std::uintptr_t return_slot,bool acknowledge_fail_stop,std::string& reason) {
    if (!acknowledge_fail_stop) { reason="explicit fail-stop acknowledgment required; no snapshot code written"; return false; }
    if (!manifest.supported || manifest.sha256!=kExpectedSha || !base) { reason="unsupported snapshot bridge Build"; return false; }
    if (auto* previous=g_legacy.load()) {
        if (previous->active.load()) { reason.clear(); return true; }
        reason="previous snapshot activation failed; restart GMod before retry"; return false;
    }
    const auto* frame=g_frame.load();
    if (!frame || !frame->armed.load() || frame->base!=base || frame->errors.load()) {
        reason="active error-free frame bridge required before snapshot activation"; return false;
    }
    if (!return_slot) { reason="installer caller return slot unavailable"; return false; }
    auto context=std::make_unique<LegacyBridgeContext>(); context->base=base; context->fail_stop_enabled=true;
    if (!BindNativeLegacyConstructor(manifest,image,base,reinterpret_cast<NativeSnapshotBuilder>(base+0x2C110),
            context->constructor,reason) || !context->thunk.Prepare(context->constructor,reason) ||
        !context->gateway.Prepare(base+0x2C110,reinterpret_cast<std::uintptr_t>(context->thunk.entry()),reason)) return false;
    // No entry is exposed yet. Replace the temporary original entry with the
    // verified continuation gateway before publication, preventing recursion.
    context->constructor.original=reinterpret_cast<NativeSnapshotBuilder>(context->gateway.original());
    context->constructor.consumers.context.bindings.build_routes=context->constructor.original;
    std::vector<MemoryPatch> loads;
    if (!BuildLegacyConsumerLoadPlan(manifest,image,base,loads,reason) ||
        !context->transaction.Prepare(context->gateway.entry_patch(),loads,reason)) return false;
    context->patches=loads; context->patches.push_back(context->gateway.entry_patch());
    constexpr std::array<std::pair<std::uint32_t,std::uint32_t>,16> ranges{{
        {0x2C110,0x183},{0x2D1D0,0x5A1},{0x2E310,0x65F},{0x32C60,0x3B2},
        {0x33530,0x110},{0x33880,0x367},{0x33BF0,0x2D3},{0x37130,0xC75},
        {0x37E20,0x293},{0x380D0,0x186},{0x382C0,0xC94},{0x396E0,0x39D},
        {0x4A1B0,0x506},{0x4A7F0,0x2E9},{0x4C420,0x797},{0x4E500,0xE05}}};
    for (std::size_t i=0;i<ranges.size();++i) {
        if (!image.rva_ptr(ranges[i].first,ranges[i].second) || base>UINTPTR_MAX-ranges[i].first-ranges[i].second) {
            reason="old snapshot function interval outside supported image"; return false;
        }
        context->unsafe[i]={base+ranges[i].first,base+ranges[i].first+ranges[i].second};
    }
    NativeThreadAudit audit; NativeStackGuard guard;
    if (!audit.Prepare(reason) || !guard.Prepare(reason)) return false;
    const auto next=reinterpret_cast<NextThread>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"NtGetNextThread"));
    HookSet no_entries; std::array<DWORD,512> ids{}; std::array<ChannelSlot,kOldCapacity> channels{};
    SoundLock sound(base);
    std::int32_t active{};
    if (!ReadSpan(base+kActiveRva,&active,4) || active || !ReadSpan(base+kChannelsRva,channels.data(),sizeof(channels))) {
        reason="snapshot activation requires readable empty active table; no automatic stopsound"; return false;
    }
    for (const auto& channel:channels) {
        std::uintptr_t mixer{}; std::int16_t reverse{};
        std::memcpy(&mixer,channel.bytes.data()+0x10,8); std::memcpy(&reverse,channel.bytes.data()+0x128,2);
        if (mixer || reverse) { reason="snapshot activation requires no mixer or active reverse position"; return false; }
    }
    if (!guard.CheckOwn(return_slot,context->unsafe.data(),context->unsafe.size())) {
        reason=guard.failure; return false;
    }
    HMODULE pinned{};
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS|GET_MODULE_HANDLE_EX_FLAG_PIN,
        reinterpret_cast<LPCWSTR>(&StartNativeSnapshotBridge),&pinned)) { reason="snapshot module pin failed"; return false; }
    // Publication is permanent even on a confirmed rollback: status readers
    // may have observed this pointer while waiting for the sound CS.
    context->Retain(); auto* published=context.release(); g_legacy.store(published);
    const char* failure{}; bool applied=false;
    {
        ThreadFreeze frozen(next);
        if (!frozen.Capture(no_entries)) failure=frozen.failure;
        if (!failure) {
            for (std::size_t i=0;i<frozen.count;++i) ids[i]=frozen.held[i].id;
            frozen.diagnostic.coverage_checked=audit.Check(ids.data(),frozen.count);
            frozen.diagnostic.system_threads=audit.observed;
            if (!frozen.diagnostic.coverage_checked) {
                failure=audit.failure; frozen.diagnostic.failed_thread_id=audit.missing; frozen.diagnostic.native_status=audit.status;
            }
        }
        for (std::size_t i=0;i<frozen.count && !failure;++i) if (!guard.Check(frozen.held[i].handle,published->unsafe.data(),published->unsafe.size())) {
            failure=guard.failure; frozen.diagnostic.failed_thread_id=frozen.held[i].id;
            frozen.diagnostic.win32_error=guard.error; frozen.diagnostic.native_status=guard.status;
            published->guard_stack_address=guard.hit_location; published->guard_code_address=guard.hit_value;
        }
        if (!failure) {
            published->stacks_checked=true;
            applied=published->transaction.Apply();
            if (!applied) failure=published->transaction.failure;
            if (!published->transaction.resume_safe) { published->fatal=true; SnapshotTransitionFailStop(); }
        }
        published->sync=frozen.diagnostic; published->sync.suspended_threads=static_cast<std::uint32_t>(frozen.count);
        if (applied) published->active=true;
        if (!frozen.Release()) { published->fatal=true; SnapshotTransitionFailStop(); }
    }
    if (failure) { published->last_error=failure; reason=failure; return false; }
    reason.clear(); return applied;
}
SnapshotBridgeStatus QuerySnapshotBridge() {
    SnapshotBridgeStatus status; const auto* context=g_legacy.load();
    if (!context) { status.reason="snapshot bridge inactive; engine capacity remains128"; return status; }
    SoundLock locked(context->base);
    status.active=context->active.load(); status.resources_retained=true; status.fail_stop_enabled=context->fail_stop_enabled;
    status.active_stacks_checked=context->stacks_checked; status.sync=context->sync;
    status.engine_capacity=context->constructor.consumers.context.capacity;
    if (const auto* storage=g_storage.load(); storage && storage->base==context->base) {
        status.storage_relocated=storage->active.load();
        status.storage_guards_intact=storage->storage.GuardsIntact();
        status.storage_redirect_count=static_cast<std::uint32_t>(storage->registry.size());
    }

    status.calls=context->constructor.calls.load(); status.carriers=context->constructor.carriers.load();
    status.passthrough=context->constructor.passthrough.load(); status.errors=context->constructor.errors.load();
    status.guard_stack_address=context->guard_stack_address; status.guard_code_address=context->guard_code_address;
    status.reason=context->last_error.empty()?(status.active?std::string("native legacy snapshot bridge active at capacity ")+std::to_string(status.engine_capacity):
        "snapshot activation failed; restart GMod before retry"):context->last_error;
    return status;
}
bool RunSnapshotStartGateSelfChecks(std::string& reason) {
    BuildManifest manifest; PeImageView image; std::string result;
    if (StartNativeSnapshotBridge(manifest,image,0,0,false,result) || result.find("acknowledgment")==std::string::npos) {
        reason="snapshot startup did not require explicit fail-stop acknowledgment"; return false;
    }
    if (StartNativeSnapshotBridge(manifest,image,0,0,true,result) || result.find("unsupported")==std::string::npos) {
        reason="unsupported snapshot startup was not refused"; return false;
    }
    manifest.supported=true; manifest.sha256=kExpectedSha;
    if (StartNativeSnapshotBridge(manifest,image,reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr)),
        reinterpret_cast<std::uintptr_t>(_AddressOfReturnAddress()),true,result) || result.find("frame bridge")==std::string::npos) {
        reason="snapshot startup did not require active frame bridge"; return false;
    }
    if (g_legacy.load()) { reason="refused startup published resources"; return false; }
    reason.clear(); return true;
}
FrameBridgeStatus QueryFrameBridge() {
    FrameBridgeStatus status; const auto* context=g_frame.load();
    if (!context) { status.reason="native frame bridge is inactive; engine capacity remains 128"; return status; }
    SoundLock locked(context->base);
    status.resources_retained=context->hooks.retained;
    status.sync=context->hooks.sync;
    status.active=context->armed.load(); status.frames=context->frames.load(); status.preprocessed=context->preprocessed.load();
    status.backend_calls=context->backend_calls.load(); status.paint_calls=context->paint_calls.load(); status.mixed=context->mixed.load();
    status.freed=context->freed.load(); status.errors=context->errors.load(); status.fallback_paints=context->fallback_paints.load();
    status.last_input=context->last_input.load(); status.last_retained=context->last_retained.load();
    status.engine_capacity=CurrentNativeStorageView(context->base).capacity;
    status.reason=context->last_error.empty()?(status.active?std::string("native frame bridge active at capacity ")+std::to_string(status.engine_capacity):
        "frame activation failed; resources retained, restart GMod before retry"):context->last_error;
    return status;
}
}

namespace channel_expand {
bool StartNativeStorageBridge(const BuildManifest& manifest,const PeImageView& image,std::uintptr_t base,
    std::uintptr_t return_slot,bool acknowledged,std::string& reason) {
    if (!acknowledged) { reason="explicit storage fail-stop acknowledgment required"; return false; }
    if (!manifest.supported || manifest.sha256!=kExpectedSha || !base) { reason="unsupported storage bridge Build"; return false; }
    if (const auto* previous=g_storage.load()) {
        if (previous->active.load()) { reason.clear(); return true; }
        reason="prior storage switch failed; restart required"; return false;
    }
    auto* frame=g_frame.load(); auto* legacy=g_legacy.load();
    if (!frame || !frame->armed.load() || frame->errors.load() || frame->base!=base ||
        !legacy || !legacy->active.load() || legacy->fatal.load() || legacy->base!=base || legacy->constructor.errors.load()) {
        reason="active error-free frame and snapshot bridges required"; return false;
    }
    const auto original=OriginalNativeStorageView(base);
    const auto current=CurrentNativeStorageView(base);
    if (!return_slot || current.channels!=original.channels || current.active_count!=original.active_count || current.capacity!=128) {
        reason="storage switch requires original128 descriptor and caller return slot"; return false;
    }
    auto candidate=std::make_unique<StorageBridgeContext>(); candidate->base=base;
    if (!candidate->storage.Prepare(base,image.image_size,reason)) return false;
    candidate->view={candidate->storage.channels(),&candidate->storage.active()->count,candidate->storage.active()->indices.data(),128};
    if (!ValidateNativeStorageView(candidate->view,reason)) return false;
    StorageRedirectPlan plan;
    if (!BuildStorageRedirectPlan(manifest,image,base,reinterpret_cast<std::uintptr_t>(candidate->view.channels),
        reinterpret_cast<std::uintptr_t>(candidate->view.active_count),plan,reason) || plan.patches.size()!=95) return false;
    // Capacity/load changes are deliberately excluded: existing carrier loads
    // are already installed; original loop bounds remain128 for this boundary.
    candidate->registry=plan.patches;
    std::vector<MemoryPatch> writes=plan.patches;
    std::vector<MemoryPatch> context_writes;
    if (!BuildStorageContextPatches(original,candidate->view,legacy->constructor.consumers.context,context_writes,reason)) return false;
    writes.insert(writes.end(),context_writes.begin(),context_writes.end());
    if (!candidate->transaction.Prepare(writes,reason)) return false;
    const auto add_range=[&](std::uintptr_t start,std::uintptr_t end) {
        if (!start || start>=end) return false;
        for (std::size_t i=0;i<candidate->unsafe_count;++i) if (candidate->unsafe[i].begin==start && candidate->unsafe[i].end==end) return true;
        if (candidate->unsafe_count==candidate->unsafe.size()) return false;
        candidate->unsafe[candidate->unsafe_count++]={start,end}; return true;
    };
    for (const auto& range:legacy->unsafe) if (!add_range(range.begin,range.end)) { reason="storage unsafe interval capacity exceeded"; return false; }
    for (const auto& patch:plan.patches) {
        const auto rva=static_cast<std::uint32_t>(patch.address-base);
        const auto ref=std::find_if(manifest.references.begin(),manifest.references.end(),[&](const Reference& x){return x.instruction==rva;});
        if (ref==manifest.references.end() || !ref->root) { reason="storage redirect lacks verified function root"; return false; }
        std::uint32_t begin=UINT32_MAX,end=0;
        if (ref->root==0x8B00) { begin=0x8B00; end=0x8E55; }
        else if (ref->root==0x2F160) { begin=0x2F160; end=0x2F1B3; }
        else for (const auto& function:image.functions) if (function.root==ref->root) {
            if (!function.chain_valid) { reason="storage function unwind chain unverified"; return false; }
            begin=std::min(begin,function.begin); end=std::max(end,function.end);
        }
        if (begin==UINT32_MAX || rva<begin || rva>=end || !image.rva_ptr(begin,end-begin) || !add_range(base+begin,base+end)) {
            reason="storage reference outside verified unsafe function interval"; return false;
        }
    }
    NativeThreadAudit audit; NativeStackGuard guard;
    if (!audit.Prepare(reason) || !guard.Prepare(reason)) return false;
    const auto next=reinterpret_cast<NextThread>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"NtGetNextThread"));
    std::array<DWORD,512> ids{}; std::array<ChannelSlot,128> channels{}; ActiveList old_active{};
    SoundLock sound(base);
    if (!ReadSpan(base+kActiveRva,&old_active,4+128*2) || old_active.count ||
        !ReadSpan(base+kChannelsRva,channels.data(),sizeof(channels))) { reason="storage switch requires empty readable active table"; return false; }
    for (const auto& slot:channels) {
        std::uintptr_t mixer{}; std::int16_t reverse{};
        std::memcpy(&mixer,slot.bytes.data()+0x10,8); std::memcpy(&reverse,slot.bytes.data()+0x128,2);
        if (mixer || reverse) { reason="storage switch requires zero mixers and reverse positions; no automatic stop"; return false; }
    }
    std::memcpy(candidate->view.channels,channels.data(),sizeof(channels));
    std::memcpy(candidate->storage.active(),&old_active,4+128*2);
    if (!candidate->storage.GuardsIntact() || !guard.CheckOwn(return_slot,candidate->unsafe.data(),candidate->unsafe_count)) {
        reason=guard.failure?guard.failure:"storage allocation guard failed"; return false;
    }
    // Publication only retains the immutable normalization registry. Readers
    // still use original storage until all code/context writes commit.
    candidate->storage.RetainForProcessLifetime(); auto* published=candidate.release(); g_storage.store(published);
    const char* failure{}; bool applied=false; HookSet no_entries;
    {
        ThreadFreeze frozen(next);
        if (!frozen.Capture(no_entries)) failure=frozen.failure;
        if (!failure) {
            for (std::size_t i=0;i<frozen.count;++i) ids[i]=frozen.held[i].id;
            frozen.diagnostic.coverage_checked=audit.Check(ids.data(),frozen.count);
            frozen.diagnostic.system_threads=audit.observed;
            if (!frozen.diagnostic.coverage_checked) failure=audit.failure;
        }
        for (std::size_t i=0;i<frozen.count && !failure;++i) if (!guard.Check(frozen.held[i].handle,published->unsafe.data(),published->unsafe_count)) {
            failure=guard.failure; frozen.diagnostic.failed_thread_id=frozen.held[i].id;
            published->hit_stack=guard.hit_location; published->hit_code=guard.hit_value;
        }
        if (!failure && (!ReadSpan(base+kChannelsRva,channels.data(),sizeof(channels)) ||
            std::memcmp(channels.data(),published->view.channels,sizeof(channels)) ||
            !ReadSpan(base+kActiveRva,&old_active,4+128*2) ||
            std::memcmp(&old_active,published->storage.active(),4+128*2) || !published->storage.GuardsIntact()))
            failure="original storage changed before authoritative synchronized commit";
        if (!failure) {
            published->stacks_checked=true;
            applied=published->transaction.ApplyWhileQuiescent({});
            if (!applied) failure=published->transaction.failure();
            if (!published->transaction.resume_safe()) { published->fatal=true; SnapshotTransitionFailStop(); }
            if (applied) { frame->storage.store(&published->view,std::memory_order_release); published->active=true; }
        }
        published->sync=frozen.diagnostic; published->sync.suspended_threads=static_cast<std::uint32_t>(frozen.count);
        if (!frozen.Release()) { published->fatal=true; SnapshotTransitionFailStop(); }
    }
    if (failure) { published->error=failure; reason=failure; return false; }
    reason.clear(); return applied;
}
SnapshotBridgeStatus QueryStorageBridge() {
    SnapshotBridgeStatus status; const auto* context=g_storage.load();
    if (!context) { status.reason="storage bridge inactive"; return status; }
    SoundLock sound(context->base);
    status.active=context->active.load(); status.resources_retained=true; status.fail_stop_enabled=true;
    status.storage_relocated=status.active; status.storage_guards_intact=context->storage.GuardsIntact();
    status.storage_redirect_count=static_cast<std::uint32_t>(context->registry.size()); status.engine_capacity=CurrentNativeStorageView(context->base).capacity;
    status.active_stacks_checked=context->stacks_checked; status.sync=context->sync;
    status.guard_stack_address=context->hit_stack; status.guard_code_address=context->hit_code;
    if (const auto* legacy=g_legacy.load(); legacy && legacy->base==context->base) {
        status.calls=legacy->constructor.calls.load(); status.carriers=legacy->constructor.carriers.load();
        status.passthrough=legacy->constructor.passthrough.load(); status.errors=legacy->constructor.errors.load();
    }
    status.reason=context->error.empty()?(status.active?std::string("native storage relocated; logical capacity ")+std::to_string(status.engine_capacity):
        "storage activation failed; restart required"):context->error;
    return status;
}
bool RunStorageStartGateSelfChecks(std::string& reason) {
    BuildManifest manifest; PeImageView image; std::string result;
    if (StartNativeStorageBridge(manifest,image,0,0,false,result) || result.find("acknowledgment")==std::string::npos ||
        StartNativeStorageBridge(manifest,image,0,0,true,result) || result.find("unsupported")==std::string::npos) {
        reason="storage startup acknowledgment/Build gates failed"; return false;
    }
    manifest.supported=true; manifest.sha256=kExpectedSha;
    if (StartNativeStorageBridge(manifest,image,reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr)),1,true,result) ||
        result.find("frame and snapshot")==std::string::npos) { reason="storage startup lacked live bridge prerequisite"; return false; }
    reason.clear(); return true;
}
}

namespace channel_expand {
bool StartNativeCapacityBridge(const BuildManifest& manifest,const PeImageView& image,std::uintptr_t base,
    std::uintptr_t return_slot,bool acknowledged,std::string& reason) {
    if (!acknowledged) { reason="explicit experimental512 fail-stop acknowledgment required"; return false; }
    if (!manifest.supported || manifest.sha256!=kExpectedSha || !base) { reason="unsupported capacity bridge Build"; return false; }
    if (const auto* previous=g_capacity.load()) {
        if (previous->active.load()) { reason.clear(); return true; }
        reason="prior capacity activation failed; restart required"; return false;
    }
    auto* frame=g_frame.load(); auto* legacy=g_legacy.load(); auto* storage=g_storage.load();
    if (!frame || !frame->armed.load() || frame->errors.load() || !legacy || !legacy->active.load() || legacy->constructor.errors.load() ||
        !storage || !storage->active.load() || storage->fatal.load() || storage->base!=base || frame->base!=base || legacy->base!=base ||
        !storage->storage.GuardsIntact()) { reason="active error-free relocated128 bridges and intact512 allocation required"; return false; }
    const auto old=CurrentNativeStorageView(base);
    if (!return_slot || old.capacity!=128 || old.channels!=storage->storage.channels() || old.active_count!=&storage->storage.active()->count ||
        legacy->constructor.consumers.context.capacity!=128 || legacy->constructor.consumers.context.channels!=old.channels ||
        legacy->constructor.consumers.context.active_count!=old.active_count || legacy->constructor.consumers.context.active_indices!=old.active_indices) { reason="capacity startup requires coherent relocated128 descriptor"; return false; }
    auto candidate=std::make_unique<CapacityBridgeContext>(); candidate->base=base; candidate->view=old; candidate->view.capacity=512;
    if (!ValidateNativeStorageView(candidate->view,reason) || !BuildCapacityBoundaryPlan(manifest,image,base,candidate->registry,reason)) return false;
    auto writes=candidate->registry;
    auto& field=legacy->constructor.consumers.context.capacity;
    MemoryPatch metadata; metadata.address=reinterpret_cast<std::uintptr_t>(&field); metadata.expected.resize(4); metadata.replacement.resize(4);
    std::memcpy(metadata.expected.data(),&field,4); const std::uint32_t desired=512; std::memcpy(metadata.replacement.data(),&desired,4);
    writes.push_back(std::move(metadata));
    if (!candidate->transaction.Prepare(writes,reason)) return false;
    NativeThreadAudit audit; NativeStackGuard guard;
    if (!audit.Prepare(reason) || !guard.Prepare(reason)) return false;
    const auto next=reinterpret_cast<NextThread>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"NtGetNextThread"));
    std::array<DWORD,512> ids{}; std::array<ChannelSlot,512> channels{};
    SoundLock sound(base); std::int32_t count{},total{};
    if (!ReadSpan(reinterpret_cast<std::uintptr_t>(old.active_count),&count,4) || count || !ReadSpan(base+kTotalRva,&total,4) ||
        total<64 || total>128 || !ReadSpan(reinterpret_cast<std::uintptr_t>(old.channels),channels.data(),sizeof(channels))) {
        reason="capacity startup requires empty readable relocated storage and valid total"; return false;
    }
    for (std::size_t i=0;i<channels.size();++i) {
        std::uintptr_t mixer{}; std::int16_t reverse{};
        std::memcpy(&mixer,channels[i].bytes.data()+0x10,8); std::memcpy(&reverse,channels[i].bytes.data()+0x128,2);
        if (mixer || reverse || (i>=128 && std::any_of(channels[i].bytes.begin(),channels[i].bytes.end(),[](std::uint8_t b){return b!=0;}))) {
            reason="capacity startup requires no mixers/reverse positions and pristine extra384 slots"; return false;
        }
    }
    if (!guard.CheckOwn(return_slot,storage->unsafe.data(),storage->unsafe_count)) { reason=guard.failure; return false; }
    auto* published=candidate.release(); g_capacity.store(published);
    const char* failure{}; bool applied=false; HookSet no_entries;
    {
        ThreadFreeze frozen(next);
        if (!frozen.Capture(no_entries)) failure=frozen.failure;
        if (!failure) {
            for (std::size_t i=0;i<frozen.count;++i) ids[i]=frozen.held[i].id;
            frozen.diagnostic.coverage_checked=audit.Check(ids.data(),frozen.count); frozen.diagnostic.system_threads=audit.observed;
            if (!frozen.diagnostic.coverage_checked) failure=audit.failure;
        }
        for (std::size_t i=0;i<frozen.count && !failure;++i) if (!guard.Check(frozen.held[i].handle,storage->unsafe.data(),storage->unsafe_count)) {
            failure=guard.failure; frozen.diagnostic.failed_thread_id=frozen.held[i].id;
        }
        if (!failure && (!ReadSpan(reinterpret_cast<std::uintptr_t>(old.active_count),&count,4) || count ||
            !ReadSpan(reinterpret_cast<std::uintptr_t>(old.channels),channels.data(),sizeof(channels)) || !storage->storage.GuardsIntact()))
            failure="capacity storage changed during preparation";
        if (!failure) for (std::size_t i=0;i<512;++i) {
            std::uintptr_t mixer{}; std::int16_t reverse{}; std::memcpy(&mixer,channels[i].bytes.data()+0x10,8); std::memcpy(&reverse,channels[i].bytes.data()+0x128,2);
            if (mixer || reverse || (i>=128 && std::any_of(channels[i].bytes.begin(),channels[i].bytes.end(),[](std::uint8_t b){return b!=0;}))) {
                failure="capacity quiescent storage recheck failed"; break;
            }
        }
        if (!failure) {
            published->stacks_checked=true; applied=published->transaction.ApplyWhileQuiescent({});
            if (!applied) failure=published->transaction.failure();
            if (!published->transaction.resume_safe()) { published->fatal=true; SnapshotTransitionFailStop(); }
            if (applied) { frame->storage.store(&published->view,std::memory_order_release); published->active=true; }
        }
        published->sync=frozen.diagnostic; published->sync.suspended_threads=static_cast<std::uint32_t>(frozen.count);
        if (!frozen.Release()) { published->fatal=true; SnapshotTransitionFailStop(); }
    }
    if (failure) { published->error=failure; reason=failure; return false; }
    reason.clear(); return applied;
}
SnapshotBridgeStatus QueryCapacityBridge() {
    SnapshotBridgeStatus result=QueryStorageBridge(); const auto* context=g_capacity.load();
    result.active=false;
    if (!context) { result.reason="experimental512 capacity bridge inactive"; return result; }
    SoundLock sound(context->base); result.active=context->active.load(); result.sync=context->sync;
    result.active_stacks_checked=context->stacks_checked; result.engine_capacity=CurrentNativeStorageView(context->base).capacity;
    result.reason=context->error.empty()?(result.active?"experimental512 active; routing/lifecycle/stress verification pending":"capacity activation failed; restart required"):context->error;
    return result;
}
bool RunCapacityStartGateSelfChecks(std::string& reason) {
    BuildManifest m; PeImageView image; std::string result;
    if (StartNativeCapacityBridge(m,image,0,0,false,result) || result.find("acknowledgment")==std::string::npos ||
        StartNativeCapacityBridge(m,image,0,0,true,result) || result.find("unsupported")==std::string::npos) { reason="capacity acknowledgment/Build gates failed"; return false; }
    m.supported=true; m.sha256=kExpectedSha;
    if (StartNativeCapacityBridge(m,image,reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr)),1,true,result) ||
        result.find("relocated128")==std::string::npos) { reason="capacity startup accepted absent storage bridge"; return false; }
    reason.clear(); return true;
}
}
