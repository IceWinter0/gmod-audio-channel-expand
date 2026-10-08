#include "manifest.hpp"
#include <cstddef>
#include <cstring>
#include <cstdlib>
#include <windows.h>
#include <utility>
#include <Zydis.h>
#include <limits>
#include <xmmintrin.h>

namespace channel_expand {
static_assert(sizeof(Vector32Metadata)==0x20);
static_assert(offsetof(Vector32Metadata,size)==0x10 && offsetof(Vector32Metadata,elements)==0x18);
static_assert(offsetof(OriginalSnapshot,item_flags)==0x104);
static_assert(offsetof(OriginalSnapshot,auxiliary_routes)==0x188);
static_assert(offsetof(OriginalSnapshot,route_mask)==0x1A8 && sizeof(OriginalSnapshot)==0x1B0);
static_assert(offsetof(ExpandedSnapshot,item_flags)==0x404);
static_assert(offsetof(ExpandedSnapshot,auxiliary_routes)==0x608);
static_assert(offsetof(ExpandedSnapshot,route_mask)==0x628 && sizeof(ExpandedSnapshot)==0x630);

bool MatchesPaintRoute(std::uint8_t flags,std::int32_t route_id,std::int32_t route_class) noexcept {
    if (route_class==0) return !(flags&12) && !route_id;
    if (route_class==1) return (flags&4)!=0;
    if (route_class==2) return (flags&8)!=0;
    if (route_class==3) return route_id!=0;
    return true;
}
bool RunPaintRouteSelfChecks(std::string& reason) {
    for (std::uint32_t flags=0;flags<256;++flags) for (const auto id:{-7,0,9}) {
        if (MatchesPaintRoute(static_cast<std::uint8_t>(flags),id,0)!=((flags&12)==0 && id==0) ||
            MatchesPaintRoute(static_cast<std::uint8_t>(flags),id,1)!=((flags&4)!=0) ||
            MatchesPaintRoute(static_cast<std::uint8_t>(flags),id,2)!=((flags&8)!=0) ||
            MatchesPaintRoute(static_cast<std::uint8_t>(flags),id,3)!=(id!=0) ||
            !MatchesPaintRoute(static_cast<std::uint8_t>(flags),id,4)) {
            reason="paint route class selection mismatch"; return false;
        }
    }
    reason.clear(); return true;
}

std::uint8_t RetainedMixMask(std::uint8_t mask,std::uint8_t flags,std::int32_t rate) noexcept {
    if (flags&8) mask|=1;
    if (flags&4) mask|=2;
    if (rate==11025) mask|=4;
    else if (rate==22050) mask|=8;
    else if (rate==44100) mask|=16;
    return mask;
}
bool RunMixRouteSelfChecks(std::string& reason) {
    for (std::uint32_t mask=0;mask<256;++mask) {
        for (std::uint32_t flags=0;flags<256;++flags) {
            for (const auto rate:{0,11025,22050,44100,48000}) {
                const auto expected=mask | ((flags&8)?1u:0u) | ((flags&4)?2u:0u) |
                    (rate==11025?4u:rate==22050?8u:rate==44100?16u:0u);
                if (RetainedMixMask(static_cast<std::uint8_t>(mask),static_cast<std::uint8_t>(flags),rate)!=expected) {
                    reason="retained channel route mask mismatch"; return false;
                }
            }
        }
    }
    std::array<std::int32_t,4> data{12,24,0,0};
    Vector32Metadata routes{reinterpret_cast<std::uintptr_t>(data.data()),4,-1,2,0,
        reinterpret_cast<std::uintptr_t>(data.data())};
    const NativePreprocessBindings unbound{}; bool appended{};
    if (!AppendNativeMixRoute(unbound,routes,12,appended,reason) || appended || routes.size!=2 ||
        !AppendNativeMixRoute(unbound,routes,36,appended,reason) || !appended || routes.size!=3 || data[2]!=36) {
        reason="route uniqueness or external-buffer append failed"; return false;
    }
    if (!AppendNativeMixRoute(unbound,routes,48,appended,reason)) return false;
    const auto saved=routes; const auto saved_data=data;
    if (AppendNativeMixRoute(unbound,routes,60,appended,reason) ||
        std::memcmp(&routes,&saved,sizeof(routes)) || data!=saved_data) {
        reason="full external vector was reallocated or mutated"; return false;
    }
    routes.size=-1; const auto invalid=routes;
    if (AppendNativeMixRoute(unbound,routes,60,appended,reason) || std::memcmp(&routes,&invalid,sizeof(routes))) {
        reason="invalid vector metadata mutated"; return false;
    }
    reason.clear(); return true;
}

bool ChannelVolumesAtMost(const ChannelSlot& slot,std::int32_t threshold) noexcept {
    // Original 0x28760 uses two banks of 12 cvttss2si results, each floored
    // at -1. Converting the maximum float instead would change NaN semantics.
    for (const auto bank:{0x18u,0x48u}) {
        std::int32_t maximum=-1;
        for (std::size_t p=0;p<12;++p) {
            float volume{};
            std::memcpy(&volume,slot.bytes.data()+bank+p*sizeof(float),sizeof(volume));
            const auto integer=_mm_cvttss_si32(_mm_set_ss(volume));
            if (integer>maximum) maximum=integer;
        }
        if (maximum>threshold) return false;
    }
    return true;
}
bool RunMixVolumeSelfChecks(std::string& reason) {
    ChannelSlot slot{};
    const auto write=[&](std::size_t offset,float value) { std::memcpy(slot.bytes.data()+offset,&value,sizeof(value)); };
    if (!ChannelVolumesAtMost(slot,1)) { reason="zero-volume channel rejected"; return false; }
    for (std::size_t offset=0x18;offset<=0x74;offset+=4) {
        slot={}; write(offset,2.0f);
        if (ChannelVolumesAtMost(slot,1)) { reason="volume above threshold accepted"; return false; }
        write(offset,1.99f);
        if (!ChannelVolumesAtMost(slot,1)) { reason="volume truncation differs from cvttss2si"; return false; }
    }
    for (const auto value:{-2.0f,std::numeric_limits<float>::quiet_NaN(),
        std::numeric_limits<float>::infinity(),2147483648.0f}) {
        for (std::size_t offset=0x18;offset<=0x74;offset+=4) write(offset,value);
        if (!ChannelVolumesAtMost(slot,-1) || ChannelVolumesAtMost(slot,-2)) {
            reason="volume conversion or -1 maximum floor differs"; return false;
        }
    }
    // Adjacent bytes are unrelated; this predicate must not inspect or mutate them.
    slot={}; write(0x14,999.0f); write(0x78,999.0f); const auto saved=slot;
    if (!ChannelVolumesAtMost(slot,0) || std::memcmp(&slot,&saved,sizeof(slot))) {
        reason="volume predicate accessed adjacent fields or mutated channel"; return false;
    }
    reason.clear(); return true;
}

bool RemoveMixSnapshotItem(ExpandedSnapshot& snapshot,std::int32_t position,std::string& reason) {
    if (snapshot.count<=0 || snapshot.count>static_cast<std::int32_t>(kTargetCapacity) ||
        position<0 || position>=snapshot.count) {
        reason="invalid mix snapshot removal position/count"; return false;
    }
    // Original 0x4A5CE swaps the already-processed tail into this position.
    // Keep its culling flag; do not remove a global active channel or free routes.
    const auto tail=snapshot.count-1;
    snapshot.count=tail;
    if (tail>0 && position!=tail) {
        snapshot.indices[position]=snapshot.indices[tail];
        snapshot.item_flags[position]=snapshot.item_flags[tail];
    }
    reason.clear(); return true;
}
bool RunMixPreprocessLayoutSelfChecks(std::string& reason) {
    // Native layout fixtures, not substitute mixers, sources or callbacks.
    struct Guarded { std::uint64_t before{0x86571324ABCD0987ull}; ExpandedSnapshot value{};
        std::uint64_t after{0x9870ABCD12435678ull}; } guarded;
    auto& value=guarded.value;
    value.count=512; value.route_mask=0xAF;
    value.auxiliary_routes={0x12340000u,8,0,2,0,0x12340000u};
    value.reserved.fill(0xBA); value.tail_padding.fill(0xCD);
    for (std::int32_t p=0;p<512;++p) {
        value.indices[p]=static_cast<std::int16_t>(p);
        value.item_flags[p]=static_cast<std::uint8_t>(p%251);
    }
    const auto initial=value;
    auto expected=initial;
    expected.count=511; expected.indices[17]=511; expected.item_flags[17]=initial.item_flags[511];
    if (!RemoveMixSnapshotItem(value,17,reason) || std::memcmp(&value,&expected,sizeof(value))) {
        reason="middle removal did not move tail index and flag together"; return false;
    }
    expected.count=510;
    if (!RemoveMixSnapshotItem(value,510,reason) || std::memcmp(&value,&expected,sizeof(value))) {
        reason="tail removal changed unrelated snapshot fields"; return false;
    }
    value=initial;
    // Descending removal: moved tail is already processed, and must keep its flag.
    for (std::int32_t p=511;p>=0;--p) {
        if (p%2==0 && !RemoveMixSnapshotItem(value,p,reason)) return false;
    }
    if (value.count!=256) { reason="descending removal count mismatch"; return false; }
    for (std::int32_t p=0;p<value.count;++p) {
        const auto index=value.indices[p];
        if (index%2!=1 || value.item_flags[p]!=initial.item_flags[index]) {
            reason="descending removal lost processed tail flag"; return false;
        }
    }
    value.count=1; value.indices[0]=511; value.item_flags[0]=7;
    expected=value; expected.count=0;
    if (!RemoveMixSnapshotItem(value,0,reason) || std::memcmp(&value,&expected,sizeof(value))) {
        reason="last removal changed stale bytes or routing ownership"; return false;
    }
    for (const auto count:{-1,0,513}) {
        value.count=count; expected=value;
        if (RemoveMixSnapshotItem(value,0,reason) || std::memcmp(&value,&expected,sizeof(value))) {
            reason="invalid count removal changed output"; return false;
        }
    }
    value=initial;
    for (const auto position:{-1,512}) {
        expected=value;
        if (RemoveMixSnapshotItem(value,position,reason) || std::memcmp(&value,&expected,sizeof(value))) {
            reason="invalid position removal changed output"; return false;
        }
    }
    if (guarded.before!=0x86571324ABCD0987ull || guarded.after!=0x9870ABCD12435678ull) {
        reason="snapshot removal crossed guards"; return false;
    }
    reason.clear(); return true;
}

bool BindNativeAudio(const BuildManifest& manifest,const PeImageView& image,std::uintptr_t base,
    NativeAudioBindings& out,std::string& reason) {
    if (!manifest.supported || manifest.sha256!=kExpectedSha || !base) { reason="unsupported native binding Build"; return false; }
    // Full loaded-code comparison belongs to the runtime caller. This binding
    // independently verifies these exact original entry bodies before any call.
    for (const auto range:{std::pair<std::uint32_t,std::uint32_t>{0x2C110,0x183},{0x1DFFC0,0x14},{0x33530,0x110}}) {
        const auto* expected=image.rva_ptr(range.first,range.second);
        if (!expected || base>UINTPTR_MAX-range.first-range.second) { reason="native binding entry outside image"; return false; }
        std::vector<std::uint8_t> actual(range.second); SIZE_T read{};
        if (!ReadProcessMemory(GetCurrentProcess(),reinterpret_cast<const void*>(base+range.first),actual.data(),actual.size(),&read) ||
            read!=actual.size() || !NormalizeEngineHookBytes(base+range.first,actual) || std::memcmp(actual.data(),expected,actual.size())) { reason="native binding executable bytes differ"; return false; }
    }
    out={ResolveOriginalSnapshotBuilder(base+0x2C110),reinterpret_cast<NativeVectorFree>(base+0x1DFFC0),
        reinterpret_cast<NativeGuidLookup>(base+0x33530)};
    reason.clear(); return true;
}
bool CopySnapshotIndices(const std::int16_t* indices,std::int32_t count,std::uint32_t capacity,
    ExpandedSnapshot& out,std::string& reason) {
    if (count<0 || count>static_cast<std::int32_t>(kTargetCapacity) || !capacity || capacity>kTargetCapacity ||
        static_cast<std::uint32_t>(count)>capacity || (count && !indices)) { reason="invalid snapshot index source"; return false; }
    std::array<bool,kTargetCapacity> seen{};
    for (std::int32_t p=0;p<count;++p) {
        const auto i=indices[p];
        if (i<0 || i>=static_cast<std::int32_t>(capacity) || seen[i]) { reason="invalid or repeated snapshot channel index"; return false; }
        seen[i]=true;
    }
    if (count) std::memmove(out.indices.data(),indices,static_cast<std::size_t>(count)*sizeof(std::int16_t));
    out.count=count; reason.clear(); return true;
}
bool AdoptRouteMetadata(OriginalSnapshot& source,ExpandedSnapshot& out,std::string& reason) {
    const Vector32Metadata empty{};
    if (std::memcmp(&out.auxiliary_routes,&empty,sizeof(empty))) { reason="destination already owns route metadata"; return false; }
    const auto& vector=source.auxiliary_routes;
    if (vector.allocation_count<0 || vector.size<0 || vector.size>vector.allocation_count ||
        (!vector.memory && (vector.elements || vector.size || vector.allocation_count)) ||
        (vector.memory && vector.elements!=vector.memory)) { reason="invalid engine route metadata"; return false; }
    out.auxiliary_routes=vector; out.route_mask=source.route_mask;
    source.auxiliary_routes={}; source.route_mask=0;
    reason.clear(); return true;
}
NativeSnapshotOwner::~NativeSnapshotOwner() noexcept { Release(); }
void NativeSnapshotOwner::Release() noexcept {
    auto& vector=snapshot.auxiliary_routes;
    if (vector.memory && vector.grow_size>=0 && bindings_.release_vector) bindings_.release_vector(reinterpret_cast<void*>(vector.memory));
    vector={}; snapshot.route_mask=0;
}
bool NativeSnapshotOwner::Build(const std::int16_t* indices,std::int32_t count,std::uint32_t capacity,std::string& reason) {
    if (!bindings_.build_routes || !bindings_.release_vector) { reason="native snapshot functions not bound"; return false; }
    ExpandedSnapshot candidate{};
    if (!CopySnapshotIndices(indices,count,capacity,candidate,reason)) return false;
    OriginalSnapshot original{}; const std::int32_t empty_count=0;
    struct RouteScope {
        OriginalSnapshot& object;
        NativeVectorFree release;
        ~RouteScope() noexcept {
            const auto& vector=object.auxiliary_routes;
            if (vector.memory && vector.grow_size>=0) release(reinterpret_cast<void*>(vector.memory));
        }
    } route_scope{original,bindings_.release_vector};
    bindings_.build_routes(&empty_count,&original);
    if (!AdoptRouteMetadata(original,candidate,reason)) return false;
    Release(); snapshot=candidate; reason.clear(); return true;
}
bool RunNativeBridgeSelfChecks(std::string& reason) {
    // Real byte/index fixtures only. No substitute callbacks or engine objects.
    std::array<std::int16_t,kTargetCapacity> indices{};
    for (std::uint32_t i=0;i<kTargetCapacity;++i) indices[i]=static_cast<std::int16_t>(i);
    struct Guarded { std::uint64_t before{0xA8720314BE569CDFull}; ExpandedSnapshot value{}; std::uint64_t after{0x341257698FAEBCD0ull}; } g;
    for (const auto count:{0,128,129,512}) {
        if (!CopySnapshotIndices(indices.data(),count,kTargetCapacity,g.value,reason) || g.value.count!=count ||
            g.before!=0xA8720314BE569CDFull || g.after!=0x341257698FAEBCD0ull) { reason="bridge index copy damaged object"; return false; }
    }
    OriginalSnapshot old{};
    old.auxiliary_routes={0x12345600u,16,0,3,0,0x12345600u}; old.route_mask=0x9F;
    const auto metadata=old.auxiliary_routes;
    g.value.item_flags.fill(0xBA); const auto flags=g.value.item_flags; const auto copied=g.value.indices;
    if (!AdoptRouteMetadata(old,g.value,reason)) return false;
    const Vector32Metadata empty{};
    if (std::memcmp(&g.value.auxiliary_routes,&metadata,sizeof(metadata)) || std::memcmp(&old.auxiliary_routes,&empty,sizeof(empty)) ||
        g.value.route_mask!=0x9F || old.route_mask || g.value.item_flags!=flags || g.value.indices!=copied || g.value.count!=512) {
        reason="route ownership move changed unrelated fields or left duplicate owner"; return false;
    }
    const auto before_old=old; const auto before_new=g.value;
    if (AdoptRouteMetadata(old,g.value,reason) || std::memcmp(&old,&before_old,sizeof(old)) || std::memcmp(&g.value,&before_new,sizeof(g.value))) {
        reason="occupied route destination overwritten"; return false;
    }
    ExpandedSnapshot free_destination{}; old.auxiliary_routes={0x12345600u,2,0,3,0,0x12345600u};
    if (AdoptRouteMetadata(old,free_destination,reason)) { reason="invalid route metadata accepted"; return false; }
    const auto saved=g.value; indices[1]=0;
    if (CopySnapshotIndices(indices.data(),512,kTargetCapacity,g.value,reason) || std::memcmp(&saved,&g.value,sizeof(saved))) {
        reason="invalid bridge indices changed output"; return false;
    }
    NativeSnapshotOwner unbound({});
    if (unbound.Build(nullptr,0,kTargetCapacity,reason)) { reason="unbound native functions accepted"; return false; }
    reason.clear(); return true;
}
namespace {
const ChannelSlot* AdaptedGuidEntry(NativeGuidContext* context,std::uint32_t guid) noexcept {
    // Windows x64 wrapper (rcx=context, edx=guid). No hook is installed by this function.
    if (!context) return nullptr;
    auto* cs=reinterpret_cast<CRITICAL_SECTION*>(context->sound_critical_section);
    if (!cs) return nullptr;
    EnterCriticalSection(cs);
    struct Unlock { CRITICAL_SECTION* cs; ~Unlock() { LeaveCriticalSection(cs); } } unlock{cs};
    try {
        NativeSnapshotOwner owner(context->bindings); std::string reason;
        if (!owner.Build(context->active_indices,*context->active_count,context->capacity,reason)) return nullptr;
        return LookupGuidInNativeSnapshot(context->channels,context->capacity,owner.snapshot,guid);
    } catch (const std::exception&) { return nullptr; }
}
}
bool EncodeNativeGuidThunk(std::uintptr_t context,std::uintptr_t entry,std::array<std::uint8_t,26>& out,std::string& reason) {
    static_assert(sizeof(std::uintptr_t)==8,"Windows x64 only");
    if (!context || !entry) { reason="null native GUID thunk address"; return false; }
    // mov edx,ecx; mov rcx,context; jmp qword ptr [rip]; dq entry.
    // Volatile registers only, no stack adjustment or return-address changes.
    std::array<std::uint8_t,26> code{0x8B,0xD1,0x48,0xB9};
    std::memcpy(code.data()+4,&context,8);
    code[12]=0xFF; code[13]=0x25;
    std::memcpy(code.data()+18,&entry,8);
    out=code; reason.clear(); return true;
}
NativeGuidThunk::~NativeGuidThunk() noexcept { if (page_) VirtualFree(page_,0,MEM_RELEASE); }
bool NativeGuidThunk::Prepare(NativeGuidContext& context,std::string& reason) {
    if (page_ || !context.active_count || !context.active_indices || !context.channels || !context.sound_critical_section ||
        !context.capacity || context.capacity>kTargetCapacity || !context.bindings.build_routes || !context.bindings.release_vector) {
        reason="invalid native GUID thunk context or already prepared"; return false;
    }
    std::array<std::uint8_t,26> code{};
    if (!EncodeNativeGuidThunk(reinterpret_cast<std::uintptr_t>(&context),reinterpret_cast<std::uintptr_t>(&AdaptedGuidEntry),code,reason)) return false;
    void* page=VirtualAlloc(nullptr,code.size(),MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);
    if (!page) { reason="cannot allocate native GUID thunk"; return false; }
    std::memcpy(page,code.data(),code.size()); DWORD old_protection{};
    if (!VirtualProtect(page,code.size(),PAGE_EXECUTE_READ,&old_protection) ||
        !FlushInstructionCache(GetCurrentProcess(),page,code.size())) {
        VirtualFree(page,0,MEM_RELEASE); reason="cannot protect or flush native GUID thunk"; return false;
    }
    page_=page; reason.clear(); return true;
}
bool RunGuidThunkSelfChecks(std::string& reason) {
    constexpr std::uintptr_t context=0x1234567812345000ull,entry=0x3456789034560000ull;
    std::array<std::uint8_t,26> code{};
    if (!EncodeNativeGuidThunk(context,entry,code,reason)) return false;
    ZydisDecoder decoder; ZydisDecoderInit(&decoder,ZYDIS_MACHINE_MODE_LONG_64,ZYDIS_STACK_WIDTH_64);
    ZydisDecodedInstruction instruction{}; ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT]{};
    const auto decode=[&](std::size_t at) {
        return ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder,code.data()+at,code.size()-at,&instruction,operands));
    };
    if (!decode(0) || instruction.length!=2 || instruction.mnemonic!=ZYDIS_MNEMONIC_MOV ||
        operands[0].reg.value!=ZYDIS_REGISTER_EDX || operands[1].reg.value!=ZYDIS_REGISTER_ECX) {
        reason="GUID input not moved ecx -> edx"; return false;
    }
    if (!decode(2) || instruction.length!=10 || instruction.mnemonic!=ZYDIS_MNEMONIC_MOV ||
        operands[0].reg.value!=ZYDIS_REGISTER_RCX || operands[1].type!=ZYDIS_OPERAND_TYPE_IMMEDIATE || operands[1].imm.value.u!=context) {
        reason="native context not loaded into rcx"; return false;
    }
    if (!decode(12) || instruction.length!=6 || instruction.mnemonic!=ZYDIS_MNEMONIC_JMP ||
        operands[0].type!=ZYDIS_OPERAND_TYPE_MEMORY || operands[0].mem.base!=ZYDIS_REGISTER_RIP || operands[0].mem.disp.value!=0) {
        reason="native GUID tail jump is not leaf RIP-indirect"; return false;
    }
    std::uintptr_t target{}; std::memcpy(&target,code.data()+18,8);
    if (target!=entry) { reason="GUID thunk target truncated"; return false; }
    const auto saved=code;
    if (EncodeNativeGuidThunk(0,entry,code,reason) || code!=saved || EncodeNativeGuidThunk(context,0,code,reason) || code!=saved) {
        reason="invalid thunk addresses altered output"; return false;
    }
    reason.clear(); return true;
}

namespace {
bool MatchesStopChannel(const ChannelSlot& slot,std::int32_t source,std::int32_t entity_channel) noexcept {
    std::int32_t actual_source{},actual_channel{};
    std::memcpy(&actual_source,slot.bytes.data()+0xAC,sizeof(actual_source));
    std::memcpy(&actual_channel,slot.bytes.data()+0xB0,sizeof(actual_channel));
    return actual_source==source && actual_channel==entity_channel;
}
void AdaptedStopEntry(NativeStopContext* context,std::int32_t source,std::int32_t entity_channel) noexcept {
    if (!context || !context->free_channel || !context->channels.active_count || !context->channels.channels) return;
    auto& channels=context->channels;
    auto* cs=reinterpret_cast<CRITICAL_SECTION*>(channels.sound_critical_section);
    if (!cs) return;
    EnterCriticalSection(cs);
    struct Unlock { CRITICAL_SECTION* cs; ~Unlock() { LeaveCriticalSection(cs); } } unlock{cs};
    try {
        NativeSnapshotOwner owner(channels.bindings); std::string reason;
        if (!owner.Build(channels.active_indices,*channels.active_count,channels.capacity,reason)) return;
        for (std::int32_t p=0;p<owner.snapshot.count;++p) {
            auto* slot=const_cast<ChannelSlot*>(channels.channels+owner.snapshot.indices[p]);
            // Evaluate each predicate at its original iteration point: free invokes
            // engine callbacks that can change later channels. Do not preselect.
            if (MatchesStopChannel(*slot,source,entity_channel)) context->free_channel(slot);
        }
    } catch (const std::exception&) { return; }
}
}
bool BindNativeChannelFree(const BuildManifest& manifest,const PeImageView& image,std::uintptr_t base,
    NativeChannelFree& out,std::string& reason) {
    constexpr std::uint32_t rva=0x4D910,length=0x176;
    if (!manifest.supported || manifest.sha256!=kExpectedSha || !base || base>UINTPTR_MAX-rva-length) {
        reason="unsupported full channel free binding Build"; return false;
    }
    const auto* expected=image.rva_ptr(rva,length);
    std::vector<std::uint8_t> actual(length); SIZE_T read{};
    if (!expected || !ReadProcessMemory(GetCurrentProcess(),reinterpret_cast<const void*>(base+rva),actual.data(),actual.size(),&read) ||
        read!=actual.size() || !NormalizeEngineHookBytes(base+rva,actual) || std::memcmp(actual.data(),expected,actual.size())) {
        reason="full channel free executable bytes differ"; return false;
    }
    // Runtime caller must also verify full executable code and route the globals
    // used by this original body to the same storage as NativeStopContext.
    out=reinterpret_cast<NativeChannelFree>(base+rva); reason.clear(); return true;
}
bool SelectStopChannels(const ChannelSlot* channels,std::uint32_t capacity,const ExpandedSnapshot& snapshot,
    std::int32_t source,std::int32_t entity_channel,ActiveList& out,std::string& reason) {
    ExpandedSnapshot validated{};
    if (!channels || !CopySnapshotIndices(snapshot.indices.data(),snapshot.count,capacity,validated,reason)) {
        if (!channels) reason="null stop channel storage";
        return false;
    }
    ActiveList candidate{};
    for (std::int32_t p=0;p<validated.count;++p) {
        const auto index=validated.indices[p];
        if (MatchesStopChannel(channels[index],source,entity_channel)) candidate.indices[candidate.count++]=index;
    }
    out=candidate; reason.clear(); return true;
}
bool EncodeNativeStopThunk(std::uintptr_t context,std::uintptr_t entry,std::array<std::uint8_t,29>& out,std::string& reason) {
    if (!context || !entry) { reason="null native stop thunk address"; return false; }
    // mov r8d,edx; mov edx,ecx; mov rcx,context; RIP-indirect leaf tail jump.
    std::array<std::uint8_t,29> code{0x41,0x89,0xD0,0x8B,0xD1,0x48,0xB9};
    std::memcpy(code.data()+7,&context,8); code[15]=0xFF; code[16]=0x25;
    std::memcpy(code.data()+21,&entry,8); out=code; reason.clear(); return true;
}
NativeStopThunk::~NativeStopThunk() noexcept { if (page_) VirtualFree(page_,0,MEM_RELEASE); }
bool NativeStopThunk::Prepare(NativeStopContext& context,std::string& reason) {
    const auto& channels=context.channels;
    if (page_ || !context.free_channel || !channels.active_count || !channels.active_indices || !channels.channels ||
        !channels.sound_critical_section || !channels.capacity || channels.capacity>kTargetCapacity ||
        !channels.bindings.build_routes || !channels.bindings.release_vector) {
        reason="invalid native stop context or already prepared"; return false;
    }
    std::array<std::uint8_t,29> code{};
    if (!EncodeNativeStopThunk(reinterpret_cast<std::uintptr_t>(&context),reinterpret_cast<std::uintptr_t>(&AdaptedStopEntry),code,reason)) return false;
    void* page=VirtualAlloc(nullptr,code.size(),MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);
    if (!page) { reason="cannot allocate native stop thunk"; return false; }
    std::memcpy(page,code.data(),code.size()); DWORD old_protection{};
    if (!VirtualProtect(page,code.size(),PAGE_EXECUTE_READ,&old_protection) ||
        !FlushInstructionCache(GetCurrentProcess(),page,code.size())) {
        VirtualFree(page,0,MEM_RELEASE); reason="cannot protect or flush native stop thunk"; return false;
    }
    page_=page; reason.clear(); return true;
}
bool RunStopConsumerSelfChecks(std::string& reason) {
    // Channel bytes and machine instructions only, without substitute engine callbacks.
    const auto slots=std::make_unique<std::array<ChannelSlot,kTargetCapacity>>();
    ExpandedSnapshot snapshot{}; snapshot.count=kTargetCapacity;
    for (std::uint32_t i=0;i<kTargetCapacity;++i) {
        snapshot.indices[i]=static_cast<std::int16_t>(kTargetCapacity-1-i);
        const std::int32_t source=i%3==0 ? 42 : 44,channel=i%5==0 ? 7 : 6;
        std::memcpy((*slots)[i].bytes.data()+0xAC,&source,sizeof(source));
        std::memcpy((*slots)[i].bytes.data()+0xB0,&channel,sizeof(channel));
    }
    const auto saved_slots=*slots; const auto saved_snapshot=snapshot;
    ActiveList selected{};
    if (!SelectStopChannels(slots->data(),kTargetCapacity,snapshot,42,6,selected,reason)) return false;
    // 171 source matches, including slot 510; 35 of them have the other channel.
    if (selected.count!=136 || selected.indices[0]!=507 || selected.indices[135]!=3 ||
        std::memcmp(slots.get(),&saved_slots,sizeof(saved_slots)) ||
        std::memcmp(&snapshot,&saved_snapshot,sizeof(snapshot))) {
        reason="stop matching crossed fields, lost snapshot order or modified channels"; return false;
    }
    const std::int32_t negative=-2,other_channel=11;
    std::memcpy((*slots)[511].bytes.data()+0xAC,&negative,sizeof(negative));
    std::memcpy((*slots)[511].bytes.data()+0xB0,&other_channel,sizeof(other_channel));
    if (!SelectStopChannels(slots->data(),kTargetCapacity,snapshot,-2,11,selected,reason) ||
        selected.count!=1 || selected.indices[0]!=511) { reason="stop selection omitted final slot or negative entity"; return false; }
    snapshot.count=0;
    if (!SelectStopChannels(slots->data(),kTargetCapacity,snapshot,42,6,selected,reason) || selected.count) {
        reason="empty stop snapshot did not clear selection"; return false;
    }
    const auto saved_selected=selected;
    snapshot.count=513;
    if (SelectStopChannels(slots->data(),kTargetCapacity,snapshot,42,6,selected,reason) ||
        std::memcmp(&selected,&saved_selected,sizeof(selected))) { reason="invalid stop count changed selection"; return false; }
    snapshot.count=2; snapshot.indices[0]=511; snapshot.indices[1]=511;
    if (SelectStopChannels(slots->data(),kTargetCapacity,snapshot,42,6,selected,reason)) {
        reason="duplicate stop snapshot could free a channel twice"; return false;
    }
    snapshot.indices[1]=512;
    if (SelectStopChannels(slots->data(),kTargetCapacity,snapshot,42,6,selected,reason)) {
        reason="out of range stop channel accepted"; return false;
    }
    constexpr std::uintptr_t context=0x1234567812345000ull,entry=0x3456789034560000ull;
    std::array<std::uint8_t,29> code{};
    if (!EncodeNativeStopThunk(context,entry,code,reason)) return false;
    ZydisDecoder decoder; ZydisDecoderInit(&decoder,ZYDIS_MACHINE_MODE_LONG_64,ZYDIS_STACK_WIDTH_64);
    ZydisDecodedInstruction instruction{}; ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT]{};
    const auto decode=[&](std::size_t at) {
        return ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder,code.data()+at,code.size()-at,&instruction,operands));
    };
    if (!decode(0) || instruction.length!=3 || instruction.mnemonic!=ZYDIS_MNEMONIC_MOV ||
        operands[0].reg.value!=ZYDIS_REGISTER_R8D || operands[1].reg.value!=ZYDIS_REGISTER_EDX ||
        !decode(3) || instruction.length!=2 || instruction.mnemonic!=ZYDIS_MNEMONIC_MOV ||
        operands[0].reg.value!=ZYDIS_REGISTER_EDX || operands[1].reg.value!=ZYDIS_REGISTER_ECX ||
        !decode(5) || instruction.length!=10 || instruction.mnemonic!=ZYDIS_MNEMONIC_MOV ||
        operands[0].reg.value!=ZYDIS_REGISTER_RCX || operands[1].imm.value.u!=context ||
        !decode(15) || instruction.length!=6 || instruction.mnemonic!=ZYDIS_MNEMONIC_JMP ||
        operands[0].type!=ZYDIS_OPERAND_TYPE_MEMORY || operands[0].mem.base!=ZYDIS_REGISTER_RIP || operands[0].mem.disp.value!=0) {
        reason="stop thunk lost entity/channel ABI or leaf tail jump"; return false;
    }
    std::uintptr_t target{}; std::memcpy(&target,code.data()+21,8);
    if (target!=entry) { reason="stop thunk entry truncated"; return false; }
    const auto saved_code=code;
    if (EncodeNativeStopThunk(0,entry,code,reason) || code!=saved_code ||
        EncodeNativeStopThunk(context,0,code,reason) || code!=saved_code) {
        reason="invalid stop thunk input changed code"; return false;
    }
    reason.clear(); return true;
}

bool CopyActiveSnapshot(const ExpandedStorage& storage, ExpandedSnapshot& out, std::string& reason) {
    if (!CheckStorageInvariants(storage,reason)) return false;
    const auto count=storage.active->list.count;
    // Snapshot-owned array; never expand a memcpy into the original engine stack object.
    if (count) std::memcpy(out.indices.data(),storage.active->list.indices.data(),static_cast<std::size_t>(count)*sizeof(std::int16_t));
    out.count=count;
    // Preserve flags and engine-owned auxiliary-vector metadata. Index copying does not own routing initialization.
    reason.clear(); return true;
}
const ChannelSlot* LookupGuidInSnapshot(const ExpandedStorage& storage, const ExpandedSnapshot& snapshot, std::uint32_t guid) noexcept {
    return LookupGuidInNativeSnapshot(storage.channels?storage.channels->slots.data():nullptr,kTargetCapacity,snapshot,guid);
}
const ChannelSlot* LookupGuidInNativeSnapshot(const ChannelSlot* channels,std::uint32_t capacity,
    const ExpandedSnapshot& snapshot,std::uint32_t guid) noexcept {
    if (!channels || !capacity || capacity>kTargetCapacity || snapshot.count<0 ||
        snapshot.count>static_cast<std::int32_t>(capacity)) return nullptr;
    for (std::int32_t p=0; p<snapshot.count; ++p) {
        const auto index=snapshot.indices[p];
        if (index<0 || index>=static_cast<std::int32_t>(capacity)) return nullptr;
        const auto& slot=channels[index];
        std::uint32_t stored{}; std::memcpy(&stored,slot.bytes.data(),sizeof(stored));
        if (stored==guid) return &slot;
    }
    return nullptr;
}
bool RunSnapshotSelfChecks(std::string& reason) {
    ExpandedStorage storage;
    if (!AllocateStorage(storage,reason)) return false;
    struct Guarded { std::uint64_t before{0x9FD3012468ABCE57ull}; ExpandedSnapshot snapshot{}; std::uint64_t after{0x74652189BDACF03Eull}; } a,b;
    // Sentinel bytes test independent native object layout and ownership metadata.
    a.snapshot.item_flags.fill(0x5A); a.snapshot.reserved.fill(0xC3); a.snapshot.tail_padding.fill(0x71);
    a.snapshot.auxiliary_routes={0x10002468u,9,-1,7,0x1234,0x10005678u}; a.snapshot.route_mask=0xA0;
    const auto flags=a.snapshot.item_flags; const auto reserved=a.snapshot.reserved;
    const auto tail=a.snapshot.tail_padding; const auto metadata=a.snapshot.auxiliary_routes;
    const auto metadata_unchanged=[&]() {
        return a.snapshot.item_flags==flags && a.snapshot.reserved==reserved && a.snapshot.tail_padding==tail &&
            std::memcmp(&a.snapshot.auxiliary_routes,&metadata,sizeof(metadata))==0 && a.snapshot.route_mask==0xA0 &&
            a.before==0x9FD3012468ABCE57ull && a.after==0x74652189BDACF03Eull;
    };
    if (!CopyActiveSnapshot(storage,a.snapshot,reason) || a.snapshot.count!=0 || !metadata_unchanged()) return false;
    for (std::uint32_t i=0; i<kTargetCapacity; ++i) {
        if (!AddActive(storage,i)) { reason="snapshot fixture index rejected"; return false; }
        const auto guid=0x110000u+i;
        std::memcpy(storage.channels->slots[i].bytes.data(),&guid,4);
        if (i==0 || i==127 || i==128 || i==511) {
            if (!CopyActiveSnapshot(storage,a.snapshot,reason) || a.snapshot.count!=static_cast<std::int32_t>(i+1) ||
                a.snapshot.indices[i]!=static_cast<std::int16_t>(i) || !metadata_unchanged()) {
                reason="snapshot copy crossed fields or guards: "+reason; return false;
            }
        }
    }
    if (LookupGuidInSnapshot(storage,a.snapshot,0x1101FFu)!=&storage.channels->slots[511] ||
        LookupGuidInSnapshot(storage,a.snapshot,0xFFFFFFFFu)!=nullptr) { reason="GUID lookup omitted index 511"; return false; }
    if (!CopyActiveSnapshot(storage,b.snapshot,reason)) return false;
    const auto b_indices=b.snapshot.indices;
    if (!RemoveActive(storage,0) || !CopyActiveSnapshot(storage,a.snapshot,reason) || b.snapshot.count!=512 || b.snapshot.indices!=b_indices) {
        reason="separate snapshots shared or overwrote index storage"; return false;
    }
    if (LookupGuidInSnapshot(storage,a.snapshot,0x110000u)!=nullptr ||
        LookupGuidInSnapshot(storage,a.snapshot,0x1101FFu)!=&storage.channels->slots[511]) { reason="GUID lookup after swap removal failed"; return false; }
    const auto saved=a.snapshot;
    storage.active->list.count=513;
    if (CopyActiveSnapshot(storage,a.snapshot,reason) || std::memcmp(&a.snapshot,&saved,sizeof(saved))!=0) {
        reason="invalid source count changed destination"; return false;
    }
    a.snapshot.count=513;
    if (LookupGuidInSnapshot(storage,a.snapshot,0x1101FFu)) { reason="invalid snapshot count accepted"; return false; }
    a.snapshot.count=1; a.snapshot.indices[0]=512;
    if (LookupGuidInSnapshot(storage,a.snapshot,0x1101FFu)) { reason="invalid snapshot index accepted"; return false; }
    reason.clear(); return true;
}

static_assert(sizeof(MixSortEntry)==16 && offsetof(MixSortEntry,score)==4 && offsetof(MixSortEntry,sfx)==8);
static_assert(offsetof(ExpandedMixScratch,cull)==0x2000 && offsetof(ExpandedMixScratch,count)==0x2200);
static_assert(offsetof(OriginalMixScratch,cull)==0x800 && offsetof(OriginalMixScratch,count)==0x880 && sizeof(OriginalMixScratch)==0x888);
std::int32_t TruncateMixPriority(float value) noexcept { return _mm_cvttss_si32(_mm_set_ss(value)); }
namespace {
void CullRankedMixEntries(ExpandedMixScratch& scratch,const std::array<std::uintptr_t,kTargetCapacity>& sfx,
    std::int32_t limit,std::uint32_t capacity) noexcept {
    for (std::int32_t p=0;p<scratch.count;++p) {
        std::int32_t preceding{};
        for (std::uint32_t i=0;i<capacity;++i) {
            const auto& entry=scratch.sorted[i];
            if (entry.snapshot_position==p || entry.score<0) break;
            if (entry.sfx==sfx[p]) ++preceding;
        }
        scratch.cull[p]=static_cast<std::uint8_t>(preceding>=limit);
    }
}
}
bool PrepareMixSortKernel(const std::array<MixSortEntry,kTargetCapacity>& input,std::int32_t count,
    const std::array<std::uintptr_t,kTargetCapacity>& channel_sfx,std::int32_t limit,std::uint32_t capacity,
    NativeMixQsort sort,NativeMixCompare compare,ExpandedMixScratch& out,std::string& reason) {
    if ((capacity!=kOldCapacity && capacity!=kTargetCapacity) || count<0 || count>static_cast<std::int32_t>(capacity) ||
        (!sort)!=(!compare)) { reason="invalid mix kernel capacity, count or callback pair"; return false; }
    std::array<bool,kTargetCapacity> seen{};
    for (std::int32_t p=0;p<count;++p) {
        const auto pos=input[p].snapshot_position;
        if (pos<0 || pos>=count || seen[pos]) { reason="invalid or duplicate mix kernel position"; return false; }
        seen[pos]=true;
    }
    ExpandedMixScratch candidate{}; candidate.count=count;
    for (std::int32_t p=0;p<count;++p) candidate.sorted[p]=input[p];
    if (!sort) {
        sort=&std::qsort;
        compare=+[](const void* a,const void* b) {
            return CompareMixScores(*static_cast<const MixSortEntry*>(a),*static_cast<const MixSortEntry*>(b));
        };
    }
    sort(candidate.sorted.data(),capacity,sizeof(MixSortEntry),compare);
    CullRankedMixEntries(candidate,channel_sfx,limit,capacity);
    out=candidate; reason.clear(); return true;
}
bool RunNativeMixSelfChecks(std::string& reason) {
    // Actual SSE conversion and byte arrays, without engine/mixer callback substitutes.
    if (TruncateMixPriority(1.75f)!=1 || TruncateMixPriority(-1.75f)!=-1 || TruncateMixPriority(0.0f)!=0 ||
        TruncateMixPriority(std::numeric_limits<float>::quiet_NaN())!=INT32_MIN ||
        TruncateMixPriority(std::numeric_limits<float>::infinity())!=INT32_MIN ||
        TruncateMixPriority(2147483648.0f)!=INT32_MIN) { reason="mix priority does not preserve cvttss2si"; return false; }
    std::array<MixSortEntry,kTargetCapacity> input{}; std::array<std::uintptr_t,kTargetCapacity> sfx{};
    for (std::uint32_t i=0;i<kTargetCapacity;++i) { input[i]={static_cast<std::int32_t>(i),static_cast<std::int32_t>(i),0x12000u}; sfx[i]=0x12000u; }
    struct Guarded { std::uint64_t before{0xC815FED0973246ABull}; ExpandedMixScratch value{}; std::uint64_t after{0xD046BC5F789213AEull}; } g;
    if (!PrepareMixSortKernel(input,128,sfx,2,128,nullptr,nullptr,g.value,reason)) return false;
    if (g.value.count!=128 || g.value.sorted[0].snapshot_position!=127 || g.value.sorted[127].snapshot_position!=0 ||
        g.value.cull[127] || g.value.cull[126] || !g.value.cull[125]) { reason="128-entry native compatibility kernel failed"; return false; }
    const auto saved=g.value;
    if (PrepareMixSortKernel(input,129,sfx,2,128,nullptr,nullptr,g.value,reason) || std::memcmp(&saved,&g.value,sizeof(saved))) {
        reason="129 entries accepted by original-capacity kernel"; return false;
    }
    if (!PrepareMixSortKernel(input,512,sfx,2,512,nullptr,nullptr,g.value,reason) || g.value.count!=512 ||
        g.value.sorted[0].snapshot_position!=511 || g.value.cull[511] || g.value.cull[510] || !g.value.cull[509]) {
        reason="expanded native kernel lost slot 511"; return false;
    }
    // The helper itself culls every item for limit 0; its caller normally skips
    // invoking it. Keep this distinct from PrepareMixSort's disabled-caller mode.
    if (!PrepareMixSortKernel(input,129,sfx,0,512,nullptr,nullptr,g.value,reason) || g.value.count!=129) return false;
    for (std::int32_t p=0;p<129;++p) if (!g.value.cull[p]) { reason="direct helper limit-zero behavior changed"; return false; }
    if (g.before!=0xC815FED0973246ABull || g.after!=0xD046BC5F789213AEull) { reason="native mix kernel overwrote guards"; return false; }
    const auto saved_zero=g.value;
    input[1].snapshot_position=0;
    if (PrepareMixSortKernel(input,129,sfx,1,512,nullptr,nullptr,g.value,reason) || std::memcmp(&saved_zero,&g.value,sizeof(saved_zero))) {
        reason="duplicate native mix position changed output"; return false;
    }
    reason.clear(); return true;
}
namespace {
bool ReadNativeMethod(std::uintptr_t object,std::uintptr_t offset,std::uintptr_t& target,std::string& reason) {
    std::uintptr_t vtable{}; SIZE_T read{};
    if (!object || !ReadProcessMemory(GetCurrentProcess(),reinterpret_cast<const void*>(object),&vtable,sizeof(vtable),&read) ||
        read!=sizeof(vtable) || !vtable || vtable>UINTPTR_MAX-offset ||
        !ReadProcessMemory(GetCurrentProcess(),reinterpret_cast<const void*>(vtable+offset),&target,sizeof(target),&read) ||
        read!=sizeof(target) || !target) { reason="cannot read native virtual callback"; return false; }
    MEMORY_BASIC_INFORMATION page{};
    if (!VirtualQuery(reinterpret_cast<const void*>(target),&page,sizeof(page)) || page.State!=MEM_COMMIT ||
        (page.Protect&(PAGE_GUARD|PAGE_NOACCESS)) ||
        !(page.Protect&(PAGE_EXECUTE|PAGE_EXECUTE_READ|PAGE_EXECUTE_READWRITE|PAGE_EXECUTE_WRITECOPY))) {
        reason="native virtual callback is not executable"; return false;
    }
    return true;
}
}
bool BindNativeMix(const BuildManifest& manifest,const PeImageView& image,std::uintptr_t base,
    NativeMixBindings& out,std::string& reason) {
    if (!manifest.supported || manifest.sha256!=kExpectedSha || !base) { reason="unsupported native mix Build"; return false; }
    for (const auto range:{std::pair<std::uint32_t,std::uint32_t>{0x289C0,0xD7},{0x49FE0,0x1CE},{0x49D40,7},{0x353BD0,0x398}}) {
        const auto* expected=image.rva_ptr(range.first,range.second);
        if (!expected || base>UINTPTR_MAX-range.first-range.second) { reason="native mix binding outside image"; return false; }
        std::vector<std::uint8_t> actual(range.second); SIZE_T read{};
        if (!ReadProcessMemory(GetCurrentProcess(),reinterpret_cast<const void*>(base+range.first),actual.data(),actual.size(),&read) ||
            read!=actual.size() || !NormalizeEngineHookBytes(base+range.first,actual) || std::memcmp(actual.data(),expected,actual.size())) {
            reason="native mix entry bytes differ"; return false;
        }
    }
    out={reinterpret_cast<NativeMixPriority>(base+0x289C0),reinterpret_cast<NativeOriginalMixSort>(base+0x49FE0),
        reinterpret_cast<NativeMixQsort>(base+0x353BD0),reinterpret_cast<NativeMixCompare>(base+0x49D40),base};
    reason.clear(); return true;
}
bool ReadNativeDuplicateLimit(const NativeMixBindings& bindings,std::int32_t& out,std::string& reason) {
    const auto base=bindings.engine_base;
    if (!base || base>UINTPTR_MAX-0x55D9EC) { reason="native duplicate-limit binding missing"; return false; }
    std::uintptr_t parent{}; SIZE_T read{};
    if (!ReadProcessMemory(GetCurrentProcess(),reinterpret_cast<const void*>(base+0x55D9C8),&parent,sizeof(parent),&read) ||
        read!=sizeof(parent) || !parent) { reason="cannot read duplicate-limit parent"; return false; }
    if (parent==base+0x55D990) {
        std::uint32_t encoded{};
        if (!ReadProcessMemory(GetCurrentProcess(),reinterpret_cast<const void*>(base+0x55D9E8),&encoded,sizeof(encoded),&read) ||
            read!=sizeof(encoded)) { reason="cannot read duplicate-limit value"; return false; }
        const auto decoded=encoded^static_cast<std::uint32_t>(parent);
        std::memcpy(&out,&decoded,sizeof(out));
    } else {
        std::uintptr_t callback{};
        if (!ReadNativeMethod(parent,0x68,callback,reason)) return false;
        out=reinterpret_cast<std::int32_t (*)(void*)>(callback)(reinterpret_cast<void*>(parent));
    }
    reason.clear(); return true;
}
bool BuildNativeMixSort(const NativeMixBindings& bindings,const ChannelSlot* channels,std::uint32_t capacity,
    const ExpandedSnapshot& snapshot,std::uint32_t sort_capacity,ExpandedMixScratch& out,NativeMixSample& sample,std::string& reason) {
    if (!channels || !bindings.priority || !bindings.sort || !bindings.compare || !bindings.original_sort ||
        (sort_capacity!=kOldCapacity && sort_capacity!=kTargetCapacity) || snapshot.count>static_cast<std::int32_t>(sort_capacity)) {
        reason="native mix functions/storage/capacity not bound"; return false;
    }
    ExpandedSnapshot validated{};
    if (!CopySnapshotIndices(snapshot.indices.data(),snapshot.count,capacity,validated,reason)) return false;
    std::array<std::uintptr_t,kTargetCapacity> sfx{}; NativeMixSample candidate_sample{};
    std::array<MixSortEntry,kTargetCapacity> input{};
    // Preserve descending callback order from original 0x49FE0.
    for (std::int32_t p=validated.count;p-- >0;) {
        const auto& slot=channels[validated.indices[p]]; std::uintptr_t mixer{},callback{};
        std::memcpy(&mixer,slot.bytes.data()+0x10,8);
        if (!ReadNativeMethod(mixer,0x60,callback,reason)) return false;
        input[p].snapshot_position=p; ++candidate_sample.ready_queries;
        if (reinterpret_cast<bool (*)(void*)>(callback)(reinterpret_cast<void*>(mixer))) {
            input[p].score=TruncateMixPriority(bindings.priority(channels+validated.indices[p]));
            std::memcpy(&input[p].sfx,slot.bytes.data()+8,8); ++candidate_sample.scored_channels;
        }
    }
    ExpandedMixScratch candidate{};
    // Read the cvar only after engine qsort, at the original helper's order point.
    // Initial limit-zero flags belong only to this private candidate and are replaced.
    if (!PrepareMixSortKernel(input,validated.count,sfx,0,sort_capacity,bindings.sort,bindings.compare,candidate,reason) ||
        !ReadNativeDuplicateLimit(bindings,candidate_sample.same_sound_limit,reason)) return false;
    for (std::int32_t p=0;p<validated.count;++p) std::memcpy(&sfx[p],channels[validated.indices[p]].bytes.data()+8,8);
    CullRankedMixEntries(candidate,sfx,candidate_sample.same_sound_limit,sort_capacity);
    out=candidate; sample=candidate_sample; reason.clear(); return true;
}
int CompareMixScores(const MixSortEntry& left,const MixSortEntry& right) noexcept {
    // engine 0x49D40 subtracts in eax, including 32-bit wraparound.
    const std::uint32_t bits=static_cast<std::uint32_t>(right.score)-static_cast<std::uint32_t>(left.score);
    std::int32_t result{}; std::memcpy(&result,&bits,sizeof(result)); return result;
}
bool PrepareMixSort(const std::array<MixSortEntry,kTargetCapacity>& input,std::int32_t count,
    const std::array<std::uintptr_t,kTargetCapacity>& channel_sfx,
    std::int32_t same_sound_limit,ExpandedMixScratch& out,std::string& reason) {
    if (count<0 || count>static_cast<std::int32_t>(kTargetCapacity)) { reason="invalid mix input count"; return false; }
    std::array<const MixSortEntry*,kTargetCapacity> by_position{};
    for (std::int32_t i=0; i<count; ++i) {
        const auto p=input[i].snapshot_position;
        if (p<0 || p>=count || by_position[p]) { reason="invalid or duplicate mix snapshot position"; return false; }
        by_position[p]=&input[i];
    }
    if (same_sound_limit>0) return PrepareMixSortKernel(input,count,channel_sfx,same_sound_limit,kTargetCapacity,nullptr,nullptr,out,reason);
    out={}; reason.clear(); return true;
}
bool RunMixSortSelfChecks(std::string& reason) {
    struct Guarded { std::uint64_t before{0xC815FED0973246ABull}; ExpandedMixScratch scratch{}; std::uint64_t after{0xD046BC5F789213AEull}; } g;
    std::array<MixSortEntry,kTargetCapacity> input{};
    auto prepare=[&](std::int32_t count,std::int32_t limit) {
        std::array<std::uintptr_t,kTargetCapacity> keys{};
        for (std::int32_t i=0; i<count && i<static_cast<std::int32_t>(kTargetCapacity); ++i) {
            const auto p=input[i].snapshot_position;
            if (p>=0 && p<static_cast<std::int32_t>(kTargetCapacity)) keys[p]=input[i].sfx;
        }
        return PrepareMixSort(input,count,keys,limit,g.scratch,reason);
    };
    for (std::uint32_t i=0; i<kTargetCapacity; ++i) input[i]={static_cast<std::int32_t>(i),static_cast<std::int32_t>(kTargetCapacity-i),0x12000u};
    if (!prepare(512,4)) return false;
    if (g.scratch.count!=512) { reason="mix scratch count truncated"; return false; }
    for (std::uint32_t i=0; i<kTargetCapacity; ++i) {
        if (g.scratch.sorted[i].snapshot_position!=static_cast<std::int32_t>(i) || g.scratch.cull[i]!=(i>=4)) {
            reason="descending order/duplicate priority changed"; return false;
        }
    }
    if (g.before!=0xC815FED0973246ABull || g.after!=0xD046BC5F789213AEull) { reason="512 scratch overwrote guards"; return false; }
    for (std::uint32_t i=0; i<kTargetCapacity; ++i) input[i].sfx=0x10000u+i;
    if (!prepare(512,1)) return false;
    for (auto v:g.scratch.cull) if (v) { reason="different sfx counted as duplicate"; return false; }
    for (std::uint32_t i=0; i<kTargetCapacity; ++i) { input[i].score=42; input[i].sfx=0x11000; }
    if (!prepare(512,4)) return false;
    std::int32_t rejected{}; for (auto v:g.scratch.cull) rejected+=v;
    if (rejected!=508) { reason="tie group duplicate count changed"; return false; }
    input[0]={0,40,0x1000}; input[1]={1,30,0x1000}; input[2]={2,20,0x2000}; input[3]={3,10,0x1000};
    if (!prepare(4,2) || g.scratch.cull[0] || g.scratch.cull[1] || g.scratch.cull[2] || !g.scratch.cull[3]) {
        reason="mixed sfx grouping changed"; return false;
    }
    input[0]={0,30,0x1000}; input[1]={1,20,0x2000}; input[2]={2,-1,0};
    std::array<std::uintptr_t,kTargetCapacity> current_sfx{};
    current_sfx[0]=0x1000; current_sfx[1]=0x2000; current_sfx[2]=0x1000;
    if (!PrepareMixSort(input,3,current_sfx,1,g.scratch,reason) || !g.scratch.cull[2]) {
        reason="invalid score lost original channel sfx matching"; return false;
    }
    if (!prepare(0,4) || g.scratch.count!=0) return false;
    if (!prepare(4,0) || g.scratch.count!=0) { reason="disabled culling not represented as disabled"; return false; }
    const auto saved=g.scratch;
    if (prepare(513,4) || std::memcmp(&saved,&g.scratch,sizeof(saved))) { reason="invalid count wrote scratch"; return false; }
    input[1].snapshot_position=0;
    if (prepare(4,4) || std::memcmp(&saved,&g.scratch,sizeof(saved))) { reason="duplicate snapshot positions accepted"; return false; }
    MixSortEntry a{0,INT32_MAX,0},b{1,-1,0};
    if (CompareMixScores(a,b)!=INT32_MIN) { reason="x86 subtraction wrap semantics changed"; return false; }
    reason.clear(); return true;
}


bool ClearReleasedChannelStorage(ChannelSlot* channels,std::uint32_t capacity,std::uint32_t& bytes,std::string& reason) {
    if (!channels || capacity<kDynamicCapacity || capacity>kTargetCapacity) {
        reason="invalid all-stop storage capacity"; return false;
    }
    // Never overwrite a mixer still owned by any slot, including inactive slots.
    for (std::uint32_t i=0;i<capacity;++i) {
        std::uintptr_t mixer{}; std::memcpy(&mixer,channels[i].bytes.data()+0x10,sizeof(mixer));
        if (mixer) { reason="all-stop storage still owns a mixer; clear refused"; return false; }
    }
    const auto size=capacity*kChannelStride;
    std::memset(channels,0,size); bytes=size; reason.clear(); return true;
}
bool RunAllStopStorageSelfChecks(std::string& reason) {
    struct Guarded { std::uint64_t before{0xAB12CD3456EF7890ull};
        std::array<ChannelSlot,kTargetCapacity> slots;
        std::uint64_t after{0x9012EF3456CD78ABull}; };
    auto g=std::make_unique<Guarded>();
    for (const auto capacity:{kOldCapacity,kTargetCapacity}) {
        for (auto& slot:g->slots) { slot.bytes.fill(0x5A); std::fill_n(slot.bytes.begin()+0x10,8,std::uint8_t{0}); }
        std::uint32_t cleared{};
        if (!ClearReleasedChannelStorage(g->slots.data(),capacity,cleared,reason)) return false;
        if (cleared!=capacity*kChannelStride) { reason="all-stop clearing byte count differs"; return false; }
        for (std::uint32_t i=0;i<capacity;++i) for (const auto byte:g->slots[i].bytes) if (byte) {
            reason="all-stop clearing left channel data, including the final slot"; return false;
        }
        if (capacity<kTargetCapacity && g->slots[capacity].bytes[0]!=0x5A) {
            reason="original-capacity clearing crossed the next storage region"; return false;
        }
        if (g->before!=0xAB12CD3456EF7890ull || g->after!=0x9012EF3456CD78ABull) {
            reason="all-stop clearing crossed guards"; return false;
        }
    }
    g->slots[511].bytes[0x10]=1; const auto saved=g->slots;
    std::uint32_t bytes=123;
    if (ClearReleasedChannelStorage(g->slots.data(),kTargetCapacity,bytes,reason) || bytes!=123 ||
        std::memcmp(g->slots.data(),saved.data(),sizeof(saved)) ||
        ClearReleasedChannelStorage(g->slots.data(),513,bytes,reason) ||
        ClearReleasedChannelStorage(nullptr,kOldCapacity,bytes,reason)) {
        reason="unsafe all-stop clear erased a live mixer or accepted invalid storage"; return false;
    }
    reason.clear(); return true;
}

namespace {
template<class T> T ChannelField(const ChannelSlot& slot,std::size_t offset) noexcept {
    T value{}; std::memcpy(&value,slot.bytes.data()+offset,sizeof(value)); return value;
}
template<class T,class... Args> bool NativeVirtual(std::uintptr_t object,std::uintptr_t offset,
    T& out,std::string& reason,Args... args) {
    std::uintptr_t target{};
    if (!ReadNativeMethod(object,offset,target,reason)) return false;
    out=reinterpret_cast<T (*)(void*,Args...)>(target)(reinterpret_cast<void*>(object),args...);
    return true;
}
template<class T> bool PreprocessRead(std::uintptr_t address,T& out,std::string& reason) {
    SIZE_T size{};
    if (!ReadProcessMemory(GetCurrentProcess(),reinterpret_cast<const void*>(address),&out,sizeof(out),&size) || size!=sizeof(out)) {
        reason="cannot read native preprocessing state"; return false;
    }
    return true;
}
}
// This consumer is called once under the sound CS. Native callbacks remain in
// original order; replaying the original all-stop body would invoke them twice.
bool BindNativeAllStop(const BuildManifest& manifest,const PeImageView& image,std::uintptr_t base,
    NativeAllStopBindings& out,std::string& reason) {
    NativeAllStopBindings candidate{};
    if (!BindNativeAudio(manifest,image,base,candidate.audio,reason) ||
        !BindNativeChannelFree(manifest,image,base,candidate.free_channel,reason)) return false;
    for (const auto range:{std::pair<std::uint32_t,std::uint32_t>{0x37E20,0x293},{0x2ECC0,0xDB},
        {0x495F0,0xC},{0x2BDF0,0x1D6},{0x48120,0x158},{0x4DEF0,0x17C}}) {
        const auto* expected=image.rva_ptr(range.first,range.second);
        if (!expected || base>UINTPTR_MAX-range.first-range.second) { reason="all-stop binding outside image"; return false; }
        std::vector<std::uint8_t> actual(range.second); SIZE_T read{};
        if (!ReadProcessMemory(GetCurrentProcess(),reinterpret_cast<const void*>(base+range.first),actual.data(),actual.size(),&read) ||
            read!=actual.size() || !NormalizeEngineHookBytes(base+range.first,actual) || std::memcmp(actual.data(),expected,actual.size())) {
            reason="native all-stop executable bytes differ"; return false;
        }
    }
    candidate.base=base; out=candidate; reason.clear(); return true;
}
namespace {
bool AllStopVoidMethod(std::uintptr_t object,std::uintptr_t offset,NativeAllStopSample& sample,std::string& reason) {
    std::uintptr_t method{};
    if (!ReadNativeMethod(object,offset,method,reason)) return false;
    reinterpret_cast<void (*)(void*)>(method)(reinterpret_cast<void*>(object));
    ++sample.interface_calls; return true;
}
}
bool StopAllNativeSounds(const NativeAllStopBindings& bindings,ChannelSlot* channels,std::uint32_t capacity,
    bool clear_device,NativeAllStopSample& sample,std::string& reason) {
    sample={};
    if (!bindings.base || !channels || capacity<kDynamicCapacity || capacity>kTargetCapacity || !bindings.free_channel) {
        reason="invalid native all-stop context"; return false;
    }
    struct SoundScope {
        CRITICAL_SECTION* cs;
        explicit SoundScope(std::uintptr_t base):cs(reinterpret_cast<CRITICAL_SECTION*>(base+0x510D50)) { EnterCriticalSection(cs); }
        ~SoundScope() { LeaveCriticalSection(cs); }
    } sound(bindings.base);
    const auto base=bindings.base;
    const auto view=CurrentNativeStorageView(base);
    if (!ValidateNativeStorageView(view,reason) || view.channels!=channels || view.capacity!=capacity) {
        reason="all-stop binding does not match current storage view"; return false;
    }
    std::uintptr_t device{}; bool ready{};
    if (!PreprocessRead(base+0x55E198,device,reason)) return false;
    if (!device) { reason="all-stop device unavailable; original body would skip"; return true; }
    if (!NativeVirtual(device,8,ready,reason)) return false;
    ++sample.interface_calls; sample.device_ready=ready;
    if (!ready) { reason="all-stop device not ready; original body would skip"; return true; }
    *reinterpret_cast<std::int32_t*>(base+0x50208C)=static_cast<std::int32_t>(kDynamicCapacity);
    std::int32_t count{};
    if (!PreprocessRead(reinterpret_cast<std::uintptr_t>(view.active_count),count,reason)) return false;
    NativeSnapshotOwner owner(bindings.audio);
    if (!owner.Build(view.active_indices,count,capacity,reason)) return false;
    sample.source_count=owner.snapshot.count;
    for (std::int32_t p=0;p<owner.snapshot.count;++p) {
        // Original debug output reads the linear ordinal's sfx, whereas the
        // actual free uses the snapshot index. Preserve that callback order.
        const auto sfx=ChannelField<std::uintptr_t>(channels[p],8);
        if (sfx) {
            std::uintptr_t name{};
            if (!NativeVirtual(sfx,0,name,reason)) return false;
            std::uintptr_t logger{};
            if (!PreprocessRead(base+0x38FA58,logger,reason) || !logger) { reason="all-stop debug logger unavailable"; return false; }
            reinterpret_cast<void (*)(std::int32_t,const char*,...)>(logger)(1,
                reinterpret_cast<const char*>(base+0x3954F0),p,reinterpret_cast<const char*>(name));
        }
        bindings.free_channel(&channels[owner.snapshot.indices[p]]); ++sample.freed;
    }
    if (!ClearReleasedChannelStorage(channels,capacity,sample.cleared_bytes,reason)) return false;
    if (clear_device) {
        if (!PreprocessRead(base+0x55E198,device,reason)) return false;
        if (device) {
            if (!AllStopVoidMethod(device,0x70,sample,reason)) return false;
            reinterpret_cast<void (*)()>(base+0x48120)();
            reinterpret_cast<void (*)(std::int32_t,bool)>(base+0x4DEF0)(0x3FC,true);
            sample.device_cleared=true;
        }
    }
    std::memset(reinterpret_cast<void*>(base+0x51B030),0,0x18);
    std::uintptr_t interface{},returned{};
    if (!PreprocessRead(base+0x4D5370,interface,reason) || !NativeVirtual(interface,0xC8,returned,reason)) return false;
    ++sample.interface_calls;
    if (!AllStopVoidMethod(returned,0x48,sample,reason)) return false;
    for (const auto call:{std::pair<std::uint32_t,std::uint32_t>{0xDA4128,0x168},{0x60ED80,0x298},{0x55E198,0x40}}) {
        // Re-read pointers after preceding callbacks, as the original does.
        if (!PreprocessRead(base+call.first,interface,reason) || !AllStopVoidMethod(interface,call.second,sample,reason)) return false;
    }
    reinterpret_cast<void (*)(void*)>(base+0x2ECC0)(reinterpret_cast<void*>(base+0x510D30)); ++sample.pool_clears;
    reinterpret_cast<void (*)()>(base+0x495F0)(); ++sample.pool_clears;
    reinterpret_cast<void (*)()>(base+0x2BDF0)(); ++sample.pool_clears;
    owner.Release(); const Vector32Metadata empty{};
    sample.routing_released=!std::memcmp(&owner.snapshot.auxiliary_routes,&empty,sizeof(empty));
    reason.clear(); return true;
}

bool BindNativePreprocess(const BuildManifest& manifest,const PeImageView& image,std::uintptr_t base,
    NativePreprocessBindings& out,std::string& reason) {
    NativePreprocessBindings candidate{};
    if (!BindNativeMix(manifest,image,base,candidate.mix,reason) ||
        !BindNativeChannelFree(manifest,image,base,candidate.free_channel,reason)) return false;
    for (const auto range:{std::pair<std::uint32_t,std::uint32_t>{0x34690,0x2F6},{0x28760,0x13C},
        {0x1DF90,0x82},{0x1DFFA0,0x14},{0x1E0150,0x1A},{0x382A0,0x1C},{0x4A1B0,0x506}}) {
        const auto* expected=image.rva_ptr(range.first,range.second);
        if (!expected || base>UINTPTR_MAX-range.first-range.second) { reason="preprocess binding outside image"; return false; }
        std::vector<std::uint8_t> actual(range.second); SIZE_T read{};
        if (!ReadProcessMemory(GetCurrentProcess(),reinterpret_cast<const void*>(base+range.first),actual.data(),actual.size(),&read) ||
            read!=actual.size() || !NormalizeEngineHookBytes(base+range.first,actual) || std::memcmp(actual.data(),expected,actual.size())) {
            reason="native preprocessing entry bytes differ"; return false;
        }
    }
    candidate.resolve_source=base+0x34690; candidate.quiet_channel=base+0x28760;
    candidate.route_growth=base+0x1DF90; candidate.allocate=base+0x1DFFA0;
    candidate.reallocate=base+0x1E0150; candidate.clear_global=base+0x382A0;
    out=candidate; reason.clear(); return true;
}
bool AppendNativeMixRoute(const NativePreprocessBindings& bindings,Vector32Metadata& vector,
    std::int32_t route,bool& appended,std::string& reason) {
    appended=false;
    if (vector.size<0 || vector.size>static_cast<std::int32_t>(kTargetCapacity) ||
        vector.allocation_count<0 || vector.size>vector.allocation_count ||
        (vector.memory!=vector.elements) || (!vector.memory && vector.allocation_count)) {
        reason="invalid mix route vector metadata"; return false;
    }
    if (!route) { reason.clear(); return true; }
    auto* data=reinterpret_cast<std::int32_t*>(vector.memory);
    for (std::int32_t p=0;p<vector.size;++p) if (data[p]==route) { reason.clear(); return true; }
    if (vector.size==static_cast<std::int32_t>(kTargetCapacity)) { reason="mix route count exceeds channel capacity"; return false; }
    const auto needed=vector.size+1;
    if (needed>vector.allocation_count) {
        if (vector.grow_size<0 || !bindings.route_growth || !bindings.allocate || !bindings.reallocate) {
            reason="mix route buffer cannot grow"; return false;
        }
        const auto capacity=reinterpret_cast<std::int32_t (*)(std::int32_t,std::int32_t,std::int32_t,std::int32_t)>(bindings.route_growth)
            (vector.allocation_count,vector.grow_size,needed,4);
        if (capacity<needed || capacity>INT32_MAX/4) { reason="native mix route growth returned invalid capacity"; return false; }
        const auto bytes=static_cast<std::size_t>(capacity)*4;
        void* memory=vector.memory?
            reinterpret_cast<void* (*)(void*,std::size_t)>(bindings.reallocate)(reinterpret_cast<void*>(vector.memory),bytes):
            reinterpret_cast<void* (*)(std::size_t)>(bindings.allocate)(bytes);
        // Unlike the original fatal path, preserve metadata on allocation failure.
        // Audio side effects already performed by this owner are not replayed
        // or rolled back when native route allocation fails.
        if (!memory) { reason="native mix route allocation failed"; return false; }
        vector.memory=vector.elements=reinterpret_cast<std::uintptr_t>(memory); vector.allocation_count=capacity;
        data=static_cast<std::int32_t*>(memory);
    }
    data[vector.size]=route; ++vector.size; appended=true; reason.clear(); return true;
}
bool PreprocessNativeMix(const NativePreprocessBindings& bindings,ChannelSlot* channels,std::uint32_t capacity,
    ExpandedSnapshot& snapshot,NativePreprocessSample& sample,std::string& reason) {
    sample={};
    const auto base=bindings.mix.engine_base;
    if (!base || base>UINTPTR_MAX-0x8B076C || !bindings.resolve_source || !bindings.quiet_channel ||
        !bindings.free_channel || !bindings.clear_global || !channels) { reason="native preprocessing bindings missing"; return false; }
    ExpandedSnapshot validated{};
    if (!CopySnapshotIndices(snapshot.indices.data(),snapshot.count,capacity,validated,reason)) return false;
    auto& routes=snapshot.auxiliary_routes;
    if (routes.size<0 || routes.size>routes.allocation_count || routes.allocation_count<0 ||
        routes.memory!=routes.elements || (!routes.memory && routes.allocation_count)) {
        reason="preprocess routing ownership invalid"; return false;
    }
    sample.input_count=snapshot.count; snapshot.route_mask&=0xE0; routes.size=0;
    std::uintptr_t engine_sound{}; bool mode{}; float pitch_scale{};
    if (!PreprocessRead(base+0x498010,engine_sound,reason) || !NativeVirtual(engine_sound,0x78,mode,reason) ||
        !PreprocessRead(base+0x3958AC,pitch_scale,reason)) return false;
    std::int32_t limit{};
    if (!ReadNativeDuplicateLimit(bindings.mix,limit,reason)) return false;
    ExpandedMixScratch scratch{}; NativeMixSample sorted;
    if (limit>0 && !BuildNativeMixSort(bindings.mix,channels,capacity,snapshot,kTargetCapacity,scratch,sorted,reason)) return false;
    bool pending0=false,pending1=false;
    for (std::int32_t p=snapshot.count-1;p>=0;--p) {
        auto& channel=channels[snapshot.indices[p]]; bool ready{};
        if (!NativeVirtual(ChannelField<std::uintptr_t>(channel,0x10),0x60,ready,reason)) return false;
        if (!ready) {
            ++sample.not_ready;
            if (!RemoveMixSnapshotItem(snapshot,p,reason)) return false;
            continue;
        }
        const auto source=reinterpret_cast<std::uintptr_t (*)(void*,ChannelSlot*)>(bindings.resolve_source)
            (reinterpret_cast<void*>(ChannelField<std::uintptr_t>(channel,8)),&channel);
        const bool quiet=reinterpret_cast<bool (*)(const ChannelSlot*,std::int32_t)>(bindings.quiet_channel)(&channel,1);
        bool drop=false,free=false;
        if (!source) free=drop=true;
        else if (quiet) {
            bool special{};
            if (!NativeVirtual(source,0x58,special,reason)) return false;
            if (special || (ChannelField<std::uint8_t>(channel,0x13C)&4)) drop=true;
            else {
                std::uintptr_t available{};
                if (!NativeVirtual(source,0x88,available,reason)) return false;
                if (!available) free=drop=true;
            }
        }
        if (free) { bindings.free_channel(&channel); ++sample.freed; }
        if (mode && (ChannelField<std::uint8_t>(channel,0x13D)&0x10)) drop=true;
        snapshot.item_flags[p]=0;
        if (drop) {
            ++sample.dropped;
            if (!RemoveMixSnapshotItem(snapshot,p,reason)) return false;
            continue;
        }
        if (!ReadNativeDuplicateLimit(bindings.mix,limit,reason)) return false;
        if (limit>0 && scratch.count>p) snapshot.item_flags[p]=scratch.cull[p];
        // Keep flag reads on their original sides of allocation/source callbacks.
        snapshot.route_mask=RetainedMixMask(snapshot.route_mask,ChannelField<std::uint8_t>(channel,0x13C)&8,0);
        bool appended{};
        if (!AppendNativeMixRoute(bindings,routes,ChannelField<std::int32_t>(channel,0x138),appended,reason)) return false;
        if (appended) {
            reinterpret_cast<std::int32_t*>(routes.memory)[routes.size-1]=ChannelField<std::int32_t>(channel,0x138);
            ++sample.route_appends;
        }
        snapshot.route_mask=RetainedMixMask(snapshot.route_mask,ChannelField<std::uint8_t>(channel,0x13C)&4,0);
        std::int32_t rate{};
        if (!NativeVirtual(source,0x28,rate,reason)) return false;
        snapshot.route_mask=RetainedMixMask(snapshot.route_mask,0,rate);
        const auto flags=ChannelField<std::uint8_t>(channel,0x13C);
        if ((flags&0x20) && ChannelField<std::int32_t>(channel,0xAC)!=-2) {
            std::uintptr_t device{};
            if (!PreprocessRead(base+0x60ED28,device,reason)) return false;
            bool mark=true;
            if (device) {
                const auto entity_channel=ChannelField<std::int32_t>(channel,0xB0);
                if (entity_channel==2 || entity_channel==7) mark=false;
                else {
                    const auto sfx=ChannelField<std::uintptr_t>(channel,8); std::uintptr_t object{};
                    if (sfx && !PreprocessRead(sfx+8,object,reason)) return false;
                    if (object) {
                        std::uintptr_t available{};
                        if (!NativeVirtual(object,0x88,available,reason)) return false;
                        if (available) mark=false;
                    }
                }
            }
            if (mark) {
                const auto current_flags=device?ChannelField<std::uint8_t>(channel,0x13C):flags;
                if (current_flags&0x40) pending1=true; else pending0=true;
            }
        }
        const auto pitch=static_cast<float>(ChannelField<std::int16_t>(channel,0xBA))*pitch_scale;
        float mixed_pitch{};
        if (!NativeVirtual(ChannelField<std::uintptr_t>(channel,0x10),0x30,mixed_pitch,reason,pitch)) return false;
        std::memcpy(channel.bytes.data()+0xBC,&mixed_pitch,sizeof(mixed_pitch)); ++sample.pitch_updates;
    }
    float time_a{},time_b{};
    if (!mode && (!PreprocessRead(base+0x8B0768,time_a,reason) || !PreprocessRead(base+0x8B0764,time_b,reason))) return false;
    const auto clear=reinterpret_cast<void (*)(std::int32_t)>(bindings.clear_global);
    if (mode || time_a>time_b) {
        pending0=false; clear(1); ++sample.global_clears;
    } else if (!pending1) { clear(1); ++sample.global_clears; }
    if (!pending0) { clear(0); ++sample.global_clears; }
    sample.retained=snapshot.count; reason.clear(); return true;
}

bool CompareOriginalVolumeKernel(const std::filesystem::path& path,std::string& reason) {
    const auto inventory=InspectEngine(path);
    if (!inventory.parsed || !inventory.manifest.supported || inventory.manifest.sha256!=kExpectedSha) {
        reason="volume kernel requires exact known engine Build"; return false;
    }
    constexpr std::size_t length=0x13C;
    const auto* bytes=inventory.image.rva_ptr(0x28760,length);
    if (!bytes) { reason="volume kernel outside image"; return false; }
    ZydisDecoder decoder; ZydisDecoderInit(&decoder,ZYDIS_MACHINE_MODE_LONG_64,ZYDIS_STACK_WIDTH_64);
    std::array<bool,length> starts{}; std::vector<std::size_t> branch_targets;
    for (std::size_t at=0;at<length;) {
        ZydisDecodedInstruction instruction; ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
        if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder,bytes+at,length-at,&instruction,operands)) ||
            !instruction.length || instruction.mnemonic==ZYDIS_MNEMONIC_CALL) {
            reason="volume kernel is not a relocatable leaf"; return false;
        }
        starts[at]=true;
        for (std::uint8_t p=0;p<instruction.operand_count;++p) {
            const auto& operand=operands[p];
            if (operand.type==ZYDIS_OPERAND_TYPE_MEMORY &&
                (operand.mem.base==ZYDIS_REGISTER_RIP || (operand.actions&ZYDIS_OPERAND_ACTION_MASK_WRITE))) {
                reason="volume kernel references global data or writes memory"; return false;
            }
            if (operand.type==ZYDIS_OPERAND_TYPE_IMMEDIATE && operand.imm.is_relative) {
                const auto target=static_cast<std::int64_t>(at+instruction.length)+operand.imm.value.s;
                if (target<0 || target>=static_cast<std::int64_t>(length)) { reason="volume kernel branches outside leaf"; return false; }
                branch_targets.push_back(static_cast<std::size_t>(target));
            }
        }
        at+=instruction.length;
    }
    for (const auto target:branch_targets) if (!starts[target]) { reason="volume kernel branch is not an instruction boundary"; return false; }
    void* page=VirtualAlloc(nullptr,4096,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
    if (!page) { reason="volume kernel page allocation failed"; return false; }
    struct Scope { void* page; ~Scope() { VirtualFree(page,0,MEM_RELEASE); } } scope{page};
    std::memcpy(page,bytes,length); DWORD previous{};
    if (!VirtualProtect(page,4096,PAGE_EXECUTE_READ,&previous) || !FlushInstructionCache(GetCurrentProcess(),page,length)) {
        reason="volume kernel executable page preparation failed"; return false;
    }
    const auto original=reinterpret_cast<bool (*)(const ChannelSlot*,std::int32_t)>(page);
    const std::array<float,9> values{0.0f,1.0f,1.99f,2.0f,-2.0f,std::numeric_limits<float>::quiet_NaN(),
        std::numeric_limits<float>::infinity(),-std::numeric_limits<float>::infinity(),2147483648.0f};
    for (const auto value:values) for (std::size_t offset=0x18;offset<=0x74;offset+=4) {
        ChannelSlot slot{}; std::memcpy(slot.bytes.data()+offset,&value,sizeof(value)); const auto saved=slot;
        for (const auto threshold:{INT32_MIN,-2,-1,0,1,2,INT32_MAX}) {
            if (original(&slot,threshold)!=ChannelVolumesAtMost(slot,threshold) || std::memcmp(&slot,&saved,sizeof(slot))) {
                reason="original volume kernel differs from compiled predicate"; return false;
            }
        }
    }
    // Mixed banks and invalid float conversions at every offset across 512 slots.
    for (std::uint32_t i=0;i<512;++i) {
        ChannelSlot slot{};
        for (std::size_t p=0;p<24;++p) {
            const auto value=values[(p+i)%values.size()]; std::memcpy(slot.bytes.data()+0x18+p*4,&value,sizeof(value));
        }
        for (const auto threshold:{-2,-1,0,1,2}) if (original(&slot,threshold)!=ChannelVolumesAtMost(slot,threshold)) {
            reason="original mixed-bank volume kernel differs"; return false;
        }
    }
    reason.clear(); return true;
}

namespace {
template<class... Args> bool NativeVirtualVoid(std::uintptr_t object,std::uintptr_t offset,std::string& reason,Args... args) {
    std::uintptr_t target{};
    if (!ReadNativeMethod(object,offset,target,reason)) return false;
    reinterpret_cast<void (*)(void*,Args...)>(target)(reinterpret_cast<void*>(object),args...); return true;
}
}
bool BindNativePaint(const BuildManifest& manifest,const PeImageView& image,std::uintptr_t base,
    NativePaintBindings& out,std::string& reason) {
    NativePaintBindings candidate{};
    if (!BindNativePreprocess(manifest,image,base,candidate.preprocess,reason)) return false;
    // 0x501F0 has chained unwind records: first .pdata span ends at 0x50278,
    // but the contiguous helper body continues through ret at 0x50469.
    for (const auto range:{std::pair<std::uint32_t,std::uint32_t>{0x4A7F0,0x2E9},{0x501F0,0x27A},
        {0x4B8F0,0x24E},{0x4C420,0x797}}) {
        const auto* expected=image.rva_ptr(range.first,range.second);
        if (!expected || base>UINTPTR_MAX-range.first-range.second) { reason="native paint binding outside image"; return false; }
        std::vector<std::uint8_t> actual(range.second); SIZE_T read{};
        if (!ReadProcessMemory(GetCurrentProcess(),reinterpret_cast<const void*>(base+range.first),actual.data(),actual.size(),&read) ||
            read!=actual.size() || !NormalizeEngineHookBytes(base+range.first,actual) || std::memcmp(actual.data(),expected,actual.size())) {
            reason="native paint entry bytes differ"; return false;
        }
    }
    candidate.prepare_source=base+0x501F0; candidate.rate_backend=base+0x4B8F0;
    out=candidate; reason.clear(); return true;
}
bool PaintNativeMix(const NativePaintBindings& bindings,ChannelSlot* channels,std::uint32_t capacity,
    ExpandedSnapshot& snapshot,std::int64_t end_position,std::int32_t route_class,std::int32_t source_rate,
    std::int32_t input_rate,NativePaintSample& sample,std::string& reason) {
    sample={}; const auto base=bindings.preprocess.mix.engine_base;
    if (!base || base>UINTPTR_MAX-0x60ED30 || !channels || !bindings.prepare_source ||
        !bindings.preprocess.free_channel || input_rate<=0 || input_rate>44100) {
        reason="native paint bindings or sample rate invalid"; return false;
    }
    ExpandedSnapshot validated{};
    if (!CopySnapshotIndices(snapshot.indices.data(),snapshot.count,capacity,validated,reason)) return false;
    std::int64_t cursor{};
    if (!PreprocessRead(base+0x51B0A8,cursor,reason)) return false;
    const auto bits=static_cast<std::uint64_t>(end_position)-static_cast<std::uint64_t>(cursor);
    std::int64_t pending{}; std::memcpy(&pending,&bits,sizeof(pending));
    const auto frame_count=pending/(44100/input_rate);
    const auto low=static_cast<std::uint32_t>(frame_count); std::int32_t samples{};
    std::memcpy(&samples,&low,sizeof(samples));
    sample.input_count=snapshot.count; sample.samples=samples;
    if (samples<=0) { sample.retained=snapshot.count; reason.clear(); return true; }
    for (std::int32_t p=snapshot.count-1;p>=0;--p) {
        auto& channel=channels[snapshot.indices[p]];
        if (!MatchesPaintRoute(ChannelField<std::uint8_t>(channel,0x13C),ChannelField<std::int32_t>(channel,0x138),route_class)) {
            ++sample.skipped; continue;
        }
        if (source_rate==11025 || source_rate==22050 || source_rate==44100) {
            std::uintptr_t source{}; const auto sfx=ChannelField<std::uintptr_t>(channel,8); std::int32_t rate{};
            if (!PreprocessRead(sfx+8,source,reason) || !NativeVirtual(source,0x28,rate,reason)) return false;
            if (rate!=source_rate) { ++sample.skipped; continue; }
        }
        bool prepare=true;
        if (ChannelField<std::int32_t>(channel,0xAC)!=-2) {
            std::uintptr_t device{};
            if (!PreprocessRead(base+0x60ED28,device,reason)) return false;
            if (!device) prepare=false;
            else {
                const auto entity_channel=ChannelField<std::int32_t>(channel,0xB0);
                if (entity_channel!=2 && entity_channel!=7) {
                    const auto sfx=ChannelField<std::uintptr_t>(channel,8); std::uintptr_t source{},available{};
                    if (sfx && !PreprocessRead(sfx+8,source,reason)) return false;
                    if (!source) prepare=false;
                    else {
                        if (!NativeVirtual(source,0x88,available,reason)) return false;
                        if (!available) prepare=false;
                    }
                }
            }
        }
        bool mix=true;
        if (prepare) {
            std::uintptr_t engine_sound{}; bool mode{};
            if (!PreprocessRead(base+0x498010,engine_sound,reason) || !NativeVirtual(engine_sound,0x78,mode,reason)) return false;
            if (mode) mix=false;
            else {
                bool spatial=true;
                const auto source_id=ChannelField<std::int32_t>(channel,0xAC);
                if (source_id!=-2) {
                    std::uintptr_t device{},entity{};
                    if (!PreprocessRead(base+0x60ED28,device,reason) || !NativeVirtual(device,0x18,entity,reason,source_id)) return false;
                    if (!entity) {
                        if (!(ChannelField<std::uint8_t>(channel,0x13C)&8)) spatial=false;
                        else {
                            if (!PreprocessRead(base+0x60ED28,device,reason) ||
                                !NativeVirtual(device,0x18,entity,reason,ChannelField<std::int32_t>(channel,0xB4))) return false;
                            if (!entity) spatial=false;
                        }
                    }
                }
                if (spatial) {
                    const auto sfx=ChannelField<std::uintptr_t>(channel,8); std::uintptr_t source{};
                    if (!PreprocessRead(sfx+8,source,reason)) return false;
                    reinterpret_cast<void (*)(ChannelSlot*,void*,std::int32_t)>(bindings.prepare_source)
                        (&channel,reinterpret_cast<void*>(source),samples);
                }
            }
        }
        // Both original painters branch directly to the next index when this
        // EngineSound mode is set; expiration/free is skipped too.
        if (!mix) { ++sample.skipped; continue; }
        if (mix) {
            const auto pitch=ChannelField<float>(channel,0xBC);
            const auto mixer=ChannelField<std::uintptr_t>(channel,0x10);
            if (snapshot.item_flags[p]) {
                if (!NativeVirtualVoid(mixer,0x10,reason,&channel,samples,input_rate,std::int32_t{0})) return false;
            } else {
                std::uintptr_t target{};
                if (!PreprocessRead(base+0x55E198,target,reason) ||
                    !NativeVirtualVoid(mixer,0x08,reason,reinterpret_cast<void*>(target),&channel,samples,input_rate,std::int32_t{0})) return false;
            }
            std::memcpy(channel.bytes.data()+0xBC,&pitch,sizeof(pitch)); ++sample.mixed;
            bool alive{};
            if (!NativeVirtual(ChannelField<std::uintptr_t>(channel,0x10),0x18,alive,reason)) return false;
            if (!alive) {
                bindings.preprocess.free_channel(&channel); ++sample.freed;
                if (!RemoveMixSnapshotItem(snapshot,p,reason)) return false;
            }
        }
        // Original reads expiration after full-free too; cleared slot yields zero.
        const auto expiration=ChannelField<std::int32_t>(channel,0xA8);
        if (expiration && static_cast<std::int64_t>(expiration)<=end_position) {
            bindings.preprocess.free_channel(&channel); ++sample.freed;
            if (!RemoveMixSnapshotItem(snapshot,p,reason)) return false;
        }
    }
    sample.retained=snapshot.count; reason.clear(); return true;
}

std::array<std::uintptr_t,3> SelectMixBuffers(const MixBufferPrefix& record) noexcept {
    std::array<std::uintptr_t,3> result{};
    std::memcpy(&result[0],record.data()+0x18,8);
    if (record[1]) {
        std::memcpy(&result[1],record.data()+0x20,8);
        if (record[2]) std::memcpy(&result[2],record.data()+0x28,8);
    }
    return result;
}
bool RunMixBufferSelfChecks(std::string& reason) {
    for (std::uint8_t second=0;second<3;++second) for (std::uint8_t third=0;third<3;++third) {
        MixBufferPrefix record{}; record[1]=second; record[2]=third;
        const std::array<std::uintptr_t,3> pointers{0x123456789ABCDEFull,0x23456789ABCDEFull,0x3456789ABCDEFull};
        for (std::size_t i=0;i<3;++i) std::memcpy(record.data()+0x18+i*8,&pointers[i],8);
        const auto selected=SelectMixBuffers(record);
        if (selected[0]!=pointers[0] || selected[1]!=(second?pointers[1]:0) || selected[2]!=((second&&third)?pointers[2]:0)) {
            reason="mix buffer flags or pointer offsets differ"; return false;
        }
    }
    reason.clear(); return true;
}
bool PaintNativeBackend(const NativePaintBindings& bindings,ChannelSlot* channels,std::uint32_t capacity,
    ExpandedSnapshot& snapshot,OriginalSnapshot& shell,std::int64_t end_position,std::int32_t sample_count,
    NativeBackendSample& sample,std::string& reason) {
    sample={}; const auto base=bindings.preprocess.mix.engine_base;
    if (!base || !bindings.rate_backend || sample_count<0 || sample_count>0x3FC) {
        reason="mix backend bindings or frame sample count invalid"; return false;
    }
    const auto read_count=[&](std::int32_t& count) {
        if (!PreprocessRead(base+0x55D978,count,reason)) return false;
        if (count<4 || count>32768) { reason="invalid native mix buffer count"; return false; }
        return true;
    };
    const auto record_address=[&](std::int32_t index,std::uintptr_t& address) {
        std::uintptr_t records{}; std::int32_t count{};
        if (!read_count(count) || index<0 || index>=count || !PreprocessRead(base+0x55D968,records,reason)) return false;
        const auto offset=static_cast<std::uintptr_t>(index)*0x158;
        if (!records || records>UINTPTR_MAX-offset-0x158) { reason="invalid mix buffer storage"; return false; }
        address=records+offset; return true;
    };
    const auto select=[&](std::int32_t index) {
        std::uintptr_t address{}; MixBufferPrefix record{};
        if (!record_address(index,address) || !PreprocessRead(address,record,reason)) return false;
        const auto pointers=SelectMixBuffers(record);
        std::memcpy(reinterpret_cast<void*>(base+0x55DB48),pointers.data(),sizeof(pointers)); return true;
    };
    const auto clear_active=[&]() {
        std::int32_t count{};
        if (!read_count(count)) return false;
        for (std::int32_t p=0;p<count;++p) {
            std::uintptr_t address{};
            if (!record_address(p,address)) return false;
            *reinterpret_cast<std::uint8_t*>(address)=0;
            if (!read_count(count)) return false;
        }
        return true;
    };
    const auto activate=[&](std::int32_t index) {
        std::uintptr_t address{}; if (!record_address(index,address)) return false;
        *reinterpret_cast<std::uint8_t*>(address)=1; return true;
    };
    const auto flag=[&](std::uint32_t rva,bool& value) {
        std::uint8_t byte{}; if (!PreprocessRead(base+rva,byte,reason)) return false;
        value=byte!=0; return true;
    };
    const auto upsample=[&](std::int32_t index,std::int32_t samples) {
        std::uintptr_t device{};
        return select(index) && PreprocessRead(base+0x55E198,device,reason) &&
            NativeVirtualVoid(device,0x88,reason,samples,std::int32_t{1});
    };
    const auto paint=[&](std::int32_t rate) {
        NativePaintSample part{};
        ++sample.paint_calls;
        const auto ok=PaintNativeMix(bindings,channels,capacity,snapshot,end_position,0,rate,rate,part,reason);
        sample.mixed+=part.mixed; sample.freed+=part.freed;
        return ok && ProjectMixShell(snapshot,shell,false,reason);
    };
    const auto route_backend=reinterpret_cast<void (*)(OriginalSnapshot*,std::int32_t,std::int64_t,std::int32_t,std::int32_t)>(bindings.rate_backend);
    const auto body=[&]() {
        if (shell.route_mask&2) route_backend(&shell,4,end_position,sample_count,1);
        if (shell.route_mask&1) route_backend(&shell,5,end_position,sample_count,2);
        for (std::int32_t p=0;p<shell.auxiliary_routes.size;++p) {
            std::int32_t route{},count{};
            if (!PreprocessRead(shell.auxiliary_routes.memory+static_cast<std::uintptr_t>(p)*4,route,reason) || !read_count(count)) return false;
            for (std::int32_t index=6;index<count;++index) {
                std::uintptr_t address{}; std::int32_t id{},state{};
                if (!record_address(index,address) || !PreprocessRead(address+0xC,id,reason) || !PreprocessRead(address+4,state,reason)) return false;
                if (id==route && state!=-1) { route_backend(&shell,index,end_position,sample_count,3); break; }
            }
        }
        if (!clear_active()) return false;
        std::int32_t count{}; if (!read_count(count)) return false;
        for (std::int32_t p=0;p<count;++p) {
            std::uintptr_t address{}; if (!record_address(p,address)) return false;
            const std::int32_t zero=0; std::memcpy(reinterpret_cast<void*>(address+0x30),&zero,4);
            if (!read_count(count)) return false;
        }
        bool first{},third{};
        if (!flag(0x53D949,first) || (!first && !activate(1)) || !activate(2) ||
            !flag(0x53D948,third) || (third && !activate(3)) || !paint(11025)) return false;
        // Reload flags and device/buffer pointers after every engine callback,
        // preserving the original quarter-rate then half-rate conversion order.
        for (const auto divisor:{4,2}) {
            if (!flag(0x53D949,first) || (!first && !upsample(1,sample_count/divisor)) ||
                !upsample(2,sample_count/divisor) || !flag(0x53D948,third) ||
                (third && !upsample(3,sample_count/divisor))) return false;
            if (!paint(divisor==4?22050:44100)) return false;
        }
        return true;
    };
    bool good=false;
    try { good=body(); }
    catch (const std::exception& e) { reason=e.what(); }
    const auto error=reason;
    const bool restored=clear_active() && select(0);
    if (!good) { reason=error; if (!restored) reason+="; default mix buffer restoration failed"; return false; }
    if (!restored) return false;
    reason.clear(); return true;
}

void PackActiveSoundRecord(const ChannelSlot& slot,std::uintptr_t address,std::uintptr_t userdata,float scale,ActiveSoundRecord& out) noexcept {
    out={};
    const auto put=[&](std::size_t o,const auto& x) { std::memcpy(out.data()+o,&x,sizeof(x)); };
    put(0,ChannelField<std::uint32_t>(slot,0)); put(8,userdata);
    put(0x10,ChannelField<std::int32_t>(slot,0xAC)); put(0x14,ChannelField<std::int32_t>(slot,0xB0));
    put(0x18,ChannelField<std::int32_t>(slot,0xB4)); put(0x1C,static_cast<float>(ChannelField<std::int16_t>(slot,0xB8))*scale);
    put(0x20,ChannelField<float>(slot,0xE4)); put(0x24,ChannelField<float>(slot,0x118));
    put(0x28,static_cast<std::int32_t>(ChannelField<std::int16_t>(slot,0xBA)));
    put(0x30,address+0xE8); put(0x38,address+0xF4);
    const auto flags=ChannelField<std::uint8_t>(slot,0x13C);
    for (std::size_t i=0;i<4;++i) out[0x40+i]=static_cast<std::uint8_t>((flags>>i)&1);
    out[0x44]=ChannelField<std::int32_t>(slot,0x138)!=0?1:0; out[0x45]=static_cast<std::uint8_t>((flags>>6)&1);
}
bool NativeAppendRecord(const NativeConsumerBindings& bindings,Vector32Metadata& vector,const void* row,std::uint32_t stride,std::string& reason) {
    if (!row || !stride || stride>sizeof(MusicSoundRecord) || vector.size<0 || vector.allocation_count<0 ||
        vector.size>vector.allocation_count || vector.size==INT32_MAX || vector.memory!=vector.elements ||
        (!vector.memory && vector.allocation_count)) { reason="invalid native output vector"; return false; }
    const auto needed=vector.size+1;
    // Copy first so a row taken from this vector survives its native reallocation.
    MusicSoundRecord saved{}; std::memcpy(saved.data(),row,stride);
    if (needed>vector.allocation_count) {
        if (vector.grow_size<0) { reason="external native vector capacity exhausted"; return false; }
        if (!bindings.growth || !bindings.allocate || !bindings.reallocate) { reason="native vector allocator not bound"; return false; }
        const auto capacity=reinterpret_cast<std::int32_t (*)(std::int32_t,std::int32_t,std::int32_t,std::int32_t)>(bindings.growth)
            (vector.allocation_count,vector.grow_size,needed,static_cast<std::int32_t>(stride));
        if (capacity<needed || capacity>INT32_MAX/static_cast<std::int32_t>(stride)) { reason="native vector growth exceeds byte range"; return false; }
        const auto bytes=static_cast<std::size_t>(capacity)*stride;
        void* memory=vector.memory?reinterpret_cast<void* (*)(void*,std::size_t)>(bindings.reallocate)(reinterpret_cast<void*>(vector.memory),bytes):
            reinterpret_cast<void* (*)(std::size_t)>(bindings.allocate)(bytes);
        if (!memory) { reason="native vector allocation failed; metadata preserved"; return false; }
        vector.memory=vector.elements=reinterpret_cast<std::uintptr_t>(memory); vector.allocation_count=capacity;
    }
    if (vector.memory>UINTPTR_MAX-static_cast<std::size_t>(needed)*stride) { reason="native vector address overflow"; return false; }
    std::memcpy(reinterpret_cast<void*>(vector.memory+static_cast<std::size_t>(vector.size)*stride),saved.data(),stride);
    ++vector.size; reason.clear(); return true;
}
namespace {
bool IsSoundPrefix(std::uint8_t c) noexcept {
    constexpr std::uint64_t mask=0x80000002A000061ull;
    return c=='*' || c=='?' || c=='}' || (c>=0x23 && c<=0x5E && ((mask>>(c-0x23))&1));
}
}
bool StripSoundUpdateModifiers(const char* text,std::size_t size,bool& special,std::string& reason) {
    special=false; if (!text) { reason.clear(); return true; }
    for (std::size_t i=0;i<size;++i) {
        const auto c=static_cast<std::uint8_t>(text[i]);
        if (c=='!') { special=true; reason.clear(); return true; }
        if (!IsSoundPrefix(c)) { reason.clear(); return true; }
    }
    reason="unterminated sound modifier prefix"; return false;
}
bool MatchesSoundUpdate(const ChannelSlot& slot,std::int32_t source,std::int32_t channel,std::uintptr_t sfx,
    std::uint32_t flags,bool special) noexcept {
    if (ChannelField<std::int32_t>(slot,0xAC)!=source) return false;
    if (!special && (flags&0x200)) return true;
    if (ChannelField<std::int32_t>(slot,0xB0)!=channel) return false;
    const auto actual=ChannelField<std::uintptr_t>(slot,8);
    return special?actual!=0:actual==sfx;
}
void ApplySoundUpdateFields(ChannelSlot& slot,std::int32_t volume,std::int32_t pitch,std::uint32_t flags,std::int32_t route) noexcept {
    if (flags&2) { const auto value=static_cast<std::uint16_t>(pitch); std::memcpy(slot.bytes.data()+0xBA,&value,2); }
    if (flags&1) { const auto value=static_cast<std::uint16_t>(volume); std::memcpy(slot.bytes.data()+0xB8,&value,2); }
    if (flags&0x800) std::memcpy(slot.bytes.data()+0x138,&route,4);
}
bool RunQueryRecordSelfChecks(std::string& reason) {
    ChannelSlot slot{};
    const auto put=[&](std::size_t o,const auto& x) { std::memcpy(slot.bytes.data()+o,&x,sizeof(x)); };
    put(0,std::uint32_t{0x12345678}); put(0xAC,std::int32_t{-2}); put(0xB0,std::int32_t{6});
    put(0xB4,std::int32_t{57}); put(0xB8,std::int16_t{-1}); put(0xBA,std::int16_t{-23});
    put(0xE4,3.5f); put(0x118,4.5f); put(0x138,std::int32_t{-7}); put(0x13C,std::uint8_t{0x4F});
    constexpr std::uintptr_t address=0x1234567812345000ull,userdata=0x2234567822345000ull;
    ActiveSoundRecord row{}; PackActiveSoundRecord(slot,address,userdata,1.0f/255.0f,row);
    const auto get=[&](std::size_t o,auto* value) { std::memcpy(value,row.data()+o,sizeof(*value)); };
    std::uint32_t guid{}; std::int32_t source{},pitch{}; float volume{}; std::uintptr_t data{},origin{},direction{};
    get(0,&guid); get(0x10,&source); get(0x28,&pitch); get(0x1C,&volume);
    get(8,&data); get(0x30,&origin); get(0x38,&direction);
    if (guid!=0x12345678 || source!=-2 || pitch!=-23 || volume!=-1.0f/255.0f || data!=userdata ||
        origin!=address+0xE8 || direction!=address+0xF4) { reason="active sound record lost signed fields or escaped coordinate pointers"; return false; }
    for (std::size_t i=0x40;i<=0x45;++i) if (row[i]!=1) { reason="active sound record flag packing differs"; return false; }
    struct Guarded { std::uint64_t before{0xAABB1234CCDD5678ull};
        std::array<ActiveSoundRecord,512> rows; std::uint64_t after{0x77889900AABBCCDDull}; };
    auto g=std::make_unique<Guarded>(); for (auto& r:g->rows) r.fill(0xAC);
    Vector32Metadata vector{reinterpret_cast<std::uintptr_t>(g->rows.data()),512,-1,0,0,reinterpret_cast<std::uintptr_t>(g->rows.data())};
    const NativeConsumerBindings unbound{};
    for (std::int32_t i=0;i<512;++i) {
        std::memcpy(row.data(),&i,sizeof(i));
        if (!NativeAppendRecord(unbound,vector,row.data(),static_cast<std::uint32_t>(row.size()),reason)) return false;
    }
    std::int32_t last{}; std::memcpy(&last,g->rows[511].data(),sizeof(last));
    if (vector.size!=512 || last!=511 || g->before!=0xAABB1234CCDD5678ull || g->after!=0x77889900AABBCCDDull) {
        reason="native record append truncated the final row or crossed guards"; return false;
    }
    const auto saved=vector;
    if (NativeAppendRecord(unbound,vector,row.data(),static_cast<std::uint32_t>(row.size()),reason) ||
        std::memcmp(&vector,&saved,sizeof(vector))) { reason="external vector overflow changed metadata"; return false; }
    vector.size=1; const auto first=g->rows[0];
    if (!NativeAppendRecord(unbound,vector,row.data(),static_cast<std::uint32_t>(row.size()),reason) || vector.size!=2 || g->rows[0]!=first) {
        reason="record append erased existing caller rows"; return false;
    }
    reason.clear(); return true;
}
bool RunSoundUpdateSelfChecks(std::string& reason) {
    bool special{};
    if (!StripSoundUpdateModifiers("*?#@><^)}!sentence",17,special,reason) || !special) return false;
    if (!StripSoundUpdateModifiers("*?#plain",8,special,reason) || special) { reason="normal sound became a sentence"; return false; }
    ChannelSlot slot{}; const std::int32_t source=-2,entity_channel=6; const std::uintptr_t sfx=0x1234567812345000ull;
    std::memcpy(slot.bytes.data()+0xAC,&source,4); std::memcpy(slot.bytes.data()+0xB0,&entity_channel,4); std::memcpy(slot.bytes.data()+8,&sfx,8);
    if (!MatchesSoundUpdate(slot,-2,6,sfx,0,false) || MatchesSoundUpdate(slot,-2,7,sfx,0,false) ||
        MatchesSoundUpdate(slot,-2,6,sfx+8,0,false) || !MatchesSoundUpdate(slot,-2,99,sfx+8,0x200,false) ||
        !MatchesSoundUpdate(slot,-2,6,sfx+8,0,true) || MatchesSoundUpdate(slot,3,6,sfx,0x200,false)) {
        reason="sound update lost exact/all-source/sentence matching"; return false;
    }
    slot.bytes.fill(0xA5); const auto saved=slot;
    ApplySoundUpdateFields(slot,0x12345678,0x11223344,0x803,-19);
    std::uint16_t vol{},pitch{}; std::int32_t route{};
    std::memcpy(&vol,slot.bytes.data()+0xB8,2); std::memcpy(&pitch,slot.bytes.data()+0xBA,2); std::memcpy(&route,slot.bytes.data()+0x138,4);
    if (vol!=0x5678 || pitch!=0x3344 || route!=-19) { reason="sound update changed truncation or route semantics"; return false; }
    for (std::size_t i=0;i<slot.bytes.size();++i) if (!((i>=0xB8 && i<0xBC)||(i>=0x138 && i<0x13C)) && slot.bytes[i]!=saved.bytes[i]) {
        reason="sound update crossed unrelated fields"; return false;
    }
    const auto changed=slot; ApplySoundUpdateFields(slot,1,2,0,3);
    if (slot.bytes!=changed.bytes) { reason="disabled update flags modified a slot"; return false; }
    reason.clear(); return true;
}


bool BindNativeConsumers(const BuildManifest& manifest,const PeImageView& image,std::uintptr_t base,
    NativeConsumerBindings& out,std::string& reason) {
    NativeConsumerBindings candidate{};
    if (!BindNativeAudio(manifest,image,base,candidate.context.bindings,reason) ||
        !BindNativeChannelFree(manifest,image,base,candidate.free_channel,reason)) return false;
    for (const auto range:{std::pair<std::uint32_t,std::uint32_t>{0x33880,0x367},{0x33BF0,0x2D3},{0x32C60,0x3B2},
        {0x34560,0x130},{0x2A52F0,0x26},{0x1DF90,0x82},{0x1DFFA0,0x14},{0x1E0150,0x1A}}) {
        const auto* expected=image.rva_ptr(range.first,range.second);
        if (!expected || base>UINTPTR_MAX-range.first-range.second) { reason="query/update binding outside image"; return false; }
        std::vector<std::uint8_t> actual(range.second); SIZE_T read{};
        if (!ReadProcessMemory(GetCurrentProcess(),reinterpret_cast<const void*>(base+range.first),actual.data(),actual.size(),&read) ||
            read!=actual.size() || !NormalizeEngineHookBytes(base+range.first,actual) || std::memcmp(actual.data(),expected,actual.size())) { reason="native query/update executable bytes differ"; return false; }
    }
    candidate.base=base; candidate.growth=base+0x1DF90; candidate.allocate=base+0x1DFFA0; candidate.reallocate=base+0x1E0150;
    candidate.music_predicate=base+0x34560; candidate.copy_name=base+0x2A52F0;
    const auto view=CurrentNativeStorageView(base);
    if (!ValidateNativeStorageView(view,reason)) return false;
    candidate.context.active_count=view.active_count; candidate.context.active_indices=view.active_indices;
    candidate.context.channels=view.channels; candidate.context.capacity=view.capacity;
    candidate.context.sound_critical_section=base+0x510D50;
    out=candidate; reason.clear(); return true;
}
namespace {
struct ConsumerSoundScope {
    CRITICAL_SECTION* cs;
    explicit ConsumerSoundScope(std::uintptr_t address):cs(reinterpret_cast<CRITICAL_SECTION*>(address)) { EnterCriticalSection(cs); }
    ~ConsumerSoundScope() { LeaveCriticalSection(cs); }
};
bool ConsumerContextValid(const NativeConsumerBindings& bindings,std::string& reason) {
    const auto& c=bindings.context;
    if (!bindings.base || !c.channels || !c.active_count || !c.active_indices || !c.sound_critical_section ||
        !c.capacity || c.capacity>kTargetCapacity) { reason="native consumer context missing"; return false; }
    return true;
}
bool ConsumerSnapshot(const NativeConsumerBindings& bindings,NativeSnapshotOwner& owner,NativeConsumerSample& sample,std::string& reason) {
    std::int32_t count{};
    if (!PreprocessRead(reinterpret_cast<std::uintptr_t>(bindings.context.active_count),count,reason) ||
        !owner.Build(bindings.context.active_indices,count,bindings.context.capacity,reason)) return false;
    sample.source_count=count; return true;
}
void ReleaseConsumerSnapshot(NativeSnapshotOwner& owner,NativeConsumerSample& sample) noexcept {
    owner.Release(); const Vector32Metadata empty{};
    sample.routing_released=!std::memcmp(&owner.snapshot.auxiliary_routes,&empty,sizeof(empty));
}
}
bool QueryNativeActiveSounds(const NativeConsumerBindings& bindings,Vector32Metadata& output,NativeConsumerSample& sample,std::string& reason) {
    sample={}; if (!ConsumerContextValid(bindings,reason)) return false;
    ConsumerSoundScope sound(bindings.context.sound_critical_section);
    NativeSnapshotOwner owner(bindings.context.bindings);
    if (!ConsumerSnapshot(bindings,owner,sample,reason)) return false;
    float scale{}; if (!PreprocessRead(bindings.base+0x3958A8,scale,reason)) return false;
    for (std::int32_t p=0;p<owner.snapshot.count;++p) {
        const auto* channel=&bindings.context.channels[owner.snapshot.indices[p]];
        const auto sfx=ChannelField<std::uintptr_t>(*channel,8); std::uintptr_t userdata{};
        if (sfx) {
            std::uint32_t handle{};
            if (!PreprocessRead(sfx+0x10,handle,reason)) return false;
            if (handle!=0xFFFF) {
                std::uintptr_t pool{};
                if (!PreprocessRead(bindings.base+0x498148,pool,reason) || !pool ||
                    !PreprocessRead(pool+static_cast<std::uint16_t>(handle)*24ull+8,userdata,reason)) return false;
            }
        }
        ActiveSoundRecord row{}; PackActiveSoundRecord(*channel,reinterpret_cast<std::uintptr_t>(channel),userdata,scale,row);
        if (!NativeAppendRecord(bindings,output,row.data(),static_cast<std::uint32_t>(row.size()),reason)) return false;
        ++sample.appended;
    }
    ReleaseConsumerSnapshot(owner,sample); reason.clear(); return true;
}
bool QueryNativeMusicSounds(const NativeConsumerBindings& bindings,Vector32Metadata& output,NativeConsumerSample& sample,std::string& reason) {
    sample={}; if (!ConsumerContextValid(bindings,reason) || !bindings.music_predicate || !bindings.copy_name) return false;
    ConsumerSoundScope sound(bindings.context.sound_critical_section);
    NativeSnapshotOwner owner(bindings.context.bindings);
    if (!ConsumerSnapshot(bindings,owner,sample,reason)) return false;
    for (std::int32_t p=0;p<owner.snapshot.count;++p) {
        const auto* channel=&bindings.context.channels[owner.snapshot.indices[p]];
        if (!reinterpret_cast<bool (*)(const ChannelSlot*)>(bindings.music_predicate)(channel)) continue;
        std::uintptr_t name{};
        if (!NativeVirtual(ChannelField<std::uintptr_t>(*channel,8),0,name,reason)) return false;
        MusicSoundRecord row{};
        reinterpret_cast<void (*)(void*,const char*,std::size_t)>(bindings.copy_name)(row.data(),reinterpret_cast<const char*>(name),128);
        std::int32_t position{};
        if (!NativeVirtual(ChannelField<std::uintptr_t>(*channel,0x10),0x68,position,reason)) return false;
        std::memcpy(row.data()+0x80,&position,4);
        const auto volume=ChannelField<std::uint16_t>(*channel,0xB8); std::memcpy(row.data()+0x84,&volume,2);
        if (!NativeAppendRecord(bindings,output,row.data(),static_cast<std::uint32_t>(row.size()),reason)) return false;
        ++sample.appended;
    }
    ReleaseConsumerSnapshot(owner,sample); reason.clear(); return true;
}
bool UpdateNativeSound(const NativeConsumerBindings& bindings,std::int32_t source,std::int32_t channel,std::uintptr_t sfx,
    std::int32_t volume,std::int32_t pitch,std::uint32_t flags,std::int32_t route,NativeConsumerSample& sample,std::string& reason) {
    sample={}; if (!ConsumerContextValid(bindings,reason) || !bindings.free_channel) return false;
    ConsumerSoundScope sound(bindings.context.sound_critical_section);
    // Original entry dereferences the sfx vtable unconditionally.
    std::uintptr_t name{}; if (!NativeVirtual(sfx,0,name,reason)) return false;
    bool special=false;
    if (name) for (std::size_t i=0;i<4096;++i) {
        char c{}; if (!PreprocessRead(name+i,c,reason)) return false;
        if (c=='!') { special=true; break; }
        if (!IsSoundPrefix(static_cast<std::uint8_t>(c))) break;
        if (i==4095) { reason="native sound modifier prefix exceeds read bound"; return false; }
    }
    NativeSnapshotOwner owner(bindings.context.bindings);
    if (!ConsumerSnapshot(bindings,owner,sample,reason)) return false;
    for (std::int32_t p=0;p<owner.snapshot.count;++p) {
        auto* slot=const_cast<ChannelSlot*>(&bindings.context.channels[owner.snapshot.indices[p]]);
        if (!MatchesSoundUpdate(*slot,source,channel,sfx,flags,special)) continue;
        ApplySoundUpdateFields(*slot,volume,pitch,flags,route); ++sample.matched;
        if (flags&4) { bindings.free_channel(slot); ++sample.freed; }
        if (special || !(flags&0x200)) break;
    }
    ReleaseConsumerSnapshot(owner,sample); reason.clear(); return true;
}


bool PackLegacyIndexCarrier(const ExpandedSnapshot& full,std::uintptr_t pointer,const Vector32Metadata& routes,
    OriginalSnapshot& out,std::string& reason) {
    ExpandedSnapshot validated{};
    if (!CopySnapshotIndices(full.indices.data(),full.count,kTargetCapacity,validated,reason) ||
        routes.size<0 || routes.size>512 || routes.allocation_count<routes.size || routes.allocation_count<0 ||
        routes.memory!=routes.elements || (!routes.memory && routes.allocation_count)) {
        if (reason.empty()) reason="invalid legacy carrier routing"; return false;
    }
    if (full.count) {
        const auto bytes=static_cast<std::size_t>(routes.allocation_count)*4;
        const auto index_bytes=static_cast<std::size_t>(full.count)*2;
        if (!routes.memory || routes.grow_size<0 || !pointer || pointer%2 || routes.memory>UINTPTR_MAX-bytes ||
            pointer<routes.memory+static_cast<std::size_t>(routes.size)*4 || pointer>routes.memory+bytes ||
            index_bytes>routes.memory+bytes-pointer || std::memcmp(reinterpret_cast<const void*>(pointer),full.indices.data(),index_bytes)) {
            reason="legacy index payload lacks unique route-owned storage"; return false;
        }
    } else if (pointer) { reason="empty legacy carrier has an index pointer"; return false; }
    OriginalSnapshot candidate{}; candidate.count=full.count; candidate.route_mask=full.route_mask;
    candidate.auxiliary_routes=routes;
    std::memcpy(candidate.indices.data(),&pointer,sizeof(pointer));
    out=candidate; reason.clear(); return true;
}
bool BuildNativeLegacyCarrier(const NativeConsumerBindings& bindings,const std::int16_t* indices,std::int32_t count,
    OriginalSnapshot& out,std::string& reason) {
    if (!ConsumerContextValid(bindings,reason)) return false;
    if (out.auxiliary_routes.memory || out.auxiliary_routes.allocation_count || out.auxiliary_routes.size || out.auxiliary_routes.elements) {
        reason="legacy constructor output already owns route memory"; return false;
    }
    ConsumerSoundScope sound(bindings.context.sound_critical_section);
    NativeSnapshotOwner owner(bindings.context.bindings);
    if (!owner.Build(indices,count,bindings.context.capacity,reason)) return false;
    if (!count) {
        OriginalSnapshot candidate{}; candidate.route_mask=owner.snapshot.route_mask;
        candidate.auxiliary_routes=owner.snapshot.auxiliary_routes; owner.snapshot.auxiliary_routes={};
        out=candidate; reason.clear(); return true;
    }
    if (!bindings.allocate || !bindings.context.bindings.release_vector) { reason="legacy index allocator not bound"; return false; }
    const auto& routes=owner.snapshot.auxiliary_routes;
    const auto route_bytes=static_cast<std::size_t>(routes.size)*4;
    const auto bytes=(route_bytes+static_cast<std::size_t>(count)*2+3)&~std::size_t{3};
    void* memory=reinterpret_cast<void* (*)(std::size_t)>(bindings.allocate)(bytes);
    if (!memory) { reason="legacy route/index allocation failed"; return false; }
    struct PayloadOwner {
        void* memory; NativeVectorFree free;
        ~PayloadOwner() { if (memory) free(memory); }
    } payload{memory,bindings.context.bindings.release_vector};
    if (route_bytes) std::memcpy(memory,reinterpret_cast<const void*>(routes.memory),route_bytes);
    auto* index_data=static_cast<std::uint8_t*>(memory)+route_bytes;
    std::memcpy(index_data,owner.snapshot.indices.data(),static_cast<std::size_t>(count)*2);
    const auto address=reinterpret_cast<std::uintptr_t>(memory);
    const Vector32Metadata combined{address,static_cast<std::int32_t>(bytes/4),0,routes.size,0,address};
    if (!PackLegacyIndexCarrier(owner.snapshot,reinterpret_cast<std::uintptr_t>(index_data),combined,out,reason)) return false;
    payload.memory=nullptr;
    // The original caller's route destructor now owns the combined allocation.
    // These consumers never grow or mutate their captured auxiliary route vector.
    owner.Release(); reason.clear(); return true;
}
bool EncodeLegacyIndexLoad(const std::vector<std::uint8_t>& source,std::vector<std::uint8_t>& out,std::string& reason) {
    ZydisDecoder decoder; ZydisDecoderInit(&decoder,ZYDIS_MACHINE_MODE_LONG_64,ZYDIS_STACK_WIDTH_64);
    ZydisDecodedInstruction ins{}; ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT]{};
    if (source.size()<3 || (source[0]&0xF8)!=0x48 || source[1]!=0x8D ||
        !ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder,source.data(),source.size(),&ins,ops)) ||
        ins.length!=source.size() || ins.mnemonic!=ZYDIS_MNEMONIC_LEA || ins.operand_count_visible!=2 ||
        ops[0].type!=ZYDIS_OPERAND_TYPE_REGISTER || ops[0].size!=64 || ops[1].type!=ZYDIS_OPERAND_TYPE_MEMORY ||
        (ops[1].mem.base!=ZYDIS_REGISTER_RSP && ops[1].mem.base!=ZYDIS_REGISTER_RBP) || ops[1].mem.index!=ZYDIS_REGISTER_NONE) {
        reason="legacy index load requires one exact stack LEA"; return false;
    }
    auto candidate=source; candidate[1]=0x8B;
    ZydisDecodedInstruction check{}; ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT]{};
    if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder,candidate.data(),candidate.size(),&check,operands)) ||
        check.length!=ins.length || check.mnemonic!=ZYDIS_MNEMONIC_MOV || operands[0].reg.value!=ops[0].reg.value ||
        operands[1].mem.base!=ops[1].mem.base || operands[1].mem.disp.value!=ops[1].mem.disp.value || operands[1].size!=64) {
        reason="legacy pointer load changed its operand or instruction length"; return false;
    }
    out=std::move(candidate); reason.clear(); return true;
}
bool BuildLegacyConsumerLoadPlan(const BuildManifest& manifest,const PeImageView& image,std::uintptr_t base,
    std::vector<MemoryPatch>& out,std::string& reason) {
    if (!manifest.supported || manifest.sha256!=kExpectedSha || !base || base>UINTPTR_MAX-image.image_size) {
        reason="unsupported legacy constructor Build"; return false;
    }
    struct Site { std::uint32_t load,constructor,root; ZydisRegister stack; std::int64_t displacement; };
    const std::array<Site,14> sites{{
        {0x2D5EF,0x2D5CE,0x2D1D0,ZYDIS_REGISTER_RSP,0x24}, {0x2E416,0x2E3FC,0x2E310,ZYDIS_REGISTER_RSP,0x34},
        {0x32D45,0x32D32,0x32C60,ZYDIS_REGISTER_RBP,0xF4}, {0x32EA7,0x32E88,0x32C60,ZYDIS_REGISTER_RSP,0x44},
        {0x33586,0x33575,0x33530,ZYDIS_REGISTER_RSP,0x24}, {0x33917,0x338DD,0x33880,ZYDIS_REGISTER_RSP,0x74},
        {0x33C7D,0x33C4C,0x33BF0,ZYDIS_REGISTER_RBP,-0x4C}, {0x37AB0,0x37AA1,0x37130,ZYDIS_REGISTER_RBP,-0xC},
        {0x37EE5,0x37EBB,0x37E20,ZYDIS_REGISTER_RSP,0x24}, {0x38152,0x3813A,0x380D0,ZYDIS_REGISTER_RSP,0x24},
        {0x385DD,0x38569,0x382C0,ZYDIS_REGISTER_RBP,-0x3C}, {0x386A2,0x38569,0x382C0,ZYDIS_REGISTER_RBP,-0x3C},
        {0x389BB,0x3899D,0x382C0,ZYDIS_REGISTER_RBP,0x174}, {0x39747,0x39720,0x396E0,ZYDIS_REGISTER_RSP,0xB4}
    }};
    for (const auto& ref:manifest.references) if (ref.kind=="snapshot_call" && ref.instruction!=0x4A1F1 &&
        std::none_of(sites.begin(),sites.end(),[&](const Site& site){return site.constructor==ref.instruction && site.root==ref.root;})) {
        reason="snapshot caller lacks a verified legacy pointer consumer"; return false;
    }
    ZydisDecoder decoder; ZydisDecoderInit(&decoder,ZYDIS_MACHINE_MODE_LONG_64,ZYDIS_STACK_WIDTH_64);
    std::vector<MemoryPatch> candidate;
    for (const auto& site:sites) {
        if (std::none_of(manifest.references.begin(),manifest.references.end(),[&](const Reference& r){
            return r.kind=="snapshot_call" && r.instruction==site.constructor && r.root==site.root;
        })) { reason="legacy constructor call missing from inventory"; return false; }
        const auto* bytes=image.rva_ptr(site.load,ZYDIS_MAX_INSTRUCTION_LENGTH);
        ZydisDecodedInstruction ins{}; ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT]{};
        if (!bytes || !ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder,bytes,ZYDIS_MAX_INSTRUCTION_LENGTH,&ins,ops)) ||
            ops[1].type!=ZYDIS_OPERAND_TYPE_MEMORY || ops[1].mem.base!=site.stack || ops[1].mem.disp.value!=site.displacement) {
            reason="legacy consumer stack coordinate differs"; return false;
        }
        MemoryPatch patch; patch.address=base+site.load; patch.expected.assign(bytes,bytes+ins.length);
        if (!EncodeLegacyIndexLoad(patch.expected,patch.replacement,reason)) return false;
        candidate.push_back(std::move(patch));
    }
    out=std::move(candidate); reason.clear(); return true;
}
bool RunLegacyCarrierSelfChecks(std::string& reason) {
    struct Payload { std::array<std::int32_t,3> routes{7,12,19}; std::array<std::int16_t,512> indices{}; } payload;
    for (std::int32_t i=0;i<512;++i) payload.indices[i]=static_cast<std::int16_t>(511-i);
    ExpandedSnapshot full{}; full.count=512; full.route_mask=0xA8; full.indices=payload.indices;
    const auto memory=reinterpret_cast<std::uintptr_t>(&payload);
    const auto pointer=reinterpret_cast<std::uintptr_t>(payload.indices.data());
    const Vector32Metadata routes{memory,259,0,3,0,memory};
    struct Guarded { std::uint64_t before{0xA1B2C3D4E5F61234ull}; OriginalSnapshot value{};
        std::uint64_t after{0x12345678ABCD9876ull}; } shell;
    if (!PackLegacyIndexCarrier(full,pointer,routes,shell.value,reason)) return false;
    std::uintptr_t actual{}; std::memcpy(&actual,shell.value.indices.data(),sizeof(actual));
    if (shell.value.count!=512 || actual!=pointer || shell.value.route_mask!=0xA8 ||
        std::memcmp(&routes,&shell.value.auxiliary_routes,sizeof(routes)) ||
        reinterpret_cast<const std::int16_t*>(actual)[511]!=0 ||
        shell.before!=0xA1B2C3D4E5F61234ull || shell.after!=0x12345678ABCD9876ull) {
        reason="legacy carrier lost final index, route ownership or stack bounds"; return false;
    }
    const auto saved=shell.value; full.indices[511]=512;
    if (PackLegacyIndexCarrier(full,pointer,routes,shell.value,reason) || std::memcmp(&shell.value,&saved,sizeof(saved))) {
        reason="invalid legacy index changed carrier"; return false;
    }
    full.indices[511]=0;
    if (PackLegacyIndexCarrier(full,memory,routes,shell.value,reason) || std::memcmp(&shell.value,&saved,sizeof(saved))) {
        reason="legacy indices overlapped route data"; return false;
    }
    const std::vector<std::uint8_t> lea{0x4C,0x8D,0x44,0x24,0x24}; std::vector<std::uint8_t> load;
    if (!EncodeLegacyIndexLoad(lea,load,reason) || load!=std::vector<std::uint8_t>({0x4C,0x8B,0x44,0x24,0x24})) return false;
    const auto saved_load=load;
    if (EncodeLegacyIndexLoad({0x48,0x8D,0x05,0,0,0,0},load,reason) || load!=saved_load ||
        EncodeLegacyIndexLoad({0x48,0x8B,0x44,0x24,0x24},load,reason) || load!=saved_load) {
        reason="non-stack/non-LEA instruction changed carrier load plan"; return false;
    }
    reason.clear(); return true;
}

LegacyConstructorRoute SelectLegacyConstructorRoute(const NativeLegacyConstructorContext& context,
    const std::int32_t* source,std::uintptr_t caller) noexcept {
    if (!source || !caller || !context.original || !context.consumers.context.active_count ||
        !context.consumers.context.capacity || context.consumers.context.capacity>kTargetCapacity) return LegacyConstructorRoute::Reject;
    const bool legacy=std::find(context.caller_returns.begin(),context.caller_returns.end(),caller)!=context.caller_returns.end();
    if (legacy) return source==context.consumers.context.active_count?LegacyConstructorRoute::Carrier:LegacyConstructorRoute::Reject;
    // Original mix owner and module's private zero-count route builder still
    // use inline indices. At512 an unknown original consumer must not receive
    // the expanded active table in its old128-entry stack allocation.
    if (source==context.consumers.context.active_count && context.consumers.context.capacity>kOldCapacity)
        return LegacyConstructorRoute::Reject;
    return LegacyConstructorRoute::Original;
}
bool EncodeLegacyConstructorThunk(std::uintptr_t context,std::uintptr_t entry,std::array<std::uint8_t,34>& out,std::string& reason) {
    if (!context || !entry) { reason="invalid legacy constructor thunk addresses"; return false; }
    std::array<std::uint8_t,34> candidate{0x49,0x89,0xD0,0x48,0x89,0xCA,0x48,0xB9};
    std::memcpy(candidate.data()+8,&context,8);
    const std::array<std::uint8_t,10> tail{0x4C,0x8B,0x0C,0x24,0xFF,0x25,0,0,0,0};
    std::memcpy(candidate.data()+16,tail.data(),tail.size()); std::memcpy(candidate.data()+26,&entry,8);
    out=candidate; reason.clear(); return true;
}
bool BindNativeLegacyConstructor(const BuildManifest& manifest,const PeImageView& image,std::uintptr_t base,
    NativeSnapshotBuilder original,NativeLegacyConstructorContext& out,std::string& reason) {
    if (!original || out.original) { reason="legacy constructor missing gateway or context already bound"; return false; }
    NativeConsumerBindings bindings{}; std::vector<MemoryPatch> loads;
    if (!BindNativeConsumers(manifest,image,base,bindings,reason) ||
        !BuildLegacyConsumerLoadPlan(manifest,image,base,loads,reason)) return false;
    std::array<std::uintptr_t,13> callers{}; std::size_t count{};
    for (const auto& ref:manifest.references) if (ref.kind=="snapshot_call" && ref.instruction!=0x4A1F1) {
        const auto* call=image.rva_ptr(ref.instruction,5); std::int32_t delta{};
        if (!call || *call!=0xE8 || count==callers.size()) { reason="invalid legacy constructor caller instruction"; return false; }
        std::memcpy(&delta,call+1,4);
        if (static_cast<std::int64_t>(ref.instruction)+5+delta!=0x2C110 || base>UINTPTR_MAX-ref.instruction-5) {
            reason="legacy caller does not target original constructor"; return false;
        }
        callers[count++]=base+ref.instruction+5;
    }
    std::sort(callers.begin(),callers.end());
    if (count!=callers.size() || !callers[0] || std::adjacent_find(callers.begin(),callers.end())!=callers.end()) {
        reason="legacy constructor caller set incomplete or duplicated"; return false;
    }
    // Private NativeSnapshotOwner's zero-count route call must bypass our hook.
    bindings.context.bindings.build_routes=original;
    out.consumers=bindings; out.original=original; out.caller_returns=callers;
    reason.clear(); return true;
}
namespace {
void EmptyLegacyHeader(OriginalSnapshot* out) noexcept {
    if (!out) return;
    out->count=0; const std::uintptr_t empty{}; std::memcpy(out->indices.data(),&empty,sizeof(empty)); out->route_mask=0;
    // Preserve an existing routing owner for the original caller's destructor.
}
void LegacyConstructorEntry(NativeLegacyConstructorContext* context,const std::int32_t* source,
    OriginalSnapshot* out,std::uintptr_t caller) noexcept {
    if (!context || !out) return;
    ++context->calls;
    try {
        ConsumerSoundScope sound(context->consumers.context.sound_critical_section);
        const auto route=SelectLegacyConstructorRoute(*context,source,caller);
        std::int32_t count{}; std::string reason;
        if (route==LegacyConstructorRoute::Reject || !PreprocessRead(reinterpret_cast<std::uintptr_t>(source),count,reason) || count<0) {
            ++context->errors; EmptyLegacyHeader(out); return;
        }
        if (route==LegacyConstructorRoute::Original) {
            if (count>static_cast<std::int32_t>(kOldCapacity)) { ++context->errors; EmptyLegacyHeader(out); return; }
            ++context->passthrough; context->original(source,out); return;
        }
        if (out->auxiliary_routes.memory || out->auxiliary_routes.elements || out->auxiliary_routes.size ||
            out->auxiliary_routes.allocation_count || count>static_cast<std::int32_t>(context->consumers.context.capacity)) {
            ++context->errors; EmptyLegacyHeader(out); return;
        }
        OriginalSnapshot candidate{};
        if (!BuildNativeLegacyCarrier(context->consumers,context->consumers.context.active_indices,count,candidate,reason)) {
            ++context->errors; EmptyLegacyHeader(out); return;
        }
        *out=candidate; ++context->carriers;
    } catch (...) {
        ++context->errors; EmptyLegacyHeader(out);
    }
}
}
NativeLegacyConstructorThunk::~NativeLegacyConstructorThunk() noexcept {
    if (page_ && !retained_) VirtualFree(page_,0,MEM_RELEASE);
}
bool NativeLegacyConstructorThunk::Prepare(NativeLegacyConstructorContext& context,std::string& reason) {
    if (page_ || !context.original || context.consumers.context.bindings.build_routes!=context.original ||
        !context.consumers.context.bindings.release_vector || !context.consumers.allocate ||
        !ConsumerContextValid(context.consumers,reason) ||
        !context.caller_returns[0] || !std::is_sorted(context.caller_returns.begin(),context.caller_returns.end()) ||
        std::adjacent_find(context.caller_returns.begin(),context.caller_returns.end())!=context.caller_returns.end()) {
        reason="invalid, recursive or already prepared legacy constructor context"; return false;
    }
    std::array<std::uint8_t,34> code{};
    if (!EncodeLegacyConstructorThunk(reinterpret_cast<std::uintptr_t>(&context),reinterpret_cast<std::uintptr_t>(&LegacyConstructorEntry),code,reason)) return false;
    auto* page=VirtualAlloc(nullptr,code.size(),MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);
    if (!page) { reason="legacy constructor thunk allocation failed"; return false; }
    std::memcpy(page,code.data(),code.size()); DWORD old{};
    if (!VirtualProtect(page,code.size(),PAGE_EXECUTE_READ,&old) || !FlushInstructionCache(GetCurrentProcess(),page,code.size())) {
        VirtualFree(page,0,MEM_RELEASE); reason="legacy constructor thunk protection/cache failed"; return false;
    }
    page_=page; reason.clear(); return true;
}
bool RunLegacyConstructorSelfChecks(std::string& reason) {
    constexpr std::uintptr_t context_address=0x1234567812345000ull,target=0x3456789034560000ull;
    std::array<std::uint8_t,34> code{};
    if (!EncodeLegacyConstructorThunk(context_address,target,code,reason)) return false;
    ZydisDecoder decoder; ZydisDecoderInit(&decoder,ZYDIS_MACHINE_MODE_LONG_64,ZYDIS_STACK_WIDTH_64);
    ZydisDecodedInstruction instruction{}; ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT]{};
    const auto decode=[&](std::size_t offset) { return ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder,code.data()+offset,
        code.size()-offset,&instruction,operands)); };
    if (!decode(0) || instruction.length!=3 || instruction.mnemonic!=ZYDIS_MNEMONIC_MOV ||
        operands[0].reg.value!=ZYDIS_REGISTER_R8 || operands[1].reg.value!=ZYDIS_REGISTER_RDX ||
        !decode(3) || instruction.length!=3 || instruction.mnemonic!=ZYDIS_MNEMONIC_MOV ||
        operands[0].reg.value!=ZYDIS_REGISTER_RDX || operands[1].reg.value!=ZYDIS_REGISTER_RCX ||
        !decode(6) || instruction.length!=10 || operands[0].reg.value!=ZYDIS_REGISTER_RCX || operands[1].imm.value.u!=context_address ||
        !decode(16) || instruction.length!=4 || operands[0].reg.value!=ZYDIS_REGISTER_R9 ||
        operands[1].mem.base!=ZYDIS_REGISTER_RSP || operands[1].mem.disp.value ||
        !decode(20) || instruction.length!=6 || instruction.mnemonic!=ZYDIS_MNEMONIC_JMP ||
        operands[0].mem.base!=ZYDIS_REGISTER_RIP || operands[0].mem.disp.value) {
        reason="legacy constructor ABI remapping or caller capture differs"; return false;
    }
    std::uintptr_t actual{}; std::memcpy(&actual,code.data()+26,8);
    if (actual!=target) { reason="legacy constructor target truncated"; return false; }
    const auto saved=code;
    if (EncodeLegacyConstructorThunk(0,target,code,reason) || code!=saved ||
        EncodeLegacyConstructorThunk(context_address,0,code,reason) || code!=saved) {
        reason="invalid constructor thunk addresses changed output"; return false;
    }
    // Routing descriptors only; never call a substitute Source constructor.
    NativeLegacyConstructorContext context;
    context.original=reinterpret_cast<NativeSnapshotBuilder>(target);
    context.consumers.context.active_count=reinterpret_cast<const std::int32_t*>(context_address);
    context.consumers.context.capacity=128;
    for (std::size_t i=0;i<context.caller_returns.size();++i) context.caller_returns[i]=0x180030005ull+i*0x100;
    const auto* source=context.consumers.context.active_count;
    const auto* private_empty=reinterpret_cast<const std::int32_t*>(context_address+8);
    if (SelectLegacyConstructorRoute(context,source,context.caller_returns[0])!=LegacyConstructorRoute::Carrier ||
        SelectLegacyConstructorRoute(context,source,context.caller_returns[12])!=LegacyConstructorRoute::Carrier ||
        SelectLegacyConstructorRoute(context,private_empty,context.caller_returns[0])!=LegacyConstructorRoute::Reject ||
        SelectLegacyConstructorRoute(context,source,0x18004A1F6ull)!=LegacyConstructorRoute::Original ||
        SelectLegacyConstructorRoute(context,private_empty,0x7FFF12340000ull)!=LegacyConstructorRoute::Original) {
        reason="constructor did not distinguish adapted callers from original/private routes"; return false;
    }
    context.consumers.context.capacity=512;
    if (SelectLegacyConstructorRoute(context,source,0x18004A1F6ull)!=LegacyConstructorRoute::Reject ||
        SelectLegacyConstructorRoute(context,private_empty,0x7FFF12340000ull)!=LegacyConstructorRoute::Original ||
        SelectLegacyConstructorRoute(context,nullptr,context.caller_returns[0])!=LegacyConstructorRoute::Reject) {
        reason="expanded constructor permits unknown original active-table consumer"; return false;
    }
    reason.clear(); return true;
}

}
