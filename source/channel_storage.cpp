#include "manifest.hpp"
#include <cstring>
#include <cstddef>
#include <new>
#include <Zydis.h>
#include <windows.h>
#include <sstream>
#include <iomanip>
#include <algorithm>

namespace channel_expand {
namespace {
constexpr std::array<std::uint64_t, 2> kGuard{0xC017A11E5120ABCDull, 0x159BDF2468ACE001ull};
constexpr std::size_t kReverseOffset = 0x128;
static_assert(sizeof(ChannelSlot) == 320 && offsetof(ActiveList, indices) == 4);
static_assert(kTargetCapacity < INT16_MAX);
std::int16_t Reverse(const ExpandedStorage& s, std::uint32_t index) noexcept {
    std::int16_t value{};
    std::memcpy(&value, s.channels->slots[index].bytes.data()+kReverseOffset, sizeof(value));
    return value;
}
void SetReverse(ExpandedStorage& s, std::uint32_t index, std::int16_t value) noexcept {
    std::memcpy(s.channels->slots[index].bytes.data()+kReverseOffset, &value, sizeof(value));
}
bool Guards(const ExpandedStorage& s) noexcept {
    return s.channels && s.active && s.channels->before == kGuard && s.channels->after == kGuard &&
        s.active->before == kGuard && s.active->after == kGuard;
}
}
NativeStorageView OriginalNativeStorageView(std::uintptr_t base) noexcept {
    if (!base || base>UINTPTR_MAX-kChannelsRva-kOldCapacity*kChannelStride) return {};
    return {reinterpret_cast<ChannelSlot*>(base+kChannelsRva),reinterpret_cast<const std::int32_t*>(base+kActiveRva),
        reinterpret_cast<const std::int16_t*>(base+kActiveRva+4),kOldCapacity};
}
bool ValidateNativeStorageView(const NativeStorageView& view,std::string& reason) {
    const auto channels=reinterpret_cast<std::uintptr_t>(view.channels),active=reinterpret_cast<std::uintptr_t>(view.active_count);
    const auto indices=reinterpret_cast<std::uintptr_t>(view.active_indices);
    if ((view.capacity!=kOldCapacity && view.capacity!=kTargetCapacity) || !channels || channels%alignof(ChannelSlot) ||
        !active || active%alignof(std::int32_t) || active>UINTPTR_MAX-4 || indices!=active+4) {
        reason="invalid native storage capacity, alignment or contiguous active table"; return false;
    }
    const auto channel_bytes=static_cast<std::size_t>(view.capacity)*kChannelStride;
    const auto active_bytes=4+static_cast<std::size_t>(view.capacity)*2;
    if (channels>UINTPTR_MAX-channel_bytes || active>UINTPTR_MAX-active_bytes ||
        (channels<active+active_bytes && active<channels+channel_bytes)) {
        reason="native storage extent overflow or overlap"; return false;
    }
    // Shape only: this does not prove ownership, mixer lifetime or quiescence.
    reason.clear(); return true;
}
bool RunStorageViewSelfChecks(std::string& reason) {
    ExpandedStorage storage;
    if (!AllocateStorage(storage,reason)) return false;
    const NativeStorageView view{storage.channels->slots.data(),&storage.active->list.count,storage.active->list.indices.data(),512};
    if (!ValidateNativeStorageView(view,reason)) return false;
    if (!AddActive(storage,511) || *view.active_count!=1 || view.active_indices[0]!=511 ||
        view.channels+511!=&storage.channels->slots[511]) { reason="512 storage view omitted final channel/active index"; return false; }
    auto wrong=view; wrong.active_indices++;
    if (ValidateNativeStorageView(wrong,reason)) { reason="discontiguous active table accepted"; return false; }
    wrong=view; wrong.capacity=129;
    if (ValidateNativeStorageView(wrong,reason)) { reason="unsupported storage capacity accepted"; return false; }
    wrong=view; wrong.active_count=reinterpret_cast<const std::int32_t*>(view.channels);
    wrong.active_indices=reinterpret_cast<const std::int16_t*>(reinterpret_cast<std::uintptr_t>(wrong.active_count)+4);
    if (ValidateNativeStorageView(wrong,reason)) { reason="overlapping channel/active storage accepted"; return false; }
    const auto original=OriginalNativeStorageView(0x180000000ull);
    if (!ValidateNativeStorageView(original,reason) || original.capacity!=128 ||
        reinterpret_cast<std::uintptr_t>(original.channels)!=0x180506D30ull ||
        OriginalNativeStorageView(0).capacity || OriginalNativeStorageView(UINTPTR_MAX).capacity) return false;
    reason.clear(); return true;
}
bool AllocateStorage(ExpandedStorage& out, std::string& reason) {
    if (out.channels || out.active) { reason = "storage already allocated"; return false; }
    ExpandedStorage s;
    s.channels.reset(new (std::nothrow) ChannelAllocation{});
    s.active.reset(new (std::nothrow) ActiveAllocation{});
    if (!s.channels || !s.active) { reason = "storage allocation failed"; return false; }
    s.channels->before = s.channels->after = s.active->before = s.active->after = kGuard;
    out = std::move(s); reason.clear(); return true;
}
bool CheckStorageInvariants(const ExpandedStorage& s, std::string& reason) {
    if (!Guards(s)) { reason = "storage guard/allocation invalid"; return false; }
    const auto count = s.active->list.count;
    if (count < 0 || count > static_cast<std::int32_t>(kTargetCapacity) ||
        s.total_channels < static_cast<std::int32_t>(kDynamicCapacity) || s.total_channels > static_cast<std::int32_t>(kTargetCapacity)) {
        reason = "count or total out of bounds"; return false;
    }
    std::array<bool, kTargetCapacity> seen{};
    for (std::int32_t p = 0; p < count; ++p) {
        const auto i = s.active->list.indices[p];
        if (i < 0 || i >= static_cast<std::int32_t>(kTargetCapacity) || seen[i] || Reverse(s, i) != p+1) {
            reason = "index/duplicate/reverse position invalid"; return false;
        }
        seen[i] = true;
    }
    for (std::uint32_t i = 0; i < kTargetCapacity; ++i) {
        if (!seen[i] && Reverse(s, i) != 0) { reason = "inactive slot has reverse position"; return false; }
    }
    reason.clear(); return true;
}
bool AddActive(ExpandedStorage& s, std::uint32_t i) noexcept {
    if (i >= kTargetCapacity || !Guards(s)) return false;
    auto& list = s.active->list;
    if (list.count < 0 || list.count >= static_cast<std::int32_t>(kTargetCapacity) || Reverse(s, i) != 0) return false;
    list.indices[list.count] = static_cast<std::int16_t>(i);
    ++list.count;
    SetReverse(s, i, static_cast<std::int16_t>(list.count)); return true;
}
bool RemoveActive(ExpandedStorage& s, std::uint32_t i) noexcept {
    if (i >= kTargetCapacity || !Guards(s)) return false;
    auto& list = s.active->list;
    if (list.count <= 0 || list.count > static_cast<std::int32_t>(kTargetCapacity)) return false;
    const auto pos = Reverse(s, i);
    if (pos <= 0 || pos > list.count || list.indices[pos-1] != static_cast<std::int16_t>(i)) return false;
    const auto moved = list.indices[list.count-1];
    if (moved < 0 || moved >= static_cast<std::int32_t>(kTargetCapacity) || Reverse(s, moved) != list.count) return false;
    --list.count;
    if (pos-1 < list.count) {
        list.indices[pos-1] = moved;
        SetReverse(s, moved, pos);
    }
    list.indices[list.count] = 0;
    SetReverse(s, i, 0); return true;
}
bool RunStorageSelfChecks(std::string& reason) {
    ExpandedStorage s;
    if (!AllocateStorage(s, reason)) return false;
    if (!CheckStorageInvariants(s, reason)) return false;
    for (std::uint32_t i = 0; i < kTargetCapacity; ++i) {
        if (!AddActive(s, i)) { reason = "valid active index rejected"; return false; }
        if (!CheckStorageInvariants(s, reason)) return false;
    }
    std::int16_t pos{};
    std::memcpy(&pos, s.channels->slots[511].bytes.data()+0x128, sizeof(pos));
    if (s.active->list.count != 512 || s.active->list.indices[511] != 511 || pos != 512) {
        reason = "511 index/512 reverse position truncated"; return false;
    }
    if (AddActive(s, 512) || AddActive(s, 511) || AddActive(s, UINT32_MAX)) {
        reason = "out-of-range/full/duplicate index accepted"; return false;
    }
    for (const std::uint32_t i : {0u, 255u, 511u}) {
        if (!RemoveActive(s, i) || !CheckStorageInvariants(s, reason)) { reason = "swap removal failed: " + reason; return false; }
        if (RemoveActive(s, i)) { reason = "duplicate removal accepted"; return false; }
    }
    while (s.active->list.count) {
        const auto index = static_cast<std::uint32_t>(s.active->list.indices[0]);
        if (!RemoveActive(s, index) || !CheckStorageInvariants(s, reason)) return false;
    }
    if (RemoveActive(s, 512) || RemoveActive(s, UINT32_MAX)) { reason = "invalid removal accepted"; return false; }
    // Preserve bytes outside the two-byte reverse position, including GUID and mixer pointer.
    auto& slot = s.channels->slots[128].bytes;
    slot.fill(0x5A); slot[0x128] = slot[0x129] = 0;
    const auto original = slot;
    if (!AddActive(s, 128) || !RemoveActive(s, 128) || slot != original) { reason = "unrelated channel bytes changed"; return false; }
    // Actual corruption must fail invariant validation; this is not an engine API mock.
    s.active->after[0] ^= 1;
    if (CheckStorageInvariants(s, reason)) { reason = "damaged guard accepted"; return false; }
    s.active->after[0] ^= 1;
    if (!AddActive(s, 511)) { reason = "index reuse failed"; return false; }
    s.active->list.indices[0] = 512;
    if (CheckStorageInvariants(s, reason)) { reason = "damaged index accepted"; return false; }
    s.active->list.indices[0] = 511;
    std::int16_t zero = 0;
    std::memcpy(s.channels->slots[511].bytes.data()+0x128, &zero, sizeof(zero));
    if (CheckStorageInvariants(s, reason)) { reason = "broken reverse position accepted"; return false; }
    reason.clear(); return true;
}

namespace {
bool EncodeEngineBaseStorage(const std::vector<std::uint8_t>& source,std::uint32_t expected,
    std::uintptr_t base,std::uintptr_t target,std::vector<std::uint8_t>& out,std::string& reason) {
    ZydisDecoder decoder; ZydisDecoderInit(&decoder,ZYDIS_MACHINE_MODE_LONG_64,ZYDIS_STACK_WIDTH_64);
    ZydisDecodedInstruction ins{}; ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT]{};
    if (source.empty() || source.size()>ZYDIS_MAX_INSTRUCTION_LENGTH ||
        !ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder,source.data(),source.size(),&ins,ops)) ||
        ins.length!=source.size() || ins.raw.disp.size!=32 || ins.raw.disp.offset+4>source.size()) {
        reason="not one complete engine-base displacement instruction"; return false;
    }
    unsigned memory_count=0;
    for (std::uint8_t i=0;i<ins.operand_count_visible;++i) if (ops[i].type==ZYDIS_OPERAND_TYPE_MEMORY) {
        ++memory_count;
        if (ops[i].mem.base!=ZYDIS_REGISTER_RCX || ops[i].mem.index!=ZYDIS_REGISTER_R10 ||
            ops[i].mem.scale!=1 || ops[i].mem.disp.value!=expected) {
            reason="engine-base member operand differs from proven profiler form"; return false;
        }
    }
    if (memory_count!=1) { reason="engine-base member requires one memory operand"; return false; }
    std::int32_t displacement{};
    if (target>=base) {
        if (target-base>INT32_MAX) { reason="engine-base member exceeds positive disp32"; return false; }
        displacement=static_cast<std::int32_t>(target-base);
    } else {
        const auto distance=base-target;
        if (distance>0x80000000ull) { reason="engine-base member exceeds negative disp32"; return false; }
        displacement=distance==0x80000000ull?INT32_MIN:-static_cast<std::int32_t>(distance);
    }
    auto candidate=source; std::memcpy(candidate.data()+ins.raw.disp.offset,&displacement,4);
    out=std::move(candidate); reason.clear(); return true;
}
bool ProveProfilerEngineBase(const PeImageView& image,std::uintptr_t base,std::string& reason) {
    constexpr std::uint32_t anchor=0x2E41F,begin=0x2E426,end=0x2E6C4;
    ZydisDecoder decoder; ZydisDecoderInit(&decoder,ZYDIS_MACHINE_MODE_LONG_64,ZYDIS_STACK_WIDTH_64);
    ZydisDecodedInstruction ins{}; ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT]{};
    const auto* bytes=image.rva_ptr(anchor,7); ZyanU64 absolute{};
    if (!bytes || !ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder,bytes,7,&ins,ops)) || ins.length!=7 ||
        ins.mnemonic!=ZYDIS_MNEMONIC_LEA || ops[0].type!=ZYDIS_OPERAND_TYPE_REGISTER ||
        ops[0].reg.value!=ZYDIS_REGISTER_R10 || ops[1].type!=ZYDIS_OPERAND_TYPE_MEMORY ||
        ops[1].mem.base!=ZYDIS_REGISTER_RIP ||
        !ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&ins,&ops[1],base+anchor,&absolute)) || absolute!=base) {
        reason="profiler R10 engine-base anchor not proven"; return false;
    }
    std::vector<std::uint32_t> boundaries,targets;
    for (auto rva=begin;rva<end;) {
        bytes=image.rva_ptr(rva,ZYDIS_MAX_INSTRUCTION_LENGTH);
        if (!bytes || !ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder,bytes,ZYDIS_MAX_INSTRUCTION_LENGTH,&ins,ops)) ||
            !ins.length || rva+ins.length>end || ins.meta.category==ZYDIS_CATEGORY_CALL || ins.meta.category==ZYDIS_CATEGORY_RET) {
            reason="profiler engine-base loop is not a closed leaf interval"; return false;
        }
        boundaries.push_back(rva);
        for (std::uint8_t i=0;i<ins.operand_count;++i) {
            if (ops[i].type==ZYDIS_OPERAND_TYPE_REGISTER && (ops[i].actions & ZYDIS_OPERAND_ACTION_MASK_WRITE) &&
                (ops[i].reg.value==ZYDIS_REGISTER_R10 || ops[i].reg.value==ZYDIS_REGISTER_R10D ||
                 ops[i].reg.value==ZYDIS_REGISTER_R10W || ops[i].reg.value==ZYDIS_REGISTER_R10B)) {
                reason="profiler loop overwrites engine-base register"; return false;
            }
        }
        if (ins.meta.category==ZYDIS_CATEGORY_COND_BR || ins.meta.category==ZYDIS_CATEGORY_UNCOND_BR) {
            if (ops[0].type!=ZYDIS_OPERAND_TYPE_IMMEDIATE || !ops[0].imm.is_relative ||
                !ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&ins,&ops[0],base+rva,&absolute)) ||
                absolute<base+begin || absolute>=base+end) {
                reason="profiler loop branch escapes proven interval"; return false;
            }
            targets.push_back(static_cast<std::uint32_t>(absolute-base));
        }
        rva+=ins.length;
    }
    for (const auto target:targets) if (!std::binary_search(boundaries.begin(),boundaries.end(),target)) {
        reason="profiler loop branch targets an instruction interior"; return false;
    }
    reason.clear(); return true;
}
std::string RedirectHex(std::uintptr_t x) { std::ostringstream out; out << "0x" << std::hex << std::uppercase << x; return out.str(); }
std::string RedirectBytes(const std::vector<std::uint8_t>& bytes) {
    std::ostringstream out; out << std::hex << std::uppercase << std::setfill('0');
    for (std::size_t i=0;i<bytes.size();++i) { if (i) out << ' '; out << std::setw(2) << static_cast<unsigned>(bytes[i]); }
    return out.str();
}
}
bool EncodeRipStorageRedirect(const std::vector<std::uint8_t>& source,std::uintptr_t ip,std::uintptr_t expected,
    std::uintptr_t target,std::vector<std::uint8_t>& out,std::string& reason) {
    ZydisDecoder decoder; ZydisDecoderInit(&decoder,ZYDIS_MACHINE_MODE_LONG_64,ZYDIS_STACK_WIDTH_64);
    ZydisDecodedInstruction ins{}; ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT]{};
    if (source.empty() || source.size()>ZYDIS_MAX_INSTRUCTION_LENGTH ||
        !ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder,source.data(),source.size(),&ins,ops)) || ins.length!=source.size() ||
        ins.raw.disp.size!=32 || ins.raw.disp.offset+4>source.size() || ip>UINTPTR_MAX-ins.length) {
        reason="not one complete RIP-displacement instruction"; return false;
    }
    const auto next=ip+ins.length; bool found=false;
    for (std::uint8_t i=0;i<ins.operand_count_visible;++i) if (ops[i].type==ZYDIS_OPERAND_TYPE_MEMORY && ops[i].mem.base==ZYDIS_REGISTER_RIP) {
        const auto disp=ops[i].mem.disp.value;
        const auto distance=disp>=0?static_cast<std::uint64_t>(disp):static_cast<std::uint64_t>(-disp);
        if ((disp>=0 && next>UINTPTR_MAX-distance) || (disp<0 && next<distance) ||
            (disp>=0?next+distance:next-distance)!=expected) { reason="RIP storage target does not match manifest"; return false; }
        found=true;
    }
    if (!found) { reason="storage redirect requires a proven RIP operand"; return false; }
    std::int32_t displacement{};
    if (target>=next) {
        const auto distance=target-next;
        if (distance>INT32_MAX) { reason="storage target exceeds positive rel32 range"; return false; }
        displacement=static_cast<std::int32_t>(distance);
    } else {
        const auto distance=next-target;
        if (distance>0x80000000ull) { reason="storage target exceeds negative rel32 range"; return false; }
        displacement=distance==0x80000000ull?INT32_MIN:-static_cast<std::int32_t>(distance);
    }
    auto candidate=source; std::memcpy(candidate.data()+ins.raw.disp.offset,&displacement,4);
    out=std::move(candidate); reason.clear(); return true;
}
namespace {
struct CapacityBoundary { std::uint32_t rva,root,value; std::size_t length,immediate; std::array<std::uint8_t,6> expected; };
constexpr std::array<CapacityBoundary,3> kCapacityBoundaries{{
    {0x8B00,0x8B00,kTargetCapacity,5,1,{0xB9,0x80,0,0,0,0}},
    {0x373D2,0x37130,kTargetCapacity,6,2,{0x81,0xFA,0x80,0,0,0}},
    {0x37F6A,0x37E20,kTargetCapacity*kChannelStride,6,2,{0x41,0xB8,0,0xA0,0,0}}}};
bool EncodeCapacityBoundary(std::uint32_t rva,const std::vector<std::uint8_t>& source,
    std::vector<std::uint8_t>& out,std::string& reason) {
    const auto site=std::find_if(kCapacityBoundaries.begin(),kCapacityBoundaries.end(),[&](const CapacityBoundary& x){return x.rva==rva;});
    if (site==kCapacityBoundaries.end() || source.size()!=site->length ||
        std::memcmp(source.data(),site->expected.data(),site->length)) {
        reason="unknown capacity boundary or unexpected instruction bytes"; return false;
    }
    auto candidate=source; std::memcpy(candidate.data()+site->immediate,&site->value,4);
    out=std::move(candidate); reason.clear(); return true;
}
}
bool BuildCapacityBoundaryPlan(const BuildManifest& manifest,const PeImageView& image,std::uintptr_t base,
    std::vector<MemoryPatch>& out,std::string& reason) {
    if (!manifest.supported || manifest.sha256!=kExpectedSha || !base || base>UINTPTR_MAX-image.image_size) {
        reason="unsupported capacity boundary Build"; return false;
    }
    if (!VerifyKnownChannelLeaves(image,reason)) return false;
    std::vector<MemoryPatch> patches;
    for (const auto& site:kCapacityBoundaries) {
        if (std::none_of(manifest.references.begin(),manifest.references.end(),[&](const Reference& ref){
            return ref.instruction==site.rva && ref.root==site.root &&
                (ref.kind=="capacity_or_layout_candidate" || ref.kind=="fixed_channel_storage_byte_count_candidate");
        })) { reason="capacity boundary lacks exact semantic inventory site"; return false; }
        const auto* bytes=image.rva_ptr(site.rva,site.length);
        if (!bytes) { reason="capacity boundary outside image"; return false; }
        MemoryPatch patch; patch.address=base+site.rva; patch.expected.assign(bytes,bytes+site.length);
        if (!EncodeCapacityBoundary(site.rva,patch.expected,patch.replacement,reason)) return false;
        patches.push_back(std::move(patch));
    }
    out=std::move(patches); reason.clear(); return true;
}
bool RunCapacityBoundarySelfChecks(std::string& reason) {
    for (const auto& site:kCapacityBoundaries) {
        const std::vector<std::uint8_t> source(site.expected.begin(),site.expected.begin()+site.length); std::vector<std::uint8_t> out{0xA5};
        if (!EncodeCapacityBoundary(site.rva,source,out,reason)) return false;
        std::uint32_t value{}; std::memcpy(&value,out.data()+site.immediate,4);
        if (out.size()!=site.length || !std::equal(source.begin(),source.begin()+site.immediate,out.begin()) || value!=site.value) {
            reason="capacity/clear immediate or instruction shape differs"; return false;
        }
        const auto saved=out; auto changed=source; changed[site.immediate]^=1;
        if (EncodeCapacityBoundary(site.rva,changed,out,reason) || out!=saved ||
            EncodeCapacityBoundary(0x38D04,source,out,reason) || out!=saved) {
            reason="unrelated128 constant or unknown bytes changed capacity plan"; return false;
        }
    }
    reason.clear(); return true;
}
bool BuildStorageRedirectPlan(const BuildManifest& manifest,const PeImageView& image,std::uintptr_t base,
    std::uintptr_t channels,std::uintptr_t active,StorageRedirectPlan& out,std::string& reason) {
    constexpr auto channel_bytes=kTargetCapacity*kChannelStride;
    if (!manifest.supported || manifest.sha256!=kExpectedSha || !base || base>UINTPTR_MAX-image.image_size ||
        !channels || channels%alignof(ChannelSlot) || channels>UINTPTR_MAX-channel_bytes ||
        !active || active%alignof(ActiveList) || active>UINTPTR_MAX-sizeof(ActiveList)) {
        reason="unsupported Build or invalid expanded storage addresses"; return false;
    }
    const auto overlap=[](std::uintptr_t a,std::size_t n,std::uintptr_t b,std::size_t m) { return a<b+m && b<a+n; };
    if (overlap(channels,channel_bytes,active,sizeof(ActiveList)) || overlap(channels,channel_bytes,base,image.image_size) ||
        overlap(active,sizeof(ActiveList),base,image.image_size)) { reason="expanded storage overlaps engine or another allocation"; return false; }
    StorageRedirectPlan candidate; candidate.engine_base=base; candidate.channels=channels; candidate.active=active;
    ZydisDecoder decoder; ZydisDecoderInit(&decoder,ZYDIS_MACHINE_MODE_LONG_64,ZYDIS_STACK_WIDTH_64);
    for (const auto& ref:manifest.references) {
        const bool member=ref.kind=="image_base_offset_candidate_channel_array" && ref.root==0x2E310 &&
            ref.instruction>=0x2E43C && ref.instruction<=0x2E68A;
        const bool channel=ref.kind=="channel_array" || member, index=ref.kind=="active_table";
        if (!channel && !index) { candidate.pending.push_back(ref); continue; }
        if (member && !ProveProfilerEngineBase(image,base,reason)) return false;
        const auto start=channel?kChannelsRva:kActiveRva;
        const auto size=channel?kOldCapacity*kChannelStride:4+kOldCapacity*2;
        if (ref.target<start || ref.target>=start+size) { reason="redirect reference outside original storage"; return false; }
        const auto* bytes=image.rva_ptr(ref.instruction,ZYDIS_MAX_INSTRUCTION_LENGTH);
        ZydisDecodedInstruction ins{}; ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT]{};
        if (!bytes || !ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder,bytes,ZYDIS_MAX_INSTRUCTION_LENGTH,&ins,ops))) {
            reason="storage redirect instruction not decodable"; return false;
        }
        MemoryPatch patch; patch.address=base+ref.instruction; patch.expected.assign(bytes,bytes+ins.length);
        if (RedirectBytes(patch.expected)!=ref.original_bytes) { reason="storage manifest instruction bytes differ"; return false; }
        const auto replacement_target=(channel?channels:active)+(ref.target-start);
        if (member) {
            if (!EncodeEngineBaseStorage(patch.expected,ref.target,base,replacement_target,patch.replacement,reason)) return false;
        } else if (!EncodeRipStorageRedirect(patch.expected,patch.address,base+ref.target,
                replacement_target,patch.replacement,reason)) return false;
        const auto duplicate=std::find_if(candidate.patches.begin(),candidate.patches.end(),[&](const MemoryPatch& x){return x.address==patch.address;});
        if (duplicate!=candidate.patches.end()) {
            if (duplicate->expected!=patch.expected || duplicate->replacement!=patch.replacement) { reason="conflicting storage redirects"; return false; }
        } else candidate.patches.push_back(std::move(patch));
        // Encoding a candidate does not upgrade incomplete control-flow evidence.
        if (!member && ref.confidence!="decoded_unwind_interval") {
            const bool leaf=ref.confidence=="verified_channel_leaf" &&
                ((ref.instruction==0x8B05 && ref.root==0x8B00) || (ref.instruction==0x2F18B && ref.root==0x2F160));
            if (leaf) { if (!VerifyKnownChannelLeaves(image,reason)) return false; }
            else candidate.pending.push_back(ref);
        }
    }
    std::sort(candidate.patches.begin(),candidate.patches.end(),[](const MemoryPatch& a,const MemoryPatch& b){return a.address<b.address;});
    for (std::size_t i=1;i<candidate.patches.size();++i) if (candidate.patches[i-1].address+candidate.patches[i-1].expected.size()>candidate.patches[i].address) {
        reason="overlapping storage redirect instructions"; return false;
    }
    if (candidate.patches.empty()) { reason="no direct storage references planned"; return false; }
    if (!BuildLegacyConsumerLoadPlan(manifest,image,base,candidate.legacy_loads,reason)) return false;
    if (!BuildCapacityBoundaryPlan(manifest,image,base,candidate.capacity_patches,reason)) return false;
    candidate.pending.erase(std::remove_if(candidate.pending.begin(),candidate.pending.end(),[](const Reference& ref){
        return std::any_of(kCapacityBoundaries.begin(),kCapacityBoundaries.end(),[&](const CapacityBoundary& x){return ref.instruction==x.rva && ref.root==x.root;});
    }),candidate.pending.end());
    out=std::move(candidate); reason.clear(); return true;
}
std::string StorageRedirectPlanJson(const StorageRedirectPlan& plan) {
    std::ostringstream out;
    out << "{\n  \"installation_available\":false,\"synthetic_addresses\":true,\"engine_base\":\"" << RedirectHex(plan.engine_base)
        << "\",\"channels\":\"" << RedirectHex(plan.channels) << "\",\"active\":\"" << RedirectHex(plan.active)
        << "\",\"direct_count\":" << plan.patches.size() << ",\"pending_count\":" << plan.pending.size() << ",\n  \"patches\":[\n";
    for (std::size_t i=0;i<plan.patches.size();++i) {
        const auto& p=plan.patches[i]; if (i) out << ",\n";
        out << "    {\"rva\":\"" << RedirectHex(p.address-plan.engine_base) << "\",\"expected\":\"" << RedirectBytes(p.expected)
            << "\",\"replacement\":\"" << RedirectBytes(p.replacement) << "\"}";
    }
    out << "\n  ],\"legacy_constructor_hooked\":false,\"legacy_consumer_load_count\":" << plan.legacy_loads.size()
        << ",\"legacy_consumer_loads\":[\n";
    for (std::size_t i=0;i<plan.legacy_loads.size();++i) {
        const auto& p=plan.legacy_loads[i]; if (i) out << ",\n";
        out << "    {\"rva\":\"" << RedirectHex(p.address-plan.engine_base) << "\",\"expected\":\"" << RedirectBytes(p.expected)
            << "\",\"replacement\":\"" << RedirectBytes(p.replacement) << "\"}";
    }
    out << "\n  ],\"capacity_boundary_count\":" << plan.capacity_patches.size() << ",\"capacity_boundaries\":[\n";
    for (std::size_t i=0;i<plan.capacity_patches.size();++i) {
        const auto& p=plan.capacity_patches[i]; if (i) out << ",\n";
        out << "    {\"rva\":\"" << RedirectHex(p.address-plan.engine_base) << "\",\"expected\":\"" << RedirectBytes(p.expected)
            << "\",\"replacement\":\"" << RedirectBytes(p.replacement) << "\"}";
    }
    out << "\n  ],\"pending\":[\n";
    for (std::size_t i=0;i<plan.pending.size();++i) {
        const auto& p=plan.pending[i]; if (i) out << ",\n";
        out << "    {\"rva\":\"" << RedirectHex(p.instruction) << "\",\"root\":\"" << RedirectHex(p.root)
            << "\",\"kind\":\"" << p.kind << "\",\"confidence\":\"" << p.confidence << "\"}";
    }
    out << "\n  ]\n}\n"; return out.str();
}
bool RunStorageRedirectSelfChecks(std::string& reason) {
    const std::vector<std::uint8_t> source{0x48,0x8D,0x0D,0x20,0,0,0}; std::vector<std::uint8_t> output{0xA5};
    if (!EncodeRipStorageRedirect(source,0x1000,0x1027,0x2000,output,reason)) return false;
    std::int32_t disp{}; std::memcpy(&disp,output.data()+3,4);
    if (disp!=0xFF9 || output.size()!=source.size() || std::memcmp(output.data(),source.data(),3)) {
        reason="storage relocation changed instruction shape or target"; return false;
    }
    const std::vector<std::uint8_t> compare{0x83,0x3D,0x20,0,0,0,0x40};
    if (!EncodeRipStorageRedirect(compare,0x1000,0x1027,0x2000,output,reason) ||
        output[0]!=0x83 || output[1]!=0x3D || output[6]!=0x40) {
        reason="storage relocation overwrote a trailing compare immediate"; return false;
    }
    std::memcpy(&disp,output.data()+2,4);
    if (disp!=0xFF9) { reason="storage compare displacement differs"; return false; }
    const auto saved=output;
    if (EncodeRipStorageRedirect(source,0x1000,0x1028,0x2000,output,reason) || output!=saved ||
        EncodeRipStorageRedirect(source,0x1000,0x1027,UINTPTR_MAX,output,reason) || output!=saved ||
        EncodeRipStorageRedirect({0x48,0x8D},0x1000,0x1027,0x2000,output,reason) || output!=saved ||
        EncodeRipStorageRedirect({0x48,0x8D,0x48,0x20},0x1000,0x1027,0x2000,output,reason) || output!=saved) {
        reason="invalid/non-RIP/unknown target changed redirect output"; return false;
    }
    const std::vector<std::uint8_t> member{0xF3,0x42,0x0F,0x10,0x8C,0x11,0x14,0x6E,0x50,0};
    if (!EncodeEngineBaseStorage(member,kChannelsRva+0xE4,0x180000000ull,0x1820000E4ull,output,reason)) return false;
    std::memcpy(&disp,output.data()+6,4);
    if (disp!=0x20000E4 || std::memcmp(output.data(),member.data(),6)) { reason="engine-base member relocation differs"; return false; }
    const auto saved_member=output;
    auto wrong_register=member; wrong_register[5]=0x12;
    auto truncated_member=member; truncated_member.pop_back();
    if (EncodeEngineBaseStorage(member,kChannelsRva,0x180000000ull,0x1820000E4ull,output,reason) || output!=saved_member ||
        EncodeEngineBaseStorage(wrong_register,kChannelsRva+0xE4,0x180000000ull,0x1820000E4ull,output,reason) || output!=saved_member ||
        EncodeEngineBaseStorage(truncated_member,kChannelsRva+0xE4,0x180000000ull,0x1820000E4ull,output,reason) || output!=saved_member ||
        EncodeEngineBaseStorage(member,kChannelsRva+0xE4,0x180000000ull,0x200000000ull,output,reason) || output!=saved_member) {
        reason="invalid engine-base member changed output"; return false;
    }
    if (!EncodeEngineBaseStorage(member,kChannelsRva+0xE4,0x180000000ull,0x100000000ull,output,reason)) return false;
    std::memcpy(&disp,output.data()+6,4);
    if (disp!=INT32_MIN) { reason="negative disp32 endpoint rejected"; return false; }
    reason.clear(); return true;
}


namespace {
struct NearNativeBlock { ChannelAllocation channels; ActiveAllocation active; };
bool NearDistance(std::uintptr_t a,std::uintptr_t b) noexcept {
    return a>=b?a-b<=INT32_MAX:b-a<=0x80000000ull;
}
}
NearChannelStorage::~NearChannelStorage() noexcept { if (region_ && !retained_) VirtualFree(region_,0,MEM_RELEASE); }
ChannelSlot* NearChannelStorage::channels() const noexcept {
    return block_?static_cast<NearNativeBlock*>(block_)->channels.slots.data():nullptr;
}
ActiveList* NearChannelStorage::active() const noexcept { return block_?&static_cast<NearNativeBlock*>(block_)->active.list:nullptr; }
bool NearChannelStorage::GuardsIntact() const noexcept {
    if (!block_) return false;
    const auto* p=static_cast<const NearNativeBlock*>(block_);
    return p->channels.before==kGuard && p->channels.after==kGuard && p->active.before==kGuard && p->active.after==kGuard;
}
bool NearChannelStorage::Prepare(std::uintptr_t base,std::size_t image_size,std::string& reason) {
    if (region_) { reason="near expanded storage already allocated"; return false; }
    SYSTEM_INFO system{}; GetSystemInfo(&system);
    const auto gran=static_cast<std::uintptr_t>(system.dwAllocationGranularity);
    const auto page=static_cast<std::size_t>(system.dwPageSize);
    const auto region_bytes=(sizeof(NearNativeBlock)+page-1)/page*page+2*page;
    const auto minimum=reinterpret_cast<std::uintptr_t>(system.lpMinimumApplicationAddress);
    const auto maximum=reinterpret_cast<std::uintptr_t>(system.lpMaximumApplicationAddress);
    if (!gran || !page || !base || base<minimum || !image_size || image_size>INT32_MAX-region_bytes-gran ||
        base>maximum || base>UINTPTR_MAX-image_size || base+image_size>maximum) {
        reason="invalid near expanded storage image bounds"; return false;
    }
    const auto center=base&~(gran-1); DWORD last_error{};
    const auto max_distance=static_cast<std::uintptr_t>(INT32_MAX)-image_size-region_bytes-gran;
    for (std::uintptr_t distance=gran;distance<=max_distance;distance+=gran) {
        for (const bool above:{false,true}) {
            if ((!above && center<distance) || (above && center>UINTPTR_MAX-distance)) continue;
            const auto candidate=above?center+distance:center-distance;
            if (candidate<minimum || candidate>maximum-region_bytes ||
                (candidate<base+image_size && base<candidate+region_bytes) ||
                !NearDistance(candidate,base) || !NearDistance(candidate+region_bytes,base) ||
                !NearDistance(candidate,base+image_size) || !NearDistance(candidate+region_bytes,base+image_size)) continue;
            MEMORY_BASIC_INFORMATION memory{};
            if (!VirtualQuery(reinterpret_cast<void*>(candidate),&memory,sizeof(memory)) || memory.State!=MEM_FREE ||
                memory.RegionSize<region_bytes) continue;
            void* region=VirtualAlloc(reinterpret_cast<void*>(candidate),region_bytes,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);
            if (!region) { last_error=GetLastError(); continue; }
            DWORD previous{};
            if (!VirtualProtect(region,page,PAGE_NOACCESS,&previous) ||
                !VirtualProtect(static_cast<std::uint8_t*>(region)+region_bytes-page,page,PAGE_NOACCESS,&previous)) {
                last_error=GetLastError(); VirtualFree(region,0,MEM_RELEASE); continue;
            }
            auto* block=new (static_cast<std::uint8_t*>(region)+page) NearNativeBlock{};
            block->channels.before=block->channels.after=block->active.before=block->active.after=kGuard;
            region_=region; block_=block; region_size_=region_bytes;
            reason.clear(); return true;
        }
    }
    reason="no rel32-reachable expanded storage region; Win32="+std::to_string(last_error); return false;
}
bool RunNearStorageSelfChecks(std::string& reason) {
    const auto base=reinterpret_cast<std::uintptr_t>(GetModuleHandleW(nullptr));
    const auto* dos=reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    const auto* nt=reinterpret_cast<const IMAGE_NT_HEADERS64*>(base+dos->e_lfanew);
    const auto size=nt->OptionalHeader.SizeOfImage;
    std::uintptr_t address{};
    {
        NearChannelStorage storage;
        if (!storage.Prepare(base,size,reason)) return false;
        if (!storage.channels() || !storage.active() || !storage.GuardsIntact() || storage.active()->count) {
            reason="near storage views or initialization invalid"; return false;
        }
        address=reinterpret_cast<std::uintptr_t>(storage.channels());
        for (std::uint32_t i=0;i<512;++i) for (const auto byte:storage.channels()[i].bytes) if (byte) {
            reason="near storage retained nonzero channel bytes"; return false;
        }
        storage.active()->count=512; storage.active()->indices[511]=511;
        const auto marker=std::uint32_t{0x12345678}; std::memcpy(storage.channels()[511].bytes.data(),&marker,4);
        if (!storage.GuardsIntact()) { reason="last near channel/index damaged guards"; return false; }
        const std::vector<std::uint8_t> source{0x48,0x8D,0x0D,0x20,0,0,0}; std::vector<std::uint8_t> output;
        if (!EncodeRipStorageRedirect(source,base+0x1000,base+0x1027,address+511*kChannelStride,output,reason) ||
            !EncodeRipStorageRedirect(source,base+0x1000,base+0x1027,reinterpret_cast<std::uintptr_t>(storage.active())+4+511*2,output,reason)) return false;
        MEMORY_BASIC_INFORMATION memory{};
        if (!VirtualQuery(storage.channels(),&memory,sizeof(memory)) || memory.Protect!=PAGE_READWRITE) {
            reason="near channel storage not writable data"; return false;
        }
        const auto saved=storage.channels();
        if (storage.Prepare(base,size,reason) || storage.channels()!=saved) { reason="near storage allocated twice"; return false; }
    }
    MEMORY_BASIC_INFORMATION released{};
    if (!VirtualQuery(reinterpret_cast<void*>(address),&released,sizeof(released)) || released.State!=MEM_FREE) {
        reason="unattached near storage not released"; return false;
    }
    NearChannelStorage invalid;
    if (invalid.Prepare(0,size,reason) || invalid.Prepare(base,0,reason)) { reason="invalid near storage bounds accepted"; return false; }
    reason.clear(); return true;
}

}

namespace channel_expand {
bool CompareOriginalChannelLeaves(const std::filesystem::path& path,std::string& reason) {
    const auto inspected=InspectEngine(path);
    if (!inspected.parsed || !inspected.manifest.supported || !VerifyKnownChannelLeaves(inspected.image,reason)) {
        if (reason.empty()) reason="unsupported channel leaf Build";
        return false;
    }
    // These are extracted engine leaf instructions executing on real native
    // guarded bytes. No Source API, mixer or GLua behavior is emulated.
    constexpr std::size_t page=4096,data_bytes=sizeof(ChannelAllocation)+sizeof(ActiveAllocation)+16;
    constexpr std::size_t data_pages=(data_bytes+page-1)/page,total=(data_pages+3)*page;
    auto* region=static_cast<std::uint8_t*>(VirtualAlloc(nullptr,total,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE));
    if (!region) { reason="channel leaf fixture allocation failed"; return false; }
    struct Release { void* ptr; ~Release(){VirtualFree(ptr,0,MEM_RELEASE);} } release{region};
    auto* channels=reinterpret_cast<ChannelAllocation*>(region+2*page);
    auto* active=reinterpret_cast<ActiveAllocation*>(region+2*page+sizeof(ChannelAllocation));
    channels->before=channels->after=active->before=active->after=kGuard;
    const auto guards=[&](){return channels->before==kGuard && channels->after==kGuard && active->before==kGuard && active->after==kGuard;};
    std::memcpy(region,inspected.image.rva_ptr(0x8B00,0x355),0x355);
    std::memcpy(region+0x400,inspected.image.rva_ptr(0x2F160,0x53),0x53);
    const auto relocate=[&](std::size_t instruction,std::uintptr_t target) {
        const auto displacement=static_cast<std::int64_t>(target)-static_cast<std::int64_t>(reinterpret_cast<std::uintptr_t>(region)+instruction+7);
        if (displacement<INT32_MIN || displacement>INT32_MAX) return false;
        const auto d=static_cast<std::int32_t>(displacement); std::memcpy(region+instruction+3,&d,4); return true;
    };
    if (!relocate(5,reinterpret_cast<std::uintptr_t>(channels->slots.data())+0xEC) ||
        !relocate(0x400+0x2F18B-0x2F160,reinterpret_cast<std::uintptr_t>(channels->slots.data())+0x128)) {
        reason="channel leaf fixture relocation overflow"; return false;
    }
    DWORD old{};
    if (!VirtualProtect(region+page,page,PAGE_NOACCESS,&old) ||
        !VirtualProtect(region+(data_pages+2)*page,page,PAGE_NOACCESS,&old)) { reason="channel leaf guard page protection failed"; return false; }
    const auto seal=[&](){return VirtualProtect(region,page,PAGE_EXECUTE_READ,&old) && FlushInstructionCache(GetCurrentProcess(),region,page);};
    const auto initialize=reinterpret_cast<void(*)()>(region);
    for (const std::uint32_t capacity:{128u,512u}) {
        for (auto& slot:channels->slots) slot.bytes.fill(0xA5);
        if (!VirtualProtect(region,page,PAGE_READWRITE,&old)) { reason="channel leaf fixture unseal failed"; return false; }
        std::memcpy(region+1,&capacity,4);
        if (!seal()) { reason="channel leaf fixture executable protection failed"; return false; }
        initialize();
        for (std::uint32_t i=0;i<512;++i) for (std::size_t j=0;j<kChannelStride;++j) {
            const auto expected=static_cast<std::uint8_t>(i<capacity && j>=0xE8 && j<0x100?0:0xA5);
            if (channels->slots[i].bytes[j]!=expected) { reason="native coordinate initialization range or unrelated byte differs"; return false; }
        }
        if (!guards()) { reason="native initializer damaged allocation guards"; return false; }
    }
    active->list={};
    for (std::uint32_t i=0;i<512;++i) {
        channels->slots[i].bytes.fill(0xA5);
        active->list.indices[i]=static_cast<std::int16_t>(i);
        const auto reverse=static_cast<std::int16_t>(i+1); std::memcpy(channels->slots[i].bytes.data()+0x128,&reverse,2);
    }
    active->list.count=512;
    const auto remove=reinterpret_cast<void(*)(ActiveList*,ChannelSlot*)>(region+0x400);
    for (const std::uint32_t index:{0u,511u,255u,509u}) {
        auto expected_channels=channels->slots; auto expected_list=active->list;
        std::int16_t reverse{}; std::memcpy(&reverse,expected_channels[index].bytes.data()+0x128,2);
        const auto last=expected_list.indices[--expected_list.count];
        if (reverse-1<expected_list.count) {
            expected_list.indices[reverse-1]=last;
            std::memcpy(expected_channels[last].bytes.data()+0x128,&reverse,2);
        }
        const std::int16_t zero=0; std::memcpy(expected_channels[index].bytes.data()+0x128,&zero,2);
        remove(&active->list,&channels->slots[index]);
        if (std::memcmp(channels->slots.data(),expected_channels.data(),sizeof(expected_channels)) ||
            std::memcmp(&active->list,&expected_list,sizeof(expected_list)) || !guards()) {
            reason="native removal count, swapped index, 1-based reverse or unrelated bytes differ"; return false;
        }
        remove(&active->list,&channels->slots[index]);
        if (std::memcmp(&active->list,&expected_list,sizeof(expected_list)) ||
            std::memcmp(channels->slots.data(),expected_channels.data(),sizeof(expected_channels)) || !guards()) {
            reason="inactive native removal changed storage"; return false;
        }
    }
    auto changed=inspected.image;
    auto* corrupt=const_cast<std::uint8_t*>(changed.rva_ptr(0x8B00,1)); *corrupt^=1;
    if (VerifyKnownChannelLeaves(changed,reason)) { reason="modified initializer body accepted"; return false; }
    changed=inspected.image; corrupt=const_cast<std::uint8_t*>(changed.rva_ptr(0x2F160,1)); *corrupt^=1;
    if (VerifyKnownChannelLeaves(changed,reason)) { reason="modified removal body accepted"; return false; }
    reason.clear(); return true;
}
}

namespace channel_expand {
bool BuildStorageContextPatches(const NativeStorageView& original,const NativeStorageView& desired,NativeGuidContext& context,
    std::vector<MemoryPatch>& out,std::string& reason) {
    if (!ValidateNativeStorageView(original,reason) || !ValidateNativeStorageView(desired,reason) || original.capacity!=128 || desired.capacity!=128 ||
        original.channels==desired.channels || original.active_count==desired.active_count || context.channels!=original.channels ||
        context.active_count!=original.active_count || context.active_indices!=original.active_indices || context.capacity!=128) {
        reason="context transition requires distinct validated128 storage and exact old consumer descriptor"; return false;
    }
    std::vector<MemoryPatch> patches;
    const auto append=[&](auto& field,auto value) {
        static_assert(sizeof(field)==8 && sizeof(value)==8);
        MemoryPatch patch; patch.address=reinterpret_cast<std::uintptr_t>(&field); patch.expected.resize(8); patch.replacement.resize(8);
        std::memcpy(patch.expected.data(),&field,8); std::memcpy(patch.replacement.data(),&value,8); patches.push_back(std::move(patch));
    };
    append(context.active_count,desired.active_count); append(context.active_indices,desired.active_indices);
    append(context.channels,static_cast<const ChannelSlot*>(desired.channels));
    out=std::move(patches); reason.clear(); return true;
}
}
