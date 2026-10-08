#include "native_protocol.hpp"
#include "manifest.hpp"
#include <windows.h>
#include <algorithm>
#include <cstring>
#include <mutex>

namespace channel_expand {
namespace {
std::mutex g_mutex;
std::unique_ptr<InventoryResult> g_inventory;
std::filesystem::path g_disk_path;

bool Read(std::uintptr_t address, void* output, std::size_t size) noexcept {
    SIZE_T read{};
    return ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<const void*>(address), output, size, &read) && read == size;
}
template<class T> bool ReadValue(std::uintptr_t address, T& value) noexcept { return Read(address, &value, sizeof(value)); }

// Compare executable bytes, compensating only for the PE loader's DIR64 fixups.
// This observes code. It does not prove thread quiescence or hidden pointer ownership.
bool CodeMatches(const PeImageView& image, std::uintptr_t base, std::uint32_t& first) {
    for (const auto& sec : image.sections) {
        if (!(sec.flags & IMAGE_SCN_MEM_EXECUTE)) continue;
        const auto size = std::min(sec.virtual_size, sec.raw_size);
        const auto* file_bytes = image.rva_ptr(sec.rva, size);
        if (!file_bytes) return false;
        std::vector<std::uint8_t> expected(file_bytes, file_bytes+size), actual(size);
        if (!Read(base+sec.rva, actual.data(), size)) return false;
        std::uint32_t cursor{};
        while (cursor < image.reloc_size) {
            const auto* p = image.rva_ptr(image.reloc_rva+cursor, sizeof(IMAGE_BASE_RELOCATION));
            if (!p) return false;
            IMAGE_BASE_RELOCATION block{}; std::memcpy(&block, p, sizeof(block));
            if (block.SizeOfBlock < sizeof(block) || block.SizeOfBlock > image.reloc_size-cursor ||
                (block.SizeOfBlock-sizeof(block))%2 || !image.rva_ptr(image.reloc_rva+cursor, block.SizeOfBlock)) return false;
            for (std::uint32_t j=sizeof(block); j<block.SizeOfBlock; j+=2) {
                WORD e{}; std::memcpy(&e,image.rva_ptr(image.reloc_rva+cursor+j,2),2);
                const auto location = static_cast<std::uint64_t>(block.VirtualAddress)+(e&0xFFF);
                const auto type = e>>12;
                if (type == IMAGE_REL_BASED_ABSOLUTE || location < sec.rva || location >= static_cast<std::uint64_t>(sec.rva)+size) continue;
                if (type != IMAGE_REL_BASED_DIR64 || static_cast<std::uint64_t>(sec.rva)+size-location < 8) return false;
                const auto offset = static_cast<std::size_t>(location-sec.rva);
                std::uint64_t v{}; std::memcpy(&v, expected.data()+offset, 8);
                v += static_cast<std::uint64_t>(base)-image.preferred_base;
                std::memcpy(expected.data()+offset,&v,8);
            }
            cursor += block.SizeOfBlock;
        }
        if (!NormalizeEngineHookBytes(base+sec.rva,actual)) { first=sec.rva; return false; }
        const auto mismatch = std::mismatch(expected.begin(), expected.end(), actual.begin());
        if (mismatch.first != expected.end()) { first = sec.rva+static_cast<std::uint32_t>(mismatch.first-expected.begin()); return false; }
    }
    return true;
}
bool SampleCounts(std::uintptr_t base, RuntimeStatus& status) {
    const auto view=CurrentNativeStorageView(base); std::string reason;
    if (!ValidateNativeStorageView(view,reason)) return false;
    const auto active_address=reinterpret_cast<std::uintptr_t>(view.active_count);
    std::array<std::uint8_t,4+kTargetCapacity*2> table{};
    std::array<ChannelSlot,kTargetCapacity> channels{};
    for (int attempt=0; attempt<3; ++attempt) {
        std::int32_t before{}, after{}, total{};
        if (!ReadValue(active_address, before) || !Read(active_address,table.data(),4+view.capacity*2) ||
            !Read(reinterpret_cast<std::uintptr_t>(view.channels),channels.data(),view.capacity*kChannelStride) || !ReadValue(base+kTotalRva,total) ||
            !ReadValue(active_address,after)) return false;
        std::int32_t copied{}; std::memcpy(&copied,table.data(),4);
        if (before != after || before != copied || before < 0 || before > static_cast<std::int32_t>(view.capacity) ||
            total < static_cast<std::int32_t>(kDynamicCapacity) || total > static_cast<std::int32_t>(view.capacity)) continue;
        std::array<bool,kTargetCapacity> seen{};
        std::int32_t dynamic{}, statics{}, mixers{}; bool valid=true;
        for (std::int32_t p=0; p<copied; ++p) {
            std::int16_t i{}; std::memcpy(&i,table.data()+4+p*2,2);
            if (i<0 || i>=total || seen[i]) { valid=false; break; }
            seen[i]=true;
            std::int16_t reverse{}; std::uint64_t mixer{};
            std::memcpy(&reverse,channels[i].bytes.data()+0x128,2);
            std::memcpy(&mixer,channels[i].bytes.data()+0x10,8);
            if (reverse != p+1) { valid=false; break; }
            if (i < static_cast<std::int32_t>(kDynamicCapacity)) ++dynamic; else ++statics;
            if (mixer) ++mixers;
        }
        if (!valid) continue;
        status.total_channels=total; status.active_count=copied;
        status.active_dynamic=dynamic; status.active_static=statics; status.mixers=mixers;
        return true;
    }
    return false;
}
RuntimeStatus QueryLocked() {
    RuntimeStatus s;
    const auto module = GetModuleHandleW(L"engine.dll");
    if (!module) { s.reason="engine.dll is not loaded"; return s; }
    std::array<wchar_t,32768> path{};
    const auto length = GetModuleFileNameW(module,path.data(),static_cast<DWORD>(path.size()));
    if (!length || length>=path.size()) { s.reason="cannot read loaded engine path"; return s; }
    const std::filesystem::path current(path.data());
    if (!g_inventory || current != g_disk_path) {
        g_inventory = std::make_unique<InventoryResult>(InspectEngine(current)); g_disk_path=current;
    }
    const auto& r=*g_inventory;
    const auto utf8=current.u8string(); s.engine_path=utf8; s.disk_sha256=r.manifest.sha256;
    s.supported_disk_build=r.parsed && r.manifest.supported;
    if (!s.supported_disk_build) { s.state="unsupported"; s.reason="unrecognized engine file; no engine memory was written"; return s; }
    const auto base = reinterpret_cast<std::uintptr_t>(module);
    s.loaded_code_matches=CodeMatches(r.image,base,s.first_code_mismatch);
    if (!s.loaded_code_matches) { s.state="unsupported"; s.reason="loaded executable code differs from this Build or cannot be read; diagnostic sampling refused"; return s; }
    s.current_capacity=CurrentNativeStorageView(base).capacity;
    s.sampled_counts_valid=SampleCounts(base,s);
    s.state=s.current_capacity==512?"experimental":"incomplete";
    s.installed=s.current_capacity==512;
    s.reason=s.installed?"experimental512 active; native loader RC, voice/music/endurance verification pending":
        "512-slot installation disabled: logical capacity transition, expanded routing and lifecycle validation are incomplete";
    return s;
}
}
RuntimeStatus QueryStatus() {
    std::lock_guard<std::mutex> lock(g_mutex);
    try { return QueryLocked(); }
    catch (const std::exception& e) { RuntimeStatus s; s.reason=e.what(); return s; }
}
static FrameBridgeStatus StartFrameBridgeLocked() {
    try {
        if (QueryFrameBridge().active) return QueryFrameBridge();
        const auto status=QueryLocked();
        if (!status.supported_disk_build || !status.loaded_code_matches) {
            FrameBridgeStatus result; result.reason=status.reason; return result;
        }
        std::string reason;
        const auto base=reinterpret_cast<std::uintptr_t>(GetModuleHandleW(L"engine.dll"));
        if (!StartNativeFrameBridge(g_inventory->manifest,g_inventory->image,base,reason)) {
            auto result=QueryFrameBridge(); result.reason=reason; return result;
        }
        return QueryFrameBridge();
    } catch (const std::exception& e) { FrameBridgeStatus result; result.reason=e.what(); return result; }
}
static SnapshotBridgeStatus StartSnapshotBridgeLocked(std::uintptr_t return_slot,bool acknowledge_fail_stop) {
    try {
        if (!acknowledge_fail_stop) { SnapshotBridgeStatus result; result.reason="explicit fail-stop acknowledgment required"; return result; }
        if (QuerySnapshotBridge().active) return QuerySnapshotBridge();
        const auto status=QueryLocked();
        if (!status.supported_disk_build || !status.loaded_code_matches) { SnapshotBridgeStatus result; result.reason=status.reason; return result; }
        std::string reason; const auto base=reinterpret_cast<std::uintptr_t>(GetModuleHandleW(L"engine.dll"));
        if (!StartNativeSnapshotBridge(g_inventory->manifest,g_inventory->image,base,return_slot,true,reason)) {
            auto result=QuerySnapshotBridge(); result.reason=reason; return result;
        }
        return QuerySnapshotBridge();
    } catch (const std::exception& e) { SnapshotBridgeStatus result; result.reason=e.what(); return result; }
}
static SnapshotBridgeStatus StartStorageBridgeLocked(std::uintptr_t return_slot,bool acknowledged) {
    try {
        if (!acknowledged) { SnapshotBridgeStatus r; r.reason="explicit storage fail-stop acknowledgment required"; return r; }
        if (QueryStorageBridge().active) return QueryStorageBridge();
        const auto status=QueryLocked();
        if (!status.supported_disk_build || !status.loaded_code_matches || !status.sampled_counts_valid) {
            SnapshotBridgeStatus r; r.reason=status.reason; return r;
        }
        std::string reason; const auto base=reinterpret_cast<std::uintptr_t>(GetModuleHandleW(L"engine.dll"));
        if (!StartNativeStorageBridge(g_inventory->manifest,g_inventory->image,base,return_slot,true,reason)) {
            auto r=QueryStorageBridge(); r.reason=reason; return r;
        }
        return QueryStorageBridge();
    } catch (const std::exception& e) { SnapshotBridgeStatus r; r.reason=e.what(); return r; }
}
static SnapshotBridgeStatus StartCapacityBridgeLocked(std::uintptr_t slot,bool acknowledged) {
    try {
        if (!acknowledged) { SnapshotBridgeStatus r; r.reason="explicit experimental512 fail-stop acknowledgment required"; return r; }
        if (QueryCapacityBridge().active) return QueryCapacityBridge();
        const auto status=QueryLocked();
        if (!status.supported_disk_build || !status.loaded_code_matches || !status.sampled_counts_valid) { SnapshotBridgeStatus r; r.reason=status.reason; return r; }
        std::string reason; const auto base=reinterpret_cast<std::uintptr_t>(GetModuleHandleW(L"engine.dll"));
        if (!StartNativeCapacityBridge(g_inventory->manifest,g_inventory->image,base,slot,true,reason)) { auto r=QueryCapacityBridge(); r.reason=reason; return r; }
        return QueryCapacityBridge();
    } catch (const std::exception& e) { SnapshotBridgeStatus r; r.reason=e.what(); return r; }
}
FrameBridgeStatus StartFrameBridge() { std::lock_guard<std::mutex> lock(g_mutex); return StartFrameBridgeLocked(); }
SnapshotBridgeStatus StartSnapshotBridge(std::uintptr_t slot,bool ack) { std::lock_guard<std::mutex> lock(g_mutex); return StartSnapshotBridgeLocked(slot,ack); }
SnapshotBridgeStatus StartStorageBridge(std::uintptr_t slot,bool ack) { std::lock_guard<std::mutex> lock(g_mutex); return StartStorageBridgeLocked(slot,ack); }
SnapshotBridgeStatus StartCapacityBridge(std::uintptr_t slot,bool ack) { std::lock_guard<std::mutex> lock(g_mutex); return StartCapacityBridgeLocked(slot,ack); }
InstallResult InstallExpansion() {
    // Deliberately no code-writing or permissive override path in the diagnostic build.
    const auto status = QueryStatus();
    return {false, status.reason};
}
NativeProbeResult ProbeNativeSnapshot() {
    std::lock_guard<std::mutex> lock(g_mutex);
    NativeProbeResult result;
    try {
        const auto status=QueryLocked();
        if (!status.loaded_code_matches || !status.supported_disk_build) { result.reason=status.reason; return result; }
        const auto base=reinterpret_cast<std::uintptr_t>(GetModuleHandleW(L"engine.dll"));
        const auto view=CurrentNativeStorageView(base);
        if (!ValidateNativeStorageView(view,result.reason)) return result;
        result.engine_capacity=view.capacity;
        NativeAudioBindings bindings;
        if (!BindNativeAudio(g_inventory->manifest,g_inventory->image,base,bindings,result.reason)) return result;
        // Original call sites pass this exact address to Enter/LeaveCriticalSection.
        // Holding it is a probe scope; it is NOT an installation quiescence proof.
        struct SoundScope {
            CRITICAL_SECTION* cs;
            explicit SoundScope(std::uintptr_t address):cs(reinterpret_cast<CRITICAL_SECTION*>(address)) { EnterCriticalSection(cs); }
            ~SoundScope() { LeaveCriticalSection(cs); }
            SoundScope(const SoundScope&)=delete;
            SoundScope& operator=(const SoundScope&)=delete;
        } sound(base+0x510D50);
        result.sound_lock_held=true;
        ActiveList active{};
        if (!Read(reinterpret_cast<std::uintptr_t>(view.active_count),&active,4+view.capacity*2)) { result.reason="cannot read original active table under sound lock"; return result; }
        result.source_count=active.count;
        const auto* channels=reinterpret_cast<const ChannelSlot*>(reinterpret_cast<std::uintptr_t>(view.channels));
        NativeGuidContext context{bindings,reinterpret_cast<const std::int32_t*>(reinterpret_cast<std::uintptr_t>(view.active_count)),
            reinterpret_cast<const std::int16_t*>(reinterpret_cast<std::uintptr_t>(view.active_indices)),channels,view.capacity,base+0x510D50};
        NativeGuidThunk thunk;
        if (!thunk.Prepare(context,result.reason)) return result;
        result.guid_thunk_prepared=true;
        struct Guarded {
            std::uint64_t before{0xAB571902CE3468DFull};
            NativeSnapshotOwner owner;
            std::uint64_t after{0xDC1902837465ABFEull};
            explicit Guarded(NativeAudioBindings b):owner(b) {}
        } guarded(bindings);
        if (!guarded.owner.Build(active.indices.data(),active.count,view.capacity,result.reason)) return result;
        const auto& snapshot=guarded.owner.snapshot;
        result.copied_count=snapshot.count; result.route_count=snapshot.auxiliary_routes.size;
        result.snapshot_bytes=sizeof(snapshot); result.route_mask=snapshot.route_mask;
        result.guid_comparison_matches=true;
        // Compare a real first/last active GUID (or empty lookup) with engine 0x33530.
        for (const auto position:{0,active.count-1}) {
            std::uint32_t guid{};
            if (active.count && !ReadValue(reinterpret_cast<std::uintptr_t>(view.channels)+active.indices[position]*kChannelStride,guid)) {
                result.reason="cannot read active GUID"; return result;
            }
            const auto* adapted=LookupGuidInNativeSnapshot(channels,view.capacity,snapshot,guid);
            const auto* through_thunk=thunk.entry()(guid);
            const auto* original=bindings.original_guid_lookup(guid);
            ++result.guid_queries;
            if (adapted!=original || through_thunk!=original) result.guid_comparison_matches=false;
            if (active.count<=1) break;
        }
        result.guards_intact=guarded.before==0xAB571902CE3468DFull && guarded.after==0xDC1902837465ABFEull;
        guarded.owner.Release();
        const Vector32Metadata empty{};
        result.routing_released=std::memcmp(&guarded.owner.snapshot.auxiliary_routes,&empty,sizeof(empty))==0;
        result.ok=result.guards_intact && result.routing_released && result.guid_comparison_matches;
        result.reason=result.ok?"native snapshot bridge executed using current channel storage":
            "native snapshot guard, GUID comparison or route cleanup failed";
        return result;
    } catch (const std::exception& e) { result.reason=e.what(); return result; }
}
NativeStopProbeResult ProbeNativeStop(std::int32_t source,std::int32_t entity_channel) {
    std::lock_guard<std::mutex> lock(g_mutex);
    NativeStopProbeResult result;
    try {
        const auto status=QueryLocked();
        if (!status.loaded_code_matches || !status.supported_disk_build) { result.reason=status.reason; return result; }
        const auto base=reinterpret_cast<std::uintptr_t>(GetModuleHandleW(L"engine.dll"));
        const auto view=CurrentNativeStorageView(base);
        if (!ValidateNativeStorageView(view,result.reason)) return result;
        result.engine_capacity=view.capacity;
        NativeAudioBindings bindings; NativeChannelFree free_channel{};
        if (!BindNativeAudio(g_inventory->manifest,g_inventory->image,base,bindings,result.reason) ||
            !BindNativeChannelFree(g_inventory->manifest,g_inventory->image,base,free_channel,result.reason)) return result;
        result.full_free_binding_verified=true;
        struct SoundScope {
            CRITICAL_SECTION* cs;
            explicit SoundScope(std::uintptr_t address):cs(reinterpret_cast<CRITICAL_SECTION*>(address)) { EnterCriticalSection(cs); }
            ~SoundScope() { LeaveCriticalSection(cs); }
        } sound(base+0x510D50);
        result.sound_lock_held=true;
        NativeStopContext context{{bindings,reinterpret_cast<const std::int32_t*>(reinterpret_cast<std::uintptr_t>(view.active_count)),
            reinterpret_cast<const std::int16_t*>(reinterpret_cast<std::uintptr_t>(view.active_indices)),reinterpret_cast<const ChannelSlot*>(reinterpret_cast<std::uintptr_t>(view.channels)),
            view.capacity,base+0x510D50},free_channel};
        NativeStopThunk thunk;
        if (!thunk.Prepare(context,result.reason)) return result;
        result.stop_thunk_prepared=true;
        struct Guarded {
            std::uint64_t before{0xAB571902CE3468DFull}; NativeSnapshotOwner owner;
            std::uint64_t after{0xDC1902837465ABFEull};
            explicit Guarded(NativeAudioBindings b):owner(b) {}
            bool intact() const noexcept { return before==0xAB571902CE3468DFull && after==0xDC1902837465ABFEull; }
        } before(bindings),after(bindings);
        auto& channels=context.channels; ActiveList selected;
        if (!before.owner.Build(channels.active_indices,*channels.active_count,view.capacity,result.reason) ||
            !SelectStopChannels(channels.channels,view.capacity,before.owner.snapshot,source,entity_channel,selected,result.reason)) return result;
        result.active_before=before.owner.snapshot.count; result.matched_before=selected.count;
        if (result.active_before) {
            const auto& first=channels.channels[before.owner.snapshot.indices[0]];
            std::memcpy(&result.first_source,first.bytes.data()+0xAC,4);
            std::memcpy(&result.first_entity_channel,first.bytes.data()+0xB0,4); result.has_first_channel=true;
        }
        // This explicit probe stops matching sounds via the real engine cleanup.
        // Original globals and capacity remain 128; no instruction is patched.
        thunk.entry()(source,entity_channel);
        if (!after.owner.Build(channels.active_indices,*channels.active_count,view.capacity,result.reason) ||
            !SelectStopChannels(channels.channels,view.capacity,after.owner.snapshot,source,entity_channel,selected,result.reason)) return result;
        result.active_after=after.owner.snapshot.count; result.matched_after=selected.count;
        result.guards_intact=before.intact() && after.intact();
        before.owner.Release(); after.owner.Release(); const Vector32Metadata empty{};
        result.routing_released=std::memcmp(&before.owner.snapshot.auxiliary_routes,&empty,sizeof(empty))==0 &&
            std::memcmp(&after.owner.snapshot.auxiliary_routes,&empty,sizeof(empty))==0;
        result.ok=result.matched_before>0 && !result.matched_after && result.guards_intact && result.routing_released;
        result.reason=result.ok?"native matching stop and full engine cleanup executed using current storage":
            (result.matched_before==0?"no matching channels; nonempty stop not verified":
                "matching channels remain or native snapshot guard/cleanup failed");
        return result;
    } catch (const std::exception& e) { result.reason=e.what(); return result; }
}
NativeMixProbeResult ProbeNativeMix() {
    std::lock_guard<std::mutex> lock(g_mutex); NativeMixProbeResult result;
    try {
        const auto status=QueryLocked();
        if (!status.loaded_code_matches || !status.supported_disk_build) { result.reason=status.reason; return result; }
        const auto base=reinterpret_cast<std::uintptr_t>(GetModuleHandleW(L"engine.dll"));
        const auto view=CurrentNativeStorageView(base);
        if (!ValidateNativeStorageView(view,result.reason)) return result;
        result.engine_capacity=view.capacity;
        if (view.capacity!=kOldCapacity) { result.reason="original128 mix comparison unavailable after storage expansion"; return result; }
        NativeAudioBindings audio; NativeMixBindings mix;
        if (!BindNativeAudio(g_inventory->manifest,g_inventory->image,base,audio,result.reason) ||
            !BindNativeMix(g_inventory->manifest,g_inventory->image,base,mix,result.reason)) return result;
        result.native_binding_verified=true;
        struct SoundScope {
            CRITICAL_SECTION* cs;
            explicit SoundScope(std::uintptr_t address):cs(reinterpret_cast<CRITICAL_SECTION*>(address)) { EnterCriticalSection(cs); }
            ~SoundScope() { LeaveCriticalSection(cs); }
        } sound(base+0x510D50); result.sound_lock_held=true;
        struct SnapshotGuard {
            std::uint64_t before{0xAB571902CE3468DFull}; NativeSnapshotOwner owner;
            std::uint64_t after{0xDC1902837465ABFEull};
            explicit SnapshotGuard(NativeAudioBindings b):owner(b) {}
            bool intact() const { return before==0xAB571902CE3468DFull && after==0xDC1902837465ABFEull; }
        } snapshot(audio);
        std::int32_t count{};
        if (!ReadValue(reinterpret_cast<std::uintptr_t>(view.active_count),count) || !snapshot.owner.Build(reinterpret_cast<const std::int16_t*>(reinterpret_cast<std::uintptr_t>(view.active_indices)),
            count,view.capacity,result.reason)) return result;
        result.source_count=count;
        // The original helper reads only count/indices; no route metadata is copied
        // into this separate object, so there is no second vector owner.
        struct OriginalSnapshotGuard {
            std::uint64_t before{0x19A4710832BF56CDull}; OriginalSnapshot value{};
            std::uint64_t after{0xDE6910F247A835BCull};
        } original_snapshot;
        original_snapshot.value.count=count;
        std::copy_n(snapshot.owner.snapshot.indices.begin(),count,original_snapshot.value.indices.begin());
        struct OriginalGuard {
            std::uint64_t before{0xC815FED0973246ABull}; OriginalMixScratch value{};
            std::uint64_t after{0xD046BC5F789213AEull};
        } original;
        struct ExpandedGuard {
            std::uint64_t before{0xC815FED0973246ABull}; ExpandedMixScratch value{};
            std::uint64_t after{0xD046BC5F789213AEull};
            bool intact() const { return before==0xC815FED0973246ABull && after==0xD046BC5F789213AEull; }
        } compatibility,expanded;
        const auto* channels=reinterpret_cast<const ChannelSlot*>(reinterpret_cast<std::uintptr_t>(view.channels));
        NativeMixSample first,second;
        if (!BuildNativeMixSort(mix,channels,view.capacity,snapshot.owner.snapshot,kOldCapacity,compatibility.value,first,result.reason)) return result;
        mix.original_sort(&original.value,&original_snapshot.value);
        if (!BuildNativeMixSort(mix,channels,view.capacity,snapshot.owner.snapshot,kTargetCapacity,expanded.value,second,result.reason)) return result;
        result.ready_queries=first.ready_queries+second.ready_queries; result.scored_channels=first.scored_channels+second.scored_channels;
        result.same_sound_limit=first.same_sound_limit;
        result.original_count=original.value.count; result.expanded_count=expanded.value.count;
        result.compatibility_matches=first.same_sound_limit==second.same_sound_limit && original.value.count==count && compatibility.value.count==count &&
            !std::memcmp(original.value.sorted.data(),compatibility.value.sorted.data(),sizeof(original.value.sorted)) &&
            !std::memcmp(original.value.cull.data(),compatibility.value.cull.data(),static_cast<std::size_t>(count));
        result.expanded_scores_match=expanded.value.count==count;
        const auto find=[](const MixSortEntry* entries,std::size_t capacity,std::int32_t p) -> const MixSortEntry* {
            for (std::size_t i=0;i<capacity;++i) if (entries[i].snapshot_position==p) return entries+i;
            return nullptr;
        };
        for (std::int32_t p=0;p<count;++p) {
            const auto* old=find(original.value.sorted.data(),kOldCapacity,p);
            const auto* now=find(expanded.value.sorted.data(),kTargetCapacity,p);
            if (!old || !now || old->score!=now->score || old->sfx!=now->sfx) result.expanded_scores_match=false;
            result.culled_original+=original.value.cull[p]!=0; result.culled_expanded+=expanded.value.cull[p]!=0;
        }
        result.guards_intact=snapshot.intact() && compatibility.intact() && expanded.intact() &&
            original.before==0xC815FED0973246ABull && original.after==0xD046BC5F789213AEull &&
            original_snapshot.before==0x19A4710832BF56CDull && original_snapshot.after==0xDE6910F247A835BCull;
        snapshot.owner.Release(); const Vector32Metadata empty{};
        result.routing_released=!std::memcmp(&snapshot.owner.snapshot.auxiliary_routes,&empty,sizeof(empty));
        result.ok=count>0 && result.scored_channels>0 && result.compatibility_matches && result.expanded_scores_match && result.guards_intact && result.routing_released;
        result.reason=result.ok?"native scoring and mix-sort compared; original channels remain capacity 128":
            (count==0?"empty active table; nonempty mix-sort not verified":
                (result.scored_channels==0?"no ready channels; native priority path not verified":"mix-sort comparison or guard/cleanup failed"));
        return result;
    } catch (const std::exception& e) { result.reason=e.what(); return result; }
}

NativePreprocessProbeResult ProbeNativePreprocess() {
    std::lock_guard<std::mutex> lock(g_mutex); NativePreprocessProbeResult result;
    try {
        const auto status=QueryLocked();
        if (!status.loaded_code_matches || !status.supported_disk_build) { result.reason=status.reason; return result; }
        const auto base=reinterpret_cast<std::uintptr_t>(GetModuleHandleW(L"engine.dll"));
        const auto view=CurrentNativeStorageView(base);
        if (!ValidateNativeStorageView(view,result.reason)) return result;
        result.engine_capacity=view.capacity;
        NativeAudioBindings audio; NativePreprocessBindings bindings;
        if (!BindNativeAudio(g_inventory->manifest,g_inventory->image,base,audio,result.reason) ||
            !BindNativePreprocess(g_inventory->manifest,g_inventory->image,base,bindings,result.reason)) return result;
        result.native_binding_verified=true;
        struct SoundScope {
            CRITICAL_SECTION* cs;
            explicit SoundScope(std::uintptr_t address):cs(reinterpret_cast<CRITICAL_SECTION*>(address)) { EnterCriticalSection(cs); }
            ~SoundScope() { LeaveCriticalSection(cs); }
        } sound(base+0x510D50); result.sound_lock_held=true;
        struct Guarded {
            std::uint64_t before{0xAB571902CE3468DFull}; NativeSnapshotOwner owner;
            std::uint64_t after{0xDC1902837465ABFEull};
            explicit Guarded(NativeAudioBindings b):owner(b) {}
            bool intact() const noexcept { return before==0xAB571902CE3468DFull && after==0xDC1902837465ABFEull; }
        } snapshot(audio),fixture(audio);
        // Exercise the actual engine allocator and reallocator on a private vector.
        // These numbers are fixture route values, never engine channel allocations.
        for (std::int32_t id=1;id<=static_cast<std::int32_t>(kTargetCapacity);++id) {
            bool appended{};
            if (!AppendNativeMixRoute(bindings,fixture.owner.snapshot.auxiliary_routes,id,appended,result.reason) || !appended) return result;
        }
        bool appended{};
        if (!AppendNativeMixRoute(bindings,fixture.owner.snapshot.auxiliary_routes,1,appended,result.reason) || appended) return result;
        const auto& vector=fixture.owner.snapshot.auxiliary_routes;
        const auto* values=reinterpret_cast<const std::int32_t*>(vector.memory);
        for (std::int32_t p=0;p<512;++p) if (values[p]!=p+1) { result.reason="native route allocator fixture corrupted"; return result; }
        result.route_fixture_count=vector.size; result.allocator_exercised=vector.size==512;
        fixture.owner.Release();
        std::int32_t count{};
        if (!ReadValue(reinterpret_cast<std::uintptr_t>(view.active_count),count) || !snapshot.owner.Build(reinterpret_cast<const std::int16_t*>(reinterpret_cast<std::uintptr_t>(view.active_indices)),
            count,view.capacity,result.reason)) return result;
        auto* channels=reinterpret_cast<ChannelSlot*>(reinterpret_cast<std::uintptr_t>(view.channels));
        result.volume_matches=true;
        const auto original_quiet=reinterpret_cast<bool (*)(const ChannelSlot*,std::int32_t)>(bindings.quiet_channel);
        for (std::int32_t p=0;p<count;++p) {
            const auto& channel=channels[snapshot.owner.snapshot.indices[p]];
            if (original_quiet(&channel,1)!=ChannelVolumesAtMost(channel,1)) result.volume_matches=false;
            ++result.volume_checked;
        }
        if (!result.volume_matches) { result.reason="native volume predicate mismatch; owner not executed"; return result; }
        // One execution only: owner may free invalid sources, alter mixer pitch and
        // clear original globals. It is never compared by replaying the original.
        if (!PreprocessNativeMix(bindings,channels,view.capacity,snapshot.owner.snapshot,result.sample,result.reason)) return result;
        result.route_count=snapshot.owner.snapshot.auxiliary_routes.size; result.route_mask=snapshot.owner.snapshot.route_mask;
        if (!ReadValue(reinterpret_cast<std::uintptr_t>(view.active_count),result.active_after)) { result.reason="cannot read post-preprocessing active count"; return result; }
        result.guards_intact=snapshot.intact() && fixture.intact();
        snapshot.owner.Release(); const Vector32Metadata empty{};
        result.routing_released=!std::memcmp(&snapshot.owner.snapshot.auxiliary_routes,&empty,sizeof(empty)) &&
            !std::memcmp(&fixture.owner.snapshot.auxiliary_routes,&empty,sizeof(empty));
        result.ok=result.sample.input_count>0 && result.sample.pitch_updates>0 && result.guards_intact &&
            result.routing_released && result.allocator_exercised && result.volume_matches;
        result.reason=result.ok?"native preprocessing executed once; pitch and routing exercised using current storage":
            "preprocessing did not cover a retained source or guard/cleanup failed";
        return result;
    } catch (const std::exception& e) { result.reason=e.what(); return result; }
}

NativeAllStopProbeResult ProbeNativeAllStop(bool clear_device) {
    std::lock_guard<std::mutex> lock(g_mutex);
    NativeAllStopProbeResult result;
    try {
        const auto status=QueryLocked();
        if (!status.loaded_code_matches || !status.supported_disk_build) { result.reason=status.reason; return result; }
        const auto base=reinterpret_cast<std::uintptr_t>(GetModuleHandleW(L"engine.dll"));
        const auto view=CurrentNativeStorageView(base);
        if (!ValidateNativeStorageView(view,result.reason)) return result;
        result.engine_capacity=view.capacity;
        NativeAllStopBindings bindings;
        if (!BindNativeAllStop(g_inventory->manifest,g_inventory->image,base,bindings,result.reason)) return result;
        result.native_binding_verified=true;
        struct SoundScope {
            CRITICAL_SECTION* cs;
            explicit SoundScope(std::uintptr_t address):cs(reinterpret_cast<CRITICAL_SECTION*>(address)) { EnterCriticalSection(cs); }
            ~SoundScope() { LeaveCriticalSection(cs); }
        } sound(base+0x510D50);
        result.sound_lock_held=true;
        if (!ReadValue(reinterpret_cast<std::uintptr_t>(view.active_count),result.active_before)) { result.reason="cannot read pre-all-stop count"; return result; }
        auto* channels=reinterpret_cast<ChannelSlot*>(reinterpret_cast<std::uintptr_t>(view.channels));
        if (!StopAllNativeSounds(bindings,channels,view.capacity,clear_device,result.sample,result.reason)) return result;
        if (!ReadValue(reinterpret_cast<std::uintptr_t>(view.active_count),result.active_after) || !ReadValue(base+kTotalRva,result.total_after)) {
            result.reason="cannot read post-all-stop state"; return result;
        }
        result.storage_zero=true;
        for (std::uint32_t i=0;i<view.capacity;++i) {
            ChannelSlot slot;
            if (!Read(reinterpret_cast<std::uintptr_t>(view.channels)+i*kChannelStride,slot.bytes.data(),slot.bytes.size()) ||
                std::any_of(slot.bytes.begin(),slot.bytes.end(),[](std::uint8_t x){return x!=0;})) { result.storage_zero=false; break; }
        }
        std::array<std::uint8_t,24> pending{};
        result.pending_globals_zero=Read(base+0x51B030,pending.data(),pending.size()) &&
            std::all_of(pending.begin(),pending.end(),[](std::uint8_t x){return x==0;});
        result.ok=result.sample.device_ready && result.sample.source_count>0 &&
            result.sample.freed==result.sample.source_count && result.sample.pool_clears==3 &&
            result.sample.cleared_bytes==view.capacity*kChannelStride && result.sample.routing_released &&
            result.active_after==0 && result.total_after==static_cast<std::int32_t>(kDynamicCapacity) &&
            result.storage_zero && result.pending_globals_zero && (!clear_device || result.sample.device_cleared);
        result.reason=result.ok?"native all-stop cleanup executed once using current storage":
            "all-stop lacked a nonempty ready source or final cleanup did not match";
        return result;
    } catch (const std::exception& e) { result.reason=e.what(); return result; }
}

namespace {
NativeStage g_native_stage=NativeStage::Engine;
NativeState g_native_state=NativeState::Waiting;
bool g_native_attempted=false, g_native_cleared=false;
std::string g_native_reason="native session not started";
NativeRequestV1 NativeStatusLocked() {
    NativeRequestV1 out;
    const auto status=QueryLocked(); const auto frame=QueryFrameBridge();
    const auto snapshot=QuerySnapshotBridge(), storage=QueryStorageBridge(), capacity=QueryCapacityBridge();
    out.state=static_cast<std::uint32_t>(g_native_state); out.stage=static_cast<std::uint32_t>(g_native_stage);
    out.capacity=status.current_capacity; out.active=status.active_count; out.dynamic=status.active_dynamic;
    out.statics=status.active_static; out.total=status.total_channels;
    out.errors=frame.errors+snapshot.errors; out.fallback=frame.fallback_paints;
    out.frames=frame.frames; out.preprocessed=frame.preprocessed; out.backend=frame.backend_calls;
    out.paint=frame.paint_calls; out.mixed=frame.mixed; out.freed=frame.freed;
    out.storage_redirects=storage.storage_redirect_count;
    if (status.loaded_code_matches) out.diagnostic_flags|=kDiagCodeMatches;
    if (status.sampled_counts_valid) out.diagnostic_flags|=kDiagCountsValid;
    if (storage.storage_guards_intact) out.diagnostic_flags|=kDiagStorageGuards;
    if (frame.active) out.diagnostic_flags|=kDiagFrameActive;
    if (snapshot.active) out.diagnostic_flags|=kDiagSnapshotActive;
    if (storage.active) out.diagnostic_flags|=kDiagStorageActive;
    if (capacity.active) out.diagnostic_flags|=kDiagCapacityActive;
    const auto all=kDiagCodeMatches|kDiagStorageGuards|kDiagFrameActive|kDiagSnapshotActive|kDiagStorageActive|kDiagCapacityActive;
    if (out.capacity==512 && (out.diagnostic_flags&all)==all && !out.errors && !out.fallback) {
        out.state=static_cast<std::uint32_t>(NativeState::Active); out.stage=static_cast<std::uint32_t>(NativeStage::Complete);
        SetNativeReason(out,status.sampled_counts_valid?"native512 active; music/voice/endurance validation pending":"native512 active; best-effort channel sample unstable, retry query");
    } else {
        if (g_native_state==NativeState::Active) {
            out.state=static_cast<std::uint32_t>(NativeState::RestartRequired);
            SetNativeReason(out,"native512 health no longer matches; restart required");
        } else SetNativeReason(out,g_native_reason);
    }
    return out;
}
bool NativeReadyLocked(NativeState& state,NativeStage& stage,std::string& reason) {
    state=NativeState::Waiting; stage=NativeStage::Engine;
    const auto module=GetModuleHandleW(L"engine.dll");
    if (!module) { reason="waiting for engine.dll"; return false; }
    const auto status=QueryLocked();
    if (!status.supported_disk_build || !status.loaded_code_matches) { state=NativeState::Rejected; reason=status.reason; return false; }
    const auto client=GetModuleHandleW(L"client.dll");
    std::array<wchar_t,32768> client_path{};
    const auto client_length=client?GetModuleFileNameW(client,client_path.data(),static_cast<DWORD>(client_path.size())):0;
    if (!client_length || client_length>=client_path.size()) { reason="waiting for GMod client module"; return false; }
    std::error_code path_error;
    if (!std::filesystem::equivalent(std::filesystem::path(client_path.data()),g_disk_path.parent_path()/L"client.dll",path_error) || path_error) {
        state=NativeState::Rejected; reason="client module is outside selected engine directory"; return false;
    }
    const auto base=reinterpret_cast<std::uintptr_t>(module);
    // Known engine .CRT initializer table invokes CThreadMutex constructor9160.
    // Export is called only after normal LoadLibrary completes (outside loader lock).
    std::uintptr_t constructor{};
    if (!ReadValue(base+0x38FD80,constructor) || constructor!=base+0x9160) {
        state=NativeState::Rejected; reason="engine sound mutex initializer identity mismatch"; return false;
    }
    stage=NativeStage::Audio;
    std::uint8_t started{}; std::uintptr_t device{};
    if (!ReadValue(base+0x51B0B0,started) || !started || !ReadValue(base+0x55E198,device) || !device || !status.sampled_counts_valid) {
        reason="waiting for initialized audio device and valid channel table"; return false;
    }
    auto* cs=reinterpret_cast<CRITICAL_SECTION*>(base+0x510D50);
    if (!TryEnterCriticalSection(cs)) { reason="waiting for audio mutex"; return false; }
    struct Unlock { CRITICAL_SECTION* cs; ~Unlock(){LeaveCriticalSection(cs);} } unlock{cs};
    std::uintptr_t current{},table{},method{};
    if (!ReadValue(base+0x55E198,current) || current!=device || !ReadValue(device,table) || !table || !ReadValue(table+8,method)) {
        reason="audio device changed or is unreadable"; return false;
    }
    MEMORY_BASIC_INFORMATION page{};
    if (!VirtualQuery(reinterpret_cast<void*>(method),&page,sizeof(page)) || page.State!=MEM_COMMIT || page.Type!=MEM_IMAGE ||
        (page.Protect&PAGE_GUARD) || !(page.Protect&(PAGE_EXECUTE|PAGE_EXECUTE_READ|PAGE_EXECUTE_READWRITE|PAGE_EXECUTE_WRITECOPY))) {
        state=NativeState::Rejected; reason="audio ready method is not executable image code"; return false;
    }
    if (!reinterpret_cast<bool (*)(void*)>(method)(reinterpret_cast<void*>(device))) { reason="waiting for audio device readiness"; return false; }
    stage=NativeStage::Validating; state=NativeState::Idle; reason="native audio readiness checked; installation synchronization still required"; return true;
}
}
NativeRequestV1 QueryNativeSession(bool readiness) {
    std::lock_guard<std::mutex> lock(g_mutex);
    try {
        auto out=NativeStatusLocked();
        if (readiness && out.state!=static_cast<std::uint32_t>(NativeState::Active) && out.state!=static_cast<std::uint32_t>(NativeState::RestartRequired)) {
            NativeState state{}; NativeStage stage{}; std::string reason;
            NativeReadyLocked(state,stage,reason);
            out.state=static_cast<std::uint32_t>(state); out.stage=static_cast<std::uint32_t>(stage); SetNativeReason(out,reason);
        }
        return out;
    } catch (const std::exception& e) { NativeRequestV1 out; out.state=static_cast<std::uint32_t>(NativeState::Failed); SetNativeReason(out,e.what()); return out; }
}
NativeRequestV1 StartNativeSession(std::uint32_t flags,std::uintptr_t return_slot) {
    std::lock_guard<std::mutex> lock(g_mutex);
    const auto failure=[&](const std::string& reason) {
        g_native_state=NativeState::RestartRequired; g_native_reason=reason; return NativeStatusLocked();
    };
    try {
        if (!(flags&kNativeAck) || flags&~(kNativeAck|kNativeClearOnce) || !return_slot) {
            NativeRequestV1 out; out.state=static_cast<std::uint32_t>(NativeState::Rejected); SetNativeReason(out,"invalid native start options/return slot"); return out;
        }
        auto current=NativeStatusLocked();
        if (current.state==static_cast<std::uint32_t>(NativeState::Active)) return current;
        if (g_native_attempted || g_native_state==NativeState::RestartRequired) return failure("previous native activation incomplete; restart GMod");
        if (!NativeReadyLocked(g_native_state,g_native_stage,g_native_reason)) return NativeStatusLocked();
        const auto base=reinterpret_cast<std::uintptr_t>(GetModuleHandleW(L"engine.dll"));
        g_native_stage=NativeStage::Empty;
        if (QueryLocked().active_count!=0) {
            if (!(flags&kNativeClearOnce)) { g_native_state=NativeState::Waiting; g_native_reason="waiting for empty audio table; startup clear not authorized"; return NativeStatusLocked(); }
            if (g_native_cleared) return failure("startup clear already attempted; restart required");
            NativeAllStopBindings binding{}; std::string reason;
            if (!BindNativeAllStop(g_inventory->manifest,g_inventory->image,base,binding,reason)) return failure(reason);
            auto* cs=reinterpret_cast<CRITICAL_SECTION*>(base+0x510D50);
            if (!TryEnterCriticalSection(cs)) { g_native_state=NativeState::Waiting; g_native_reason="waiting for sound mutex before startup clear"; return NativeStatusLocked(); }
            bool ok=false; NativeAllStopSample sample{};
            {
                struct Unlock { CRITICAL_SECTION* cs; ~Unlock(){LeaveCriticalSection(cs);} } unlock{cs};
                const auto view=CurrentNativeStorageView(base); g_native_cleared=true;
                ok=StopAllNativeSounds(binding,view.channels,view.capacity,true,sample,reason);
            }
            if (!ok || !sample.device_ready || !sample.routing_released) return failure(reason.empty()?"startup audio clear incomplete":reason);
        }
        if (QueryLocked().active_count!=0) { g_native_state=NativeState::Waiting; g_native_reason="audio table changed before activation"; return NativeStatusLocked(); }
        g_native_attempted=true;
        g_native_stage=NativeStage::Frame; const auto frame=StartFrameBridgeLocked(); if (!frame.active || frame.errors) return failure(frame.reason);
        g_native_stage=NativeStage::Snapshot; const auto snapshot=StartSnapshotBridgeLocked(return_slot,true); if (!snapshot.active || snapshot.errors) return failure(snapshot.reason);
        g_native_stage=NativeStage::Storage; const auto storage=StartStorageBridgeLocked(return_slot,true); if (!storage.active || !storage.storage_guards_intact) return failure(storage.reason);
        g_native_stage=NativeStage::Capacity; const auto capacity=StartCapacityBridgeLocked(return_slot,true); if (!capacity.active || capacity.engine_capacity!=512 || !capacity.storage_guards_intact) return failure(capacity.reason);
        g_native_stage=NativeStage::Complete; g_native_state=NativeState::Active; g_native_reason="native512 active; experimental verification scope applies";
        return NativeStatusLocked();
    } catch (const std::exception& e) { return failure(e.what()); }
}

}
