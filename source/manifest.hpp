#pragma once
#include <cstdint>
#include <cstddef>
#include <filesystem>
#include <string>
#include <vector>
#include <array>
#include <memory>
#include <atomic>

namespace channel_expand {
constexpr std::uint32_t kOldCapacity = 128, kTargetCapacity = 512, kDynamicCapacity = 64;
constexpr std::uint32_t kChannelStride = 320;
constexpr std::uint32_t kChannelsRva = 0x506D30, kChannelsEndRva = 0x510D30;
constexpr std::uint32_t kActiveRva = 0x506C20, kTotalRva = 0x50208C;
constexpr char kExpectedSha[] = "7C21E827722FA7AC9BA4539DC652D3B79F58E240DA49D28E75A1A9A1A88C4173";

struct Section { std::uint32_t rva{}, virtual_size{}, offset{}, raw_size{}, flags{}; std::string name; };
struct FunctionRange { std::uint32_t begin{}, end{}, unwind{}, root{}; bool chain_valid{}; };
struct PeImageView {
    std::vector<std::uint8_t> bytes;
    std::vector<Section> sections;
    std::vector<FunctionRange> functions;
    std::uint64_t preferred_base{};
    std::uint32_t image_size{}, headers_size{}, timestamp{}, entry{}, reloc_rva{}, reloc_size{};
    const std::uint8_t* rva_ptr(std::uint32_t rva, std::size_t length) const noexcept;
};
struct Reference {
    std::uint32_t instruction{}, target{}, range_begin{}, root{};
    std::string kind, instruction_text, original_bytes, confidence;
};
struct DecodeIssue { std::uint32_t rva{}, range_begin{}; std::string reason; };
struct BuildManifest {
    std::string sha256;
    bool supported{}, complete{};
    std::vector<Reference> references;
    std::vector<DecodeIssue> decode_issues;
    std::vector<std::string> unresolved;
};
struct InventoryResult { bool parsed{}; PeImageView image; BuildManifest manifest; std::string reason; };

bool ParsePe(std::vector<std::uint8_t> bytes, PeImageView& image, std::string& reason);
InventoryResult InspectEngine(const std::filesystem::path& path);
bool ValidateManifest(const BuildManifest&, const PeImageView&, std::string& reason);
std::string InventoryJson(const InventoryResult&);
bool RunPeSelfChecks(std::string& reason);

// Raw engine channel bytes, not a mixer object or an imitation of Source APIs.
struct alignas(16) ChannelSlot { std::array<std::uint8_t, kChannelStride> bytes{}; };
struct NativeStorageView {
    ChannelSlot* channels{};
    const std::int32_t* active_count{};
    const std::int16_t* active_indices{};
    std::uint32_t capacity{};
};
NativeStorageView OriginalNativeStorageView(std::uintptr_t) noexcept;
bool ValidateNativeStorageView(const NativeStorageView&,std::string&);
bool RunStorageViewSelfChecks(std::string&);
struct NativeGuidContext; struct MemoryPatch;
bool BuildStorageContextPatches(const NativeStorageView&,const NativeStorageView&,NativeGuidContext&,std::vector<MemoryPatch>&,std::string&);
NativeStorageView CurrentNativeStorageView(std::uintptr_t) noexcept;
struct ActiveList { std::int32_t count{}; std::array<std::int16_t, kTargetCapacity> indices{}; };
struct ChannelAllocation {
    std::array<std::uint64_t, 2> before{};
    std::array<ChannelSlot, kTargetCapacity> slots{};
    std::array<std::uint64_t, 2> after{};
};
struct ActiveAllocation {
    std::array<std::uint64_t, 2> before{};
    ActiveList list{};
    std::array<std::uint64_t, 2> after{};
};
struct ExpandedStorage {
    std::unique_ptr<ChannelAllocation> channels;
    std::unique_ptr<ActiveAllocation> active;
    // This storage is not attached to engine.dll. GUID/mixer lifetime is not inferred.
    std::int32_t total_channels{kDynamicCapacity};
};
bool AllocateStorage(ExpandedStorage&, std::string& reason);
bool CheckStorageInvariants(const ExpandedStorage&, std::string& reason);
bool AddActive(ExpandedStorage&, std::uint32_t index) noexcept;
bool RemoveActive(ExpandedStorage&, std::uint32_t index) noexcept;
bool RunStorageSelfChecks(std::string& reason);

// Engine-owned dynamic vector metadata; this type never frees or dereferences it.
// The recorded auxiliary values route extra mix buffers, not voice-channel IDs.
struct Vector32Metadata {
    std::uintptr_t memory{};
    std::int32_t allocation_count{}, grow_size{}, size{}, alignment_padding{};
    std::uintptr_t elements{};
};
template<std::size_t Capacity> struct ChannelSnapshot {
    std::int32_t count{};
    std::array<std::int16_t, Capacity> indices{};
    std::array<std::uint8_t, Capacity> item_flags{};
    std::array<std::uint8_t, 4> reserved{};
    Vector32Metadata auxiliary_routes{};
    std::uint8_t route_mask{};
    std::array<std::uint8_t, 7> tail_padding{};
};
using OriginalSnapshot = ChannelSnapshot<kOldCapacity>;
using ExpandedSnapshot = ChannelSnapshot<kTargetCapacity>;
bool CopyActiveSnapshot(const ExpandedStorage&, ExpandedSnapshot&, std::string& reason);
const ChannelSlot* LookupGuidInSnapshot(const ExpandedStorage&, const ExpandedSnapshot&, std::uint32_t guid) noexcept;
bool RunSnapshotSelfChecks(std::string& reason);
bool RemoveMixSnapshotItem(ExpandedSnapshot&,std::int32_t position,std::string& reason);
bool RunMixPreprocessLayoutSelfChecks(std::string& reason);
bool ChannelVolumesAtMost(const ChannelSlot&,std::int32_t threshold) noexcept;
bool RunMixVolumeSelfChecks(std::string& reason);
bool CompareOriginalVolumeKernel(const std::filesystem::path&,std::string& reason);

// Native bridge: source count is deliberately zero when entering engine 0x2C110.
// The engine constructs routing with its allocator; expanded indices are copied separately.
using NativeSnapshotBuilder = void (*)(const std::int32_t*, OriginalSnapshot*);
using NativeVectorFree = void (*)(void*);
using NativeGuidLookup = const ChannelSlot* (*)(std::uint32_t);
struct NativeAudioBindings {
    NativeSnapshotBuilder build_routes{};
    NativeVectorFree release_vector{};
    NativeGuidLookup original_guid_lookup{};
};
bool BindNativeAudio(const BuildManifest&, const PeImageView&, std::uintptr_t engine_base,
    NativeAudioBindings&, std::string& reason);
bool CopySnapshotIndices(const std::int16_t* indices,std::int32_t count,std::uint32_t capacity,
    ExpandedSnapshot&,std::string& reason);
bool AdoptRouteMetadata(OriginalSnapshot&,ExpandedSnapshot&,std::string& reason);
class NativeSnapshotOwner {
public:
    explicit NativeSnapshotOwner(NativeAudioBindings bindings) noexcept : bindings_(bindings) {}
    NativeSnapshotOwner(const NativeSnapshotOwner&)=delete;
    NativeSnapshotOwner& operator=(const NativeSnapshotOwner&)=delete;
    ~NativeSnapshotOwner() noexcept;
    ExpandedSnapshot snapshot{};
    bool Build(const std::int16_t* indices,std::int32_t count,std::uint32_t capacity,std::string& reason);
    void Release() noexcept;
private:
    NativeAudioBindings bindings_{};
};
bool RunNativeBridgeSelfChecks(std::string& reason);
const ChannelSlot* LookupGuidInNativeSnapshot(const ChannelSlot* channels,std::uint32_t capacity,
    const ExpandedSnapshot&,std::uint32_t guid) noexcept;
struct NativeGuidContext {
    NativeAudioBindings bindings{};
    const std::int32_t* active_count{};
    const std::int16_t* active_indices{};
    const ChannelSlot* channels{};
    std::uint32_t capacity{};
    std::uintptr_t sound_critical_section{};
};
bool EncodeNativeGuidThunk(std::uintptr_t context,std::uintptr_t entry,std::array<std::uint8_t,26>&,
    std::string& reason);
class NativeGuidThunk {
public:
    NativeGuidThunk()=default;
    NativeGuidThunk(const NativeGuidThunk&)=delete;
    NativeGuidThunk& operator=(const NativeGuidThunk&)=delete;
    ~NativeGuidThunk() noexcept;
    bool Prepare(NativeGuidContext&,std::string& reason);
    NativeGuidLookup entry() const noexcept { return reinterpret_cast<NativeGuidLookup>(page_); }
private:
    void* page_{};
};
bool RunGuidThunkSelfChecks(std::string& reason);
using NativeChannelFree = void (*)(ChannelSlot*);
using NativeStopByEntityChannel = void (*)(std::int32_t,std::int32_t);
struct NativeStopContext {
    NativeGuidContext channels{};
    NativeChannelFree free_channel{};
};
bool BindNativeChannelFree(const BuildManifest&,const PeImageView&,std::uintptr_t engine_base,
    NativeChannelFree&,std::string& reason);
bool SelectStopChannels(const ChannelSlot*,std::uint32_t capacity,const ExpandedSnapshot&,
    std::int32_t sound_source,std::int32_t entity_channel,ActiveList&,std::string& reason);
bool EncodeNativeStopThunk(std::uintptr_t context,std::uintptr_t entry,std::array<std::uint8_t,29>&,
    std::string& reason);
class NativeStopThunk {
public:
    NativeStopThunk()=default;
    NativeStopThunk(const NativeStopThunk&)=delete;
    NativeStopThunk& operator=(const NativeStopThunk&)=delete;
    ~NativeStopThunk() noexcept;
    bool Prepare(NativeStopContext&,std::string& reason);
    NativeStopByEntityChannel entry() const noexcept { return reinterpret_cast<NativeStopByEntityChannel>(page_); }
private:
    void* page_{};
};
bool RunStopConsumerSelfChecks(std::string& reason);
struct NativeAllStopBindings {
    NativeAudioBindings audio{};
    NativeChannelFree free_channel{};
    std::uintptr_t base{};
};
struct NativeAllStopSample {
    bool device_ready{},device_cleared{},routing_released{};
    std::int32_t source_count{},freed{},interface_calls{},pool_clears{};
    std::uint32_t cleared_bytes{};
};
bool ClearReleasedChannelStorage(ChannelSlot*,std::uint32_t,std::uint32_t&,std::string&);
bool RunAllStopStorageSelfChecks(std::string&);
using ActiveSoundRecord=std::array<std::uint8_t,0x48>;
using MusicSoundRecord=std::array<std::uint8_t,0x88>;
struct NativeConsumerBindings {
    NativeGuidContext context{};
    NativeChannelFree free_channel{};
    std::uintptr_t base{},growth{},allocate{},reallocate{},music_predicate{},copy_name{};
};
struct NativeConsumerSample { std::int32_t source_count{},appended{},matched{},freed{}; bool routing_released{}; };
void PackActiveSoundRecord(const ChannelSlot&,std::uintptr_t,std::uintptr_t,float,ActiveSoundRecord&) noexcept;
bool NativeAppendRecord(const NativeConsumerBindings&,Vector32Metadata&,const void*,std::uint32_t,std::string&);
bool RunQueryRecordSelfChecks(std::string&);
bool StripSoundUpdateModifiers(const char*,std::size_t,bool&,std::string&);
bool MatchesSoundUpdate(const ChannelSlot&,std::int32_t,std::int32_t,std::uintptr_t,std::uint32_t,bool) noexcept;
void ApplySoundUpdateFields(ChannelSlot&,std::int32_t,std::int32_t,std::uint32_t,std::int32_t) noexcept;
bool RunSoundUpdateSelfChecks(std::string&);
struct MemoryPatch;

// This carrier keeps the1B0 shell, but its indices field holds a pointer.
// Only the individually verified LEA->MOV consumers may read it.
bool PackLegacyIndexCarrier(const ExpandedSnapshot&,std::uintptr_t,const Vector32Metadata&,OriginalSnapshot&,std::string&);
bool BuildNativeLegacyCarrier(const NativeConsumerBindings&,const std::int16_t*,std::int32_t,OriginalSnapshot&,std::string&);
bool EncodeLegacyIndexLoad(const std::vector<std::uint8_t>&,std::vector<std::uint8_t>&,std::string&);
bool BuildLegacyConsumerLoadPlan(const BuildManifest&,const PeImageView&,std::uintptr_t,std::vector<MemoryPatch>&,std::string&);
bool RunLegacyCarrierSelfChecks(std::string&);
enum class LegacyConstructorRoute { Original,Carrier,Reject };
struct NativeLegacyConstructorContext {
    NativeConsumerBindings consumers{};
    NativeSnapshotBuilder original{};
    std::array<std::uintptr_t,13> caller_returns{};
    std::atomic<std::uint64_t> calls{},carriers{},passthrough{},errors{};
};
LegacyConstructorRoute SelectLegacyConstructorRoute(const NativeLegacyConstructorContext&,const std::int32_t*,std::uintptr_t) noexcept;
bool BindNativeLegacyConstructor(const BuildManifest&,const PeImageView&,std::uintptr_t,NativeSnapshotBuilder,
    NativeLegacyConstructorContext&,std::string&);
bool EncodeLegacyConstructorThunk(std::uintptr_t,std::uintptr_t,std::array<std::uint8_t,34>&,std::string&);
class NativeLegacyConstructorThunk {
public:
    NativeLegacyConstructorThunk()=default;
    NativeLegacyConstructorThunk(const NativeLegacyConstructorThunk&)=delete;
    NativeLegacyConstructorThunk& operator=(const NativeLegacyConstructorThunk&)=delete;
    ~NativeLegacyConstructorThunk() noexcept;
    bool Prepare(NativeLegacyConstructorContext&,std::string&);
    NativeSnapshotBuilder entry() const noexcept { return reinterpret_cast<NativeSnapshotBuilder>(page_); }
    void RetainForProcessLifetime() noexcept { retained_=true; }
private:
    void* page_{}; bool retained_{};
};
bool RunLegacyConstructorSelfChecks(std::string&);


bool BindNativeConsumers(const BuildManifest&,const PeImageView&,std::uintptr_t,NativeConsumerBindings&,std::string&);
bool QueryNativeActiveSounds(const NativeConsumerBindings&,Vector32Metadata&,NativeConsumerSample&,std::string&);
bool QueryNativeMusicSounds(const NativeConsumerBindings&,Vector32Metadata&,NativeConsumerSample&,std::string&);
bool UpdateNativeSound(const NativeConsumerBindings&,std::int32_t,std::int32_t,std::uintptr_t,std::int32_t,
    std::int32_t,std::uint32_t,std::int32_t,NativeConsumerSample&,std::string&);

bool BindNativeAllStop(const BuildManifest&,const PeImageView&,std::uintptr_t,NativeAllStopBindings&,std::string&);
bool StopAllNativeSounds(const NativeAllStopBindings&,ChannelSlot*,std::uint32_t,bool,NativeAllStopSample&,std::string&);

struct MemoryPatch {
    std::uintptr_t address{};
    std::vector<std::uint8_t> expected, replacement;
};
struct StorageRedirectPlan {
    std::vector<MemoryPatch> patches,legacy_loads,capacity_patches;
    std::vector<Reference> pending;
    std::uintptr_t engine_base{},channels{},active{};
};
bool EncodeRipStorageRedirect(const std::vector<std::uint8_t>&,std::uintptr_t,std::uintptr_t,std::uintptr_t,
    std::vector<std::uint8_t>&,std::string&);
bool BuildStorageRedirectPlan(const BuildManifest&,const PeImageView&,std::uintptr_t,std::uintptr_t,std::uintptr_t,StorageRedirectPlan&,std::string&);
std::string StorageRedirectPlanJson(const StorageRedirectPlan&);
bool RunStorageRedirectSelfChecks(std::string&);
bool BuildCapacityBoundaryPlan(const BuildManifest&,const PeImageView&,std::uintptr_t,std::vector<MemoryPatch>&,std::string&);
bool RunCapacityBoundarySelfChecks(std::string&);
bool VerifyKnownChannelLeaves(const PeImageView&,std::string&);
bool CompareOriginalChannelLeaves(const std::filesystem::path&,std::string&);
class NearChannelStorage {
public:
    NearChannelStorage()=default;
    NearChannelStorage(const NearChannelStorage&)=delete;
    NearChannelStorage& operator=(const NearChannelStorage&)=delete;
    ~NearChannelStorage() noexcept;
    bool Prepare(std::uintptr_t engine_base,std::size_t image_size,std::string&);
    ChannelSlot* channels() const noexcept;
    ActiveList* active() const noexcept;
    bool GuardsIntact() const noexcept;
    void RetainForProcessLifetime() noexcept { retained_=true; }
private:
    void* region_{};
    void* block_{};
    std::size_t region_size_{};
    bool retained_{};
};
bool RunNearStorageSelfChecks(std::string&);


// CLI-only transaction primitive for now; engine install must separately prove quiescence.
bool ApplyPatchTransaction(const std::vector<MemoryPatch>&,std::string& reason);
bool RunPatchSelfChecks(std::string& reason);
// Prepare before suspending threads. Apply/Restore allocate no memory and do
// not prove quiescence: the installer owns thread, stack and sound-lock guards.
class PreparedPatchTransaction {
public:
    enum class Dialect { Original,Replacement,Unknown };
    struct Fault { int after_write{-1},after_protect{-1},after_restore{-1}; bool before_flush{}; };
    PreparedPatchTransaction()=default;
    PreparedPatchTransaction(const PreparedPatchTransaction&)=delete;
    PreparedPatchTransaction& operator=(const PreparedPatchTransaction&)=delete;
    bool Prepare(const std::vector<MemoryPatch>&,std::string&);
    bool ApplyWhileQuiescent(Fault) noexcept;
    bool RestoreWhileQuiescent(Fault) noexcept;
    Dialect dialect() const noexcept { return dialect_; }
    bool resume_safe() const noexcept { return resume_safe_; }
    const char* failure() const noexcept { return failure_; }
    std::size_t site_count() const noexcept { return site_count_; }
private:
    struct Site { std::uintptr_t address{}; std::size_t size{}; std::array<std::uint8_t,32> original{},replacement{}; };
    struct Page { std::uintptr_t address{}; std::uint32_t protection{}; bool writable{}; };
    std::array<Site,256> sites_{};
    std::array<Page,512> pages_{};
    std::size_t site_count_{},page_count_{},page_size_{};
    bool ready_{},resume_safe_{};
    Dialect dialect_{Dialect::Unknown}; const char* failure_{};
    bool Matches(bool) const noexcept;
    bool ProtectionsMatch() const noexcept;
    bool RestorePages(int) noexcept;
    bool SiteWritable(std::size_t) const noexcept;
    bool Run(bool,Fault) noexcept;
};
bool RunPreparedPatchSelfChecks(std::string&);
bool RunEngineRelocationTransaction(const std::filesystem::path&,std::string&);


struct MixSortEntry { std::int32_t snapshot_position{-1}, score{-1}; std::uintptr_t sfx{}; };
struct ExpandedMixScratch {
    std::array<MixSortEntry,kTargetCapacity> sorted{};
    std::array<std::uint8_t,kTargetCapacity> cull{};
    std::int32_t count{};
};
struct OriginalMixScratch {
    std::array<MixSortEntry,kOldCapacity> sorted{};
    std::array<std::uint8_t,kOldCapacity> cull{};
    std::int32_t count{};
};
using NativeMixCompare = int (*)(const void*,const void*);
using NativeMixQsort = void (*)(void*,std::size_t,std::size_t,NativeMixCompare);
using NativeMixPriority = float (*)(const ChannelSlot*);
using NativeOriginalMixSort = void (*)(OriginalMixScratch*,const OriginalSnapshot*);
struct NativeMixBindings {
    NativeMixPriority priority{};
    NativeOriginalMixSort original_sort{};
    NativeMixQsort sort{};
    NativeMixCompare compare{};
    std::uintptr_t engine_base{};
};
struct NativeMixSample { std::int32_t ready_queries{},scored_channels{},same_sound_limit{}; };
bool BindNativeMix(const BuildManifest&,const PeImageView&,std::uintptr_t,NativeMixBindings&,std::string&);
bool ReadNativeDuplicateLimit(const NativeMixBindings&,std::int32_t&,std::string&);
std::int32_t TruncateMixPriority(float) noexcept;
bool PrepareMixSortKernel(const std::array<MixSortEntry,kTargetCapacity>& input,std::int32_t count,
    const std::array<std::uintptr_t,kTargetCapacity>& channel_sfx,std::int32_t same_sound_limit,
    std::uint32_t sort_capacity,NativeMixQsort,NativeMixCompare,ExpandedMixScratch&,std::string& reason);
bool BuildNativeMixSort(const NativeMixBindings&,const ChannelSlot*,std::uint32_t channel_capacity,
    const ExpandedSnapshot&,std::uint32_t sort_capacity,ExpandedMixScratch&,NativeMixSample&,std::string&);
bool RunNativeMixSelfChecks(std::string&);
struct NativePreprocessBindings {
    NativeMixBindings mix{};
    NativeChannelFree free_channel{};
    std::uintptr_t resolve_source{},quiet_channel{},route_growth{},allocate{},reallocate{},clear_global{};
};
struct NativePreprocessSample {
    std::int32_t input_count{},retained{},not_ready{},dropped{},freed{},pitch_updates{},route_appends{},global_clears{};
};
bool BindNativePreprocess(const BuildManifest&,const PeImageView&,std::uintptr_t,NativePreprocessBindings&,std::string&);
bool AppendNativeMixRoute(const NativePreprocessBindings&,Vector32Metadata&,std::int32_t,bool& appended,std::string&);
bool PreprocessNativeMix(const NativePreprocessBindings&,ChannelSlot*,std::uint32_t,ExpandedSnapshot&,
    NativePreprocessSample&,std::string&);
// Caller holds the sound CS throughout; original free/source callbacks require
// engine globals to address the same channel storage. Current probe uses 128.
std::uint8_t RetainedMixMask(std::uint8_t,std::uint8_t,std::int32_t) noexcept;
bool RunMixRouteSelfChecks(std::string&);
bool MatchesPaintRoute(std::uint8_t flags,std::int32_t route_id,std::int32_t route_class) noexcept;
bool RunPaintRouteSelfChecks(std::string&);
struct NativePaintBindings {
    NativePreprocessBindings preprocess{};
    std::uintptr_t prepare_source{},rate_backend{};
};
bool BindNativePaint(const BuildManifest&,const PeImageView&,std::uintptr_t,NativePaintBindings&,std::string&);
struct NativePaintSample { std::int32_t input_count{},retained{},mixed{},skipped{},freed{},samples{}; };
bool PaintNativeMix(const NativePaintBindings&,ChannelSlot*,std::uint32_t,ExpandedSnapshot&,
    std::int64_t end_position,std::int32_t route_class,std::int32_t source_rate,std::int32_t input_rate,
    NativePaintSample&,std::string&);
using MixBufferPrefix=std::array<std::uint8_t,0x30>;
std::array<std::uintptr_t,3> SelectMixBuffers(const MixBufferPrefix&) noexcept;
bool RunMixBufferSelfChecks(std::string&);
struct NativeBackendSample { std::int32_t paint_calls{},mixed{},freed{}; };
bool PaintNativeBackend(const NativePaintBindings&,ChannelSlot*,std::uint32_t,ExpandedSnapshot&,
    OriginalSnapshot&,std::int64_t end_position,std::int32_t sample_count,NativeBackendSample&,std::string&);
bool ProjectMixShell(ExpandedSnapshot&,OriginalSnapshot&,bool transfer_routes,std::string&);
bool RunMixShellSelfChecks(std::string&);
class LegacySnapshotGateway {
public:
    LegacySnapshotGateway()=default;
    LegacySnapshotGateway(const LegacySnapshotGateway&)=delete;
    LegacySnapshotGateway& operator=(const LegacySnapshotGateway&)=delete;
    ~LegacySnapshotGateway() noexcept;
    bool Prepare(std::uintptr_t entry,std::uintptr_t target,std::string& reason);
    std::uintptr_t original() const noexcept { return page_?page_+0x40:0; }
    const MemoryPatch& entry_patch() const noexcept { return patch_; }
    void RetainForProcessLifetime() noexcept { retained_=true; }
private:
    std::uintptr_t page_{};
    bool registered_{},retained_{};
    MemoryPatch patch_;
};
bool RunLegacyGatewaySelfChecks(std::string&);
bool RunThreadAuditSelfChecks(std::string&);
bool RunStackGuardSelfChecks(std::string&);
bool RunOwnStackGuardSelfChecks(std::string&);
bool RunLegacySwitchSelfChecks(std::string&);
bool NormalizeRegisteredPatchBytes(const std::vector<MemoryPatch>&,std::uintptr_t,std::vector<std::uint8_t>&) noexcept;
bool RunRegisteredPatchSelfChecks(std::string&);
bool NormalizeEngineHookBytes(std::uintptr_t,std::vector<std::uint8_t>&) noexcept;
NativeSnapshotBuilder ResolveOriginalSnapshotBuilder(std::uintptr_t) noexcept;
bool RunFrameBridgeSelfChecks(std::string&);
bool NormalizeFrameHookBytes(std::uintptr_t,std::vector<std::uint8_t>&) noexcept;
bool StartNativeFrameBridge(const BuildManifest&,const PeImageView&,std::uintptr_t,std::string&);
struct ThreadSyncDiagnostic {
    std::uint32_t failed_thread_id{},win32_error{},native_status{},suspended_threads{},exited_threads{},exit_wait_result{},passes{};
    std::uint32_t system_threads{}; bool coverage_checked{};
};
struct FrameBridgeStatus {
    std::uint32_t engine_capacity{kOldCapacity};
    bool active{},resources_retained{};
    ThreadSyncDiagnostic sync{};
    std::uint64_t frames{},preprocessed{},backend_calls{},paint_calls{},mixed{},freed{},errors{},fallback_paints{};
    std::int32_t last_input{},last_retained{};
    std::string reason;
};
FrameBridgeStatus QueryFrameBridge();
FrameBridgeStatus StartFrameBridge();
struct SnapshotBridgeStatus {
    std::uint32_t engine_capacity{kOldCapacity},storage_redirect_count{};
    bool active{},resources_retained{},fail_stop_enabled{},active_stacks_checked{},storage_relocated{},storage_guards_intact{};
    ThreadSyncDiagnostic sync{};
    std::uint64_t calls{},carriers{},passthrough{},errors{};
    std::uintptr_t guard_stack_address{},guard_code_address{};
    std::string reason;
};
SnapshotBridgeStatus QuerySnapshotBridge();
SnapshotBridgeStatus StartSnapshotBridge(std::uintptr_t caller_return_slot,bool acknowledge_fail_stop);
bool StartNativeSnapshotBridge(const BuildManifest&,const PeImageView&,std::uintptr_t,std::uintptr_t,bool,std::string&);
bool RunSnapshotStartGateSelfChecks(std::string&);
SnapshotBridgeStatus StartStorageBridge(std::uintptr_t,bool);
SnapshotBridgeStatus QueryStorageBridge();
bool StartNativeStorageBridge(const BuildManifest&,const PeImageView&,std::uintptr_t,std::uintptr_t,bool,std::string&);
bool RunStorageStartGateSelfChecks(std::string&);
SnapshotBridgeStatus StartCapacityBridge(std::uintptr_t,bool);
SnapshotBridgeStatus QueryCapacityBridge();
bool StartNativeCapacityBridge(const BuildManifest&,const PeImageView&,std::uintptr_t,std::uintptr_t,bool,std::string&);
bool RunCapacityStartGateSelfChecks(std::string&);
[[noreturn]] void SnapshotTransitionFailStop() noexcept;
bool RunSnapshotFailStopSelfChecks(std::string&);

int CompareMixScores(const MixSortEntry&, const MixSortEntry&) noexcept;
bool PrepareMixSort(const std::array<MixSortEntry,kTargetCapacity>& input, std::int32_t count,
    const std::array<std::uintptr_t,kTargetCapacity>& channel_sfx,
    std::int32_t same_sound_limit, ExpandedMixScratch&, std::string& reason);
bool RunMixSortSelfChecks(std::string& reason);

struct RuntimeStatus {
    std::string state{"failed"}, reason, engine_path, disk_sha256;
    bool supported_disk_build{}, loaded_code_matches{}, sampled_counts_valid{}, quiescence_proven{};
    bool installed{}, installation_available{};
    std::uint32_t target_capacity{kTargetCapacity}, current_capacity{};
    std::uint32_t first_code_mismatch{};
    std::int32_t total_channels{-1}, active_count{-1}, active_dynamic{-1}, active_static{-1}, mixers{-1};
};
struct InstallResult { bool installed{}; std::string reason; };
RuntimeStatus QueryStatus();
InstallResult InstallExpansion();
struct NativeProbeResult {
    std::uint32_t engine_capacity{kOldCapacity};
    bool ok{}, sound_lock_held{}, guards_intact{}, routing_released{}, guid_comparison_matches{}, guid_thunk_prepared{};
    std::int32_t source_count{-1}, copied_count{-1}, route_count{-1};
    std::uint32_t snapshot_bytes{}, route_mask{}, guid_queries{};
    std::string reason;
};
NativeProbeResult ProbeNativeSnapshot();
struct NativeStopProbeResult {
    std::uint32_t engine_capacity{kOldCapacity};
    bool ok{}, full_free_binding_verified{}, stop_thunk_prepared{}, sound_lock_held{}, guards_intact{}, routing_released{};
    std::int32_t active_before{-1},active_after{-1},matched_before{-1},matched_after{-1};
    std::int32_t first_source{},first_entity_channel{};
    bool has_first_channel{};
    std::string reason;
};
NativeStopProbeResult ProbeNativeStop(std::int32_t sound_source,std::int32_t entity_channel);
struct NativeAllStopProbeResult {
    std::uint32_t engine_capacity{kOldCapacity};
    bool ok{},native_binding_verified{},sound_lock_held{},storage_zero{},pending_globals_zero{};
    std::int32_t active_before{-1},active_after{-1},total_after{-1};
    NativeAllStopSample sample{};
    std::string reason;
};
NativeAllStopProbeResult ProbeNativeAllStop(bool clear_device);

struct NativeMixProbeResult {
    std::uint32_t engine_capacity{kOldCapacity};
    bool ok{},native_binding_verified{},guards_intact{},routing_released{},sound_lock_held{},compatibility_matches{},expanded_scores_match{};
    std::int32_t source_count{-1},ready_queries{},scored_channels{},same_sound_limit{},expanded_count{-1},original_count{-1},culled_original{},culled_expanded{};
    std::string reason;
};
NativeMixProbeResult ProbeNativeMix();
struct NativePreprocessProbeResult {
    std::uint32_t engine_capacity{kOldCapacity};
    bool ok{},native_binding_verified{},sound_lock_held{},guards_intact{},routing_released{},volume_matches{},allocator_exercised{};
    std::int32_t active_after{-1},route_count{-1},volume_checked{},route_fixture_count{};
    std::uint32_t route_mask{};
    NativePreprocessSample sample{};
    std::string reason;
};
NativePreprocessProbeResult ProbeNativePreprocess();
}
