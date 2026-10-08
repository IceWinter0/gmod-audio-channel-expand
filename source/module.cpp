#include "manifest.hpp"
#include <GarrysMod/Lua/Interface.h>
#include <cmath>
#include <limits>
#include <intrin.h>

namespace {
using GarrysMod::Lua::ILua;
void Bool(ILua* lua, const char* name, bool v) { lua->PushBool(v); lua->SetField(-2,name); }
void Number(ILua* lua, const char* name, double v) { lua->PushNumber(v); lua->SetField(-2,name); }
void String(ILua* lua, const char* name, const std::string& v) { lua->PushString(v.c_str()); lua->SetField(-2,name); }
void OptionalCount(ILua* lua, const char* name, bool available, double v) {
    if (available) lua->PushNumber(v); else lua->PushNil();
    lua->SetField(-2,name);
}
LUA_FUNCTION_STATIC(Status) {
    const auto s=channel_expand::QueryStatus();
    LUA->CreateTable();
    String(LUA,"state",s.state); String(LUA,"reason",s.reason);
    String(LUA,"engine_path",s.engine_path); String(LUA,"disk_sha256",s.disk_sha256);
    Bool(LUA,"installed",s.installed); Bool(LUA,"installation_available",s.installation_available);
    Bool(LUA,"supported_disk_build",s.supported_disk_build); Bool(LUA,"loaded_code_matches",s.loaded_code_matches);
    Bool(LUA,"sampled_counts_valid",s.sampled_counts_valid); Bool(LUA,"quiescence_proven",s.quiescence_proven);
    Number(LUA,"target_capacity",s.target_capacity); Number(LUA,"dynamic_capacity",channel_expand::kDynamicCapacity);
    OptionalCount(LUA,"current_capacity",s.loaded_code_matches,s.current_capacity);
    OptionalCount(LUA,"first_code_mismatch_rva",s.first_code_mismatch!=0,s.first_code_mismatch);
    OptionalCount(LUA,"total_channels",s.sampled_counts_valid,s.total_channels);
    OptionalCount(LUA,"active_count",s.sampled_counts_valid,s.active_count);
    OptionalCount(LUA,"active_dynamic",s.sampled_counts_valid,s.active_dynamic);
    OptionalCount(LUA,"active_static",s.sampled_counts_valid,s.active_static);
    OptionalCount(LUA,"mixers",s.sampled_counts_valid,s.mixers);
    String(LUA,"sampling_note","best-effort read-only sample; matching counts do not prove quiescence");
    return 1;
}
LUA_FUNCTION_STATIC(Install) {
    const auto result=channel_expand::InstallExpansion();
    LUA->PushBool(result.installed); LUA->PushString(result.reason.c_str()); return 2;
}
LUA_FUNCTION_STATIC(SnapshotProbe) {
    const auto result=channel_expand::ProbeNativeSnapshot();
    LUA->CreateTable();
    Bool(LUA,"ok",result.ok); Bool(LUA,"sound_lock_held",result.sound_lock_held);
    Bool(LUA,"guards_intact",result.guards_intact); Bool(LUA,"routing_cleanup_completed",result.routing_released);
    Bool(LUA,"guid_comparison_matches",result.guid_comparison_matches);
    Bool(LUA,"guid_thunk_prepared",result.guid_thunk_prepared);
    OptionalCount(LUA,"source_count",result.source_count>=0,result.source_count);
    OptionalCount(LUA,"copied_count",result.copied_count>=0,result.copied_count);
    OptionalCount(LUA,"route_count",result.route_count>=0,result.route_count);
    Number(LUA,"guid_queries",result.guid_queries); Number(LUA,"snapshot_bytes",result.snapshot_bytes);
    Number(LUA,"route_mask",result.route_mask); Number(LUA,"engine_capacity",result.engine_capacity);
    Bool(LUA,"installation_available",false); String(LUA,"reason",result.reason);
    return 1;
}
LUA_FUNCTION_STATIC(StopProbe) {
    const double source=LUA->CheckNumber(1),channel=LUA->CheckNumber(2);
    const auto valid=[](double v) {
        return std::isfinite(v) && std::trunc(v)==v && v>=std::numeric_limits<std::int32_t>::min() &&
            v<=std::numeric_limits<std::int32_t>::max();
    };
    if (!valid(source) || !valid(channel)) { LUA->ThrowError("sound_source and entity_channel must be signed 32-bit integers"); return 0; }
    const auto result=channel_expand::ProbeNativeStop(static_cast<std::int32_t>(source),static_cast<std::int32_t>(channel));
    LUA->CreateTable();
    Bool(LUA,"ok",result.ok); Bool(LUA,"full_free_binding_verified",result.full_free_binding_verified);
    Bool(LUA,"stop_thunk_prepared",result.stop_thunk_prepared); Bool(LUA,"sound_lock_held",result.sound_lock_held);
    Bool(LUA,"guards_intact",result.guards_intact); Bool(LUA,"routing_cleanup_completed",result.routing_released);
    OptionalCount(LUA,"active_before",result.active_before>=0,result.active_before);
    OptionalCount(LUA,"active_after",result.active_after>=0,result.active_after);
    OptionalCount(LUA,"matched_before",result.matched_before>=0,result.matched_before);
    OptionalCount(LUA,"matched_after",result.matched_after>=0,result.matched_after);
    OptionalCount(LUA,"first_source_before",result.has_first_channel,result.first_source);
    OptionalCount(LUA,"first_entity_channel_before",result.has_first_channel,result.first_entity_channel);
    Number(LUA,"engine_capacity",result.engine_capacity); Bool(LUA,"installation_available",false);
    String(LUA,"reason",result.reason); return 1;
}
LUA_FUNCTION_STATIC(AllStopProbe) {
    const bool clear=LUA->Top()>0?LUA->GetBool(1):true;
    const auto r=channel_expand::ProbeNativeAllStop(clear); LUA->CreateTable();
    Bool(LUA,"ok",r.ok); Bool(LUA,"native_binding_verified",r.native_binding_verified);
    Bool(LUA,"sound_lock_held",r.sound_lock_held); Bool(LUA,"device_ready",r.sample.device_ready);
    Bool(LUA,"device_clear_requested",clear); Bool(LUA,"device_cleared",r.sample.device_cleared);
    Bool(LUA,"storage_zero",r.storage_zero); Bool(LUA,"pending_globals_zero",r.pending_globals_zero);
    Bool(LUA,"routing_cleanup_completed",r.sample.routing_released);
    Number(LUA,"source_count",r.sample.source_count); Number(LUA,"freed",r.sample.freed);
    Number(LUA,"cleared_bytes",r.sample.cleared_bytes); Number(LUA,"interface_calls",r.sample.interface_calls);
    Number(LUA,"pool_clears",r.sample.pool_clears);
    OptionalCount(LUA,"active_before",r.active_before>=0,r.active_before);
    OptionalCount(LUA,"active_after",r.active_after>=0,r.active_after);
    OptionalCount(LUA,"total_after",r.total_after>=0,r.total_after);
    Number(LUA,"engine_capacity",r.engine_capacity); Bool(LUA,"installation_available",false);
    String(LUA,"reason",r.reason); return 1;
}
LUA_FUNCTION_STATIC(MixProbe) {
    const auto result=channel_expand::ProbeNativeMix(); LUA->CreateTable();
    Bool(LUA,"ok",result.ok); Bool(LUA,"native_binding_verified",result.native_binding_verified);
    Bool(LUA,"guards_intact",result.guards_intact); Bool(LUA,"routing_cleanup_completed",result.routing_released);
    Bool(LUA,"sound_lock_held",result.sound_lock_held); Bool(LUA,"compatibility_matches",result.compatibility_matches);
    Bool(LUA,"expanded_scores_match",result.expanded_scores_match);
    OptionalCount(LUA,"source_count",result.source_count>=0,result.source_count);
    OptionalCount(LUA,"original_count",result.original_count>=0,result.original_count);
    OptionalCount(LUA,"expanded_count",result.expanded_count>=0,result.expanded_count);
    Number(LUA,"adapted_ready_queries",result.ready_queries); Number(LUA,"adapted_scored_channels",result.scored_channels);
    Number(LUA,"duplicate_limit",result.same_sound_limit); Bool(LUA,"culling_enabled_in_engine",result.same_sound_limit>0);
    Number(LUA,"culled_original",result.culled_original); Number(LUA,"culled_expanded",result.culled_expanded);
    Number(LUA,"scratch_capacity",channel_expand::kTargetCapacity); Number(LUA,"engine_capacity",result.engine_capacity);
    Bool(LUA,"installation_available",false); String(LUA,"reason",result.reason); return 1;
}
LUA_FUNCTION_STATIC(PreprocessProbe) {
    const auto r=channel_expand::ProbeNativePreprocess(); LUA->CreateTable();
    Bool(LUA,"ok",r.ok); Bool(LUA,"native_binding_verified",r.native_binding_verified);
    Bool(LUA,"sound_lock_held",r.sound_lock_held); Bool(LUA,"guards_intact",r.guards_intact);
    Bool(LUA,"routing_cleanup_completed",r.routing_released); Bool(LUA,"volume_comparison_matches",r.volume_matches);
    Bool(LUA,"native_allocator_exercised",r.allocator_exercised);
    Number(LUA,"volume_checked",r.volume_checked); Number(LUA,"route_fixture_count",r.route_fixture_count);
    Number(LUA,"source_count",r.sample.input_count); Number(LUA,"retained_count",r.sample.retained);
    Number(LUA,"not_ready",r.sample.not_ready); Number(LUA,"dropped",r.sample.dropped);
    Number(LUA,"freed",r.sample.freed); Number(LUA,"pitch_updates",r.sample.pitch_updates);
    Number(LUA,"route_appends",r.sample.route_appends); Number(LUA,"global_clears",r.sample.global_clears);
    OptionalCount(LUA,"active_after",r.active_after>=0,r.active_after);
    OptionalCount(LUA,"route_count",r.route_count>=0,r.route_count); Number(LUA,"route_mask",r.route_mask);
    Number(LUA,"engine_capacity",r.engine_capacity); Number(LUA,"scratch_capacity",channel_expand::kTargetCapacity);
    Bool(LUA,"original_owner_replayed",false); Bool(LUA,"installation_available",false);
    String(LUA,"reason",r.reason); return 1;
}
int FrameTable(ILua* lua,const channel_expand::FrameBridgeStatus& r) {
    lua->CreateTable(); Bool(lua,"active",r.active); String(lua,"reason",r.reason);
    Number(lua,"frames",static_cast<double>(r.frames)); Number(lua,"preprocessed",static_cast<double>(r.preprocessed));
    Number(lua,"backend_calls",static_cast<double>(r.backend_calls)); Number(lua,"paint_calls",static_cast<double>(r.paint_calls));
    Number(lua,"mixed",static_cast<double>(r.mixed)); Number(lua,"freed",static_cast<double>(r.freed));
    Number(lua,"errors",static_cast<double>(r.errors)); Number(lua,"fallback_paints",static_cast<double>(r.fallback_paints));
    Number(lua,"last_input",r.last_input); Number(lua,"last_retained",r.last_retained);
    Number(lua,"sync_failed_thread_id",r.sync.failed_thread_id); Number(lua,"sync_win32_error",r.sync.win32_error);
    Number(lua,"sync_ntstatus",r.sync.native_status); Number(lua,"sync_suspended_threads",r.sync.suspended_threads);
    Number(lua,"sync_passes",r.sync.passes); Number(lua,"sync_exited_threads",r.sync.exited_threads); Number(lua,"sync_exit_wait_result",r.sync.exit_wait_result);
    Number(lua,"sync_system_threads",r.sync.system_threads); Bool(lua,"sync_coverage_checked",r.sync.coverage_checked);
    Number(lua,"engine_capacity",r.engine_capacity); Number(lua,"scratch_capacity",channel_expand::kTargetCapacity);
    Bool(lua,"installation_available",false); Bool(lua,"process_lifetime_resources",r.resources_retained); return 1;
}
int SnapshotBridgeTable(ILua* lua,const channel_expand::SnapshotBridgeStatus& r) {
    lua->CreateTable(); Bool(lua,"active",r.active); String(lua,"reason",r.reason);
    Bool(lua,"process_lifetime_resources",r.resources_retained); Bool(lua,"fail_stop_enabled",r.fail_stop_enabled);
    Bool(lua,"active_stacks_checked",r.active_stacks_checked); Bool(lua,"sync_coverage_checked",r.sync.coverage_checked);
    Number(lua,"calls",static_cast<double>(r.calls)); Number(lua,"carriers",static_cast<double>(r.carriers));
    Number(lua,"passthrough",static_cast<double>(r.passthrough)); Number(lua,"errors",static_cast<double>(r.errors));
    Number(lua,"sync_suspended_threads",r.sync.suspended_threads); Number(lua,"sync_system_threads",r.sync.system_threads);
    Number(lua,"sync_passes",r.sync.passes); Number(lua,"sync_failed_thread_id",r.sync.failed_thread_id);
    Number(lua,"sync_win32_error",r.sync.win32_error); Number(lua,"sync_ntstatus",r.sync.native_status);
    Number(lua,"guard_stack_address",static_cast<double>(r.guard_stack_address)); Number(lua,"guard_code_address",static_cast<double>(r.guard_code_address));
    Bool(lua,"storage_relocated",r.storage_relocated); Bool(lua,"storage_guards_intact",r.storage_guards_intact);
    Number(lua,"storage_redirect_count",r.storage_redirect_count);
    Number(lua,"consumer_load_count",14); Number(lua,"engine_capacity",r.engine_capacity); Bool(lua,"installation_available",false); return 1;
}
LUA_FUNCTION_STATIC(SnapshotBridgeStart) {
    const auto return_slot=reinterpret_cast<std::uintptr_t>(_AddressOfReturnAddress());
    const bool acknowledged=LUA->Top()>0 && LUA->IsType(1,GarrysMod::Lua::Type::Bool) && LUA->GetBool(1);
    return SnapshotBridgeTable(LUA,channel_expand::StartSnapshotBridge(return_slot,acknowledged));
}
LUA_FUNCTION_STATIC(SnapshotBridgeQuery) { return SnapshotBridgeTable(LUA,channel_expand::QuerySnapshotBridge()); }
LUA_FUNCTION_STATIC(StorageBridgeStart) {
    const auto slot=reinterpret_cast<std::uintptr_t>(_AddressOfReturnAddress());
    const bool ack=LUA->Top()>0 && LUA->IsType(1,GarrysMod::Lua::Type::Bool) && LUA->GetBool(1);
    return SnapshotBridgeTable(LUA,channel_expand::StartStorageBridge(slot,ack));
}
LUA_FUNCTION_STATIC(StorageBridgeQuery) { return SnapshotBridgeTable(LUA,channel_expand::QueryStorageBridge()); }
LUA_FUNCTION_STATIC(CapacityStart) {
    const auto slot=reinterpret_cast<std::uintptr_t>(_AddressOfReturnAddress());
    const bool ack=LUA->Top()>0 && LUA->IsType(1,GarrysMod::Lua::Type::Bool) && LUA->GetBool(1);
    return SnapshotBridgeTable(LUA,channel_expand::StartCapacityBridge(slot,ack));
}
LUA_FUNCTION_STATIC(CapacityQuery) { return SnapshotBridgeTable(LUA,channel_expand::QueryCapacityBridge()); }
LUA_FUNCTION_STATIC(FrameStart) { return FrameTable(LUA,channel_expand::StartFrameBridge()); }
LUA_FUNCTION_STATIC(FrameStatus) { return FrameTable(LUA,channel_expand::QueryFrameBridge()); }

}
GMOD_MODULE_OPEN() {
    // GMod binary modules use gmod13_open and conventionally register a global API.
    // No engine writes, hooks, stopsound or console commands occur on require.
    LUA->PushSpecial(GarrysMod::Lua::SPECIAL_GLOB);
    LUA->CreateTable();
    LUA->PushCFunction(Status); LUA->SetField(-2,"status");
    LUA->PushCFunction(Install); LUA->SetField(-2,"install");
    LUA->PushCFunction(SnapshotProbe); LUA->SetField(-2,"snapshot_probe");
    LUA->PushCFunction(StopProbe); LUA->SetField(-2,"stop_probe");
    LUA->PushCFunction(AllStopProbe); LUA->SetField(-2,"all_stop_probe");
    LUA->PushCFunction(MixProbe); LUA->SetField(-2,"mix_probe");
    LUA->PushCFunction(PreprocessProbe); LUA->SetField(-2,"preprocess_probe");
    LUA->PushCFunction(FrameStart); LUA->SetField(-2,"frame_bridge_start");
    LUA->PushCFunction(FrameStatus); LUA->SetField(-2,"frame_bridge_status");
    LUA->PushCFunction(SnapshotBridgeStart); LUA->SetField(-2,"snapshot_bridge_start");
    LUA->PushCFunction(SnapshotBridgeQuery); LUA->SetField(-2,"snapshot_bridge_status");
    LUA->PushCFunction(StorageBridgeStart); LUA->SetField(-2,"storage_bridge_start");
    LUA->PushCFunction(StorageBridgeQuery); LUA->SetField(-2,"storage_bridge_status");
    LUA->PushCFunction(CapacityStart); LUA->SetField(-2,"capacity_bridge_start");
    LUA->PushCFunction(CapacityQuery); LUA->SetField(-2,"capacity_bridge_status");
    LUA->PushString("0.11.0-rc1-native-loader"); LUA->SetField(-2,"version");
    LUA->SetField(-2,"channel_expand"); LUA->Pop(); return 0;
}
GMOD_MODULE_CLOSE() {
    // Activated frame hooks pin this module and retain gateways until process
    // exit. Lua close does not unpatch code under a concurrently running mixer.
    return 0;
}
