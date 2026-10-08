#include <windows.h>
#include "native_protocol.hpp"
#include "manifest.hpp"
#include <fstream>
#include <iostream>
#include <stdexcept>

int wmain(int argc, wchar_t** argv) {
    using namespace channel_expand;
    try {
        if (argc==2 && std::wstring(argv[1])==L"--snapshot-fail-stop-child") SnapshotTransitionFailStop();
        if (argc==3 && std::wstring(argv[1])==L"--relocation-transaction") {
            std::string reason;
            if (!RunEngineRelocationTransaction(argv[2],reason)) { std::cerr << "RELOCATION_TRANSACTION_FAIL: " << reason << '\n'; return 1; }
            std::cout << "RELOCATION_TRANSACTION_PASS:112 original engine spans +98 code/context +4 capacity transition/private image/near storage; rollback and commit verified; no engine install\n"; return 0;
        }
        if (argc==3 && std::wstring(argv[1])==L"--channel-leaf-kernels") {
            std::string reason;
            if (!CompareOriginalChannelLeaves(argv[2],reason)) { std::cerr << "CHANNEL_LEAVES_FAIL: " << reason << '\n'; return 1; }
            std::cout << "CHANNEL_LEAVES_PASS: actual initializer 128/512 and native swap-removal at slot511\n"; return 0;
        }
        if (argc==3 && std::wstring(argv[1])==L"--native-entry") {
            const auto dll=LoadLibraryW(argv[2]);
            if (!dll) { std::cerr << "NATIVE_ENTRY_FAIL: DLL load failed\n"; return 1; }
            struct Release { HMODULE h; ~Release(){FreeLibrary(h);} } release{dll};
            const auto entry=reinterpret_cast<DWORD (WINAPI*)(void*)>(GetProcAddress(dll,"ChannelExpandNativeEntry"));
            if (!entry) { std::cerr << "NATIVE_ENTRY_FAIL: export missing\n"; return 1; }
            if (GetModuleHandleW(L"engine.dll")) { std::cerr << "NATIVE_ENTRY_FAIL: test requires no engine loaded\n"; return 1; }
            NativeRequestV1 request; request.action=1; request.request_id=1;
            if (entry(&request) || request.state!=static_cast<std::uint32_t>(NativeState::Waiting) || request.stage!=static_cast<std::uint32_t>(NativeStage::Engine)) {
                std::cerr << "NATIVE_ENTRY_FAIL: no-engine readiness incorrect\n"; return 1;
            }
            request=NativeRequestV1{}; request.action=2; request.flags=kNativeAck|kNativeClearOnce; request.request_id=2;
            if (entry(&request) || request.state!=static_cast<std::uint32_t>(NativeState::Waiting) || request.capacity) {
                std::cerr << "NATIVE_ENTRY_FAIL: no-engine start did not wait\n"; return 1;
            }
            request=NativeRequestV1{}; request.action=2; request.request_id=3;
            if (entry(&request) || request.state!=static_cast<std::uint32_t>(NativeState::Rejected)) {
                std::cerr << "NATIVE_ENTRY_FAIL: unacknowledged start accepted\n"; return 1;
            }
            if (entry(nullptr)!=ERROR_NOACCESS) { std::cerr << "NATIVE_ENTRY_FAIL: null request accepted\n"; return 1; }
            std::cout << "NATIVE_ENTRY_PASS: real DLL ABI rejection/waiting without Source or Lua\n"; return 0;
        }
        if (argc==3 && std::wstring(argv[1])==L"--volume-kernel") {
            std::string reason;
            if (!CompareOriginalVolumeKernel(argv[2],reason)) { std::cerr << "VOLUME_KERNEL_FAIL: " << reason << '\n'; return 1; }
            std::cout << "VOLUME_KERNEL_PASS: original known-build leaf executed on native fixtures\n"; return 0;
        }
        if (argc==5 && std::wstring(argv[1])==L"--storage-plan" && std::wstring(argv[3])==L"--output") {
            const auto inspected=InspectEngine(argv[2]); StorageRedirectPlan plan; std::string reason;
            const auto base=static_cast<std::uintptr_t>(inspected.image.preferred_base);
            if (!inspected.parsed || !BuildStorageRedirectPlan(inspected.manifest,inspected.image,base,base+0x2000000,
                base+0x2100000,plan,reason)) { std::cerr << "STORAGE_PLAN_FAIL: " << reason << '\n'; return 1; }
            std::cout << "LEGACY_CONSUMER_POINTER_LOADS_OFFLINE: " << plan.legacy_loads.size() << "; constructor not hooked\n";
            std::ofstream out(std::filesystem::path(argv[4]),std::ios::binary); out << StorageRedirectPlanJson(plan); out.close();
            if (!out) throw std::runtime_error("Cannot write storage plan");
            std::cout << "CAPACITY_BOUNDARIES_OFFLINE: " << plan.capacity_patches.size() << "; no engine writes\n";
            std::cout << "STORAGE_PLAN_OFFLINE: direct=" << plan.patches.size() << " pending=" << plan.pending.size()
                << "; synthetic addresses; no engine writes; installation incomplete\n"; return 3;
        }
        if (argc == 3 && std::wstring(argv[1]) == L"--self-check") {
            std::string reason;
            const std::wstring name(argv[2]);
            bool ok = false;
            if (name == L"native-protocol") ok = RunNativeProtocolSelfChecks(reason);
            else if (name == L"pe") ok = RunPeSelfChecks(reason);
            else if (name == L"storage") ok = RunStorageSelfChecks(reason);
            else if (name == L"storage-view") ok = RunStorageViewSelfChecks(reason);
            else if (name == L"capacity-boundaries") ok = RunCapacityBoundarySelfChecks(reason);
            else if (name == L"storage-redirect") ok = RunStorageRedirectSelfChecks(reason);
            else if (name == L"near-storage") ok = RunNearStorageSelfChecks(reason);
            else if (name == L"snapshots") ok = RunSnapshotSelfChecks(reason);
            else if (name == L"mix-sort") ok = RunMixSortSelfChecks(reason);
            else if (name == L"native-bridge") ok = RunNativeBridgeSelfChecks(reason);
            else if (name == L"guid-thunk") ok = RunGuidThunkSelfChecks(reason);
            else if (name == L"patches") ok = RunPatchSelfChecks(reason);
            else if (name == L"prepared-patches") ok = RunPreparedPatchSelfChecks(reason);
            else if (name == L"stop-consumer") ok = RunStopConsumerSelfChecks(reason);
            else if (name == L"all-stop-storage") ok = RunAllStopStorageSelfChecks(reason);
            else if (name == L"query-records") ok = RunQueryRecordSelfChecks(reason);
            else if (name == L"sound-update") ok = RunSoundUpdateSelfChecks(reason);
            else if (name == L"legacy-carrier") ok = RunLegacyCarrierSelfChecks(reason);
            else if (name == L"legacy-constructor") ok = RunLegacyConstructorSelfChecks(reason);
            else if (name == L"legacy-gateway") ok = RunLegacyGatewaySelfChecks(reason);
            else if (name == L"thread-audit") ok = RunThreadAuditSelfChecks(reason);
            else if (name == L"stack-guard") ok = RunStackGuardSelfChecks(reason);
            else if (name == L"own-stack-guard") ok = RunOwnStackGuardSelfChecks(reason);
            else if (name == L"legacy-switch") ok = RunLegacySwitchSelfChecks(reason);
            else if (name == L"registered-patches") ok = RunRegisteredPatchSelfChecks(reason);
            else if (name == L"capacity-start-gates") ok = RunCapacityStartGateSelfChecks(reason);
            else if (name == L"storage-start-gates") ok = RunStorageStartGateSelfChecks(reason);
            else if (name == L"snapshot-start-gates") ok = RunSnapshotStartGateSelfChecks(reason);
            else if (name == L"snapshot-fail-stop") ok = RunSnapshotFailStopSelfChecks(reason);
            else if (name == L"native-mix") ok = RunNativeMixSelfChecks(reason);
            else if (name == L"mix-preprocess-layout") ok = RunMixPreprocessLayoutSelfChecks(reason);
            else if (name == L"mix-volumes") ok = RunMixVolumeSelfChecks(reason);
            else if (name == L"mix-routes") ok = RunMixRouteSelfChecks(reason);
            else if (name == L"paint-routes") ok = RunPaintRouteSelfChecks(reason);
            else if (name == L"mix-shell") ok = RunMixShellSelfChecks(reason);
            else if (name == L"frame-bridge") ok = RunFrameBridgeSelfChecks(reason);
            else if (name == L"mix-buffers") ok = RunMixBufferSelfChecks(reason);
            else { std::cerr << "Unknown self-check (implemented: pe, storage, snapshots, mix-sort, native-bridge, guid-thunk, patches, stop-consumer, native-mix, mix-preprocess-layout, mix-volumes, mix-routes, paint-routes)\n"; return 2; }
            if (!ok) { std::cerr << "SELF_CHECK_FAIL: " << reason << '\n'; return 1; }
            std::wcout << L"SELF_CHECK_PASS: " << name << L'\n'; return 0;
        }
        if (argc != 5 || std::wstring(argv[1]) != L"--inventory" || std::wstring(argv[3]) != L"--output") {
            std::cerr << "Usage: inspect_engine --inventory engine.dll --output report.json | --self-check pe|storage|snapshots|mix-sort|native-bridge|guid-thunk|patches|stop-consumer|native-mix|mix-preprocess-layout|mix-volumes|mix-routes|paint-routes\n"; return 2;
        }
        const auto result = InspectEngine(argv[2]);
        std::ofstream out(std::filesystem::path(argv[4]), std::ios::binary);
        if (!out) throw std::runtime_error("Cannot create report");
        out << InventoryJson(result); out.close();
        if (!out) throw std::runtime_error("Cannot finish report");
        std::cout << "parsed=" << result.parsed << " supported=" << result.manifest.supported
            << " complete=" << result.manifest.complete << " references=" << result.manifest.references.size()
            << " decode_issues=" << result.manifest.decode_issues.size()
            << " unresolved=" << result.manifest.unresolved.size() << '\n';
        if (!result.reason.empty()) std::cout << "reason=" << result.reason << '\n';
        // 3 明确表示报告生成成功但适配清单尚未完成，不能安装扩容。
        return !result.parsed ? 2 : (result.manifest.complete ? 0 : 3);
    } catch (const std::exception& e) { std::cerr << e.what() << '\n'; return 2; }
}
